"""One verified privacy policy for interactive text, uploaded batches and watched folders."""
from collections import Counter
import re
import time

from .engine import Anonymizer, Policy, PrivacyError, Term
from .files import MAX_TEXT
from .verify import independent_check
from .guard import MASK
from .known_values import mask_known_values
from .secrets import mask_explicit_fields

PROFILES = {"faceless": "Полный · Faceless (максимальная строгость)", "strict": "Строгий · Переговорка", "basic": "Базовый · Переговорка"}

GROUPS = {
    "personal": ("Люди, контакты и документы", ("person", "location", "address", "phone", "email", "id_number", "health", "bank")),
    "business": ("Организации и коммерческие сведения", ("organization", "doc_number", "money", "marker", "project")),
    "network": ("Учётные записи и инфраструктура", ("ip", "host", "url", "login")),
}


def policy_for(profile, glossary="", groups=None):
    if profile not in PROFILES:
        raise ValueError("Выберите профиль обработки.")
    words = [s.strip() for s in glossary.splitlines() if s.strip()]
    if len(words) > 48 or any(len(w) > 96 or w.startswith("re:") for w in words):
        raise ValueError("Допустимо до 48 буквальных терминов длиной до 96 знаков.")
    policy = Policy.from_profile("strict" if profile == "faceless" else profile,
                                 use_faceless=profile == "faceless", terms=[Term(w) for w in words])
    if groups is not None:
        if set(groups) - GROUPS.keys():
            raise ValueError("Неизвестная группа данных.")
        for key, (_, categories) in GROUPS.items():
            if key not in groups:
                policy.actions.update(dict.fromkeys(categories, "keep"))
    return policy


def verified(engine, source):
    policy = engine.policy
    result = engine.process(source)
    if independent_check(result.text, policy):
        labels = {r.replacement for r in result.replacements if r.replacement.startswith("[")}
        remaining, field_masks = mask_explicit_fields(result.text, ignored_repeats=labels)
        if field_masks and not independent_check(remaining, policy):
            result.text = remaining
            result.field_secret_count += field_masks
            result.warnings.append("Проведён дополнительный проход.")
            return result
        again = engine.process(remaining)
        # A broad address/organization span can replace the already redacted field
        # with its own label. Normalize explicit fields on the final text as well.
        labels.update(r.replacement for r in again.replacements if r.replacement.startswith("["))
        again.text, final_masks = mask_explicit_fields(again.text, ignored_repeats=labels)
        if independent_check(again.text, policy):
            raise PrivacyError("verification_failed", "Повторная проверка обнаружила остаточные данные. Выдача результата остановлена.")
        result.text = again.text
        result.replacements.extend(again.replacements)
        result.field_secret_count += field_masks + final_masks
        result.warnings.extend(again.warnings + ["Проведён дополнительный проход."])
    return result


def analyze(source, profile="faceless", glossary="", groups=None):
    if not source.strip() or len(source) > MAX_TEXT:
        raise ValueError("Требуется от 1 до 60 000 знаков исходного текста.")
    policy = policy_for(profile, glossary, groups)
    source, n = mask_explicit_fields(source)
    result = verified(Anonymizer(policy), source)
    result.field_secret_count += n
    return result


# Keep multiline keys intact across NLP windows, including a truncated final key.
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)")
WINDOW = 12000


def sections(text, engine=None):
    start = 0
    while len(text) - start > WINDOW:
        end = start + WINDOW
        newline = text.rfind("\n", start + WINDOW // 2, end)
        if newline >= 0:
            end = newline + 1
        else:
            # Prefer a complete sentence. Whitespace keeps long single-line exports processable.
            middle = start + WINDOW // 2
            region = text[middle:end]
            breaks = list(re.finditer(r"(?<=[.!?])\s+", region)) or list(re.finditer(r"\s+", region))
            if breaks:
                end = middle + breaks[-1].end()
            else:
                boundary = re.search(r"\s", text[end:start + MAX_TEXT])
                if boundary:
                    end += boundary.end()
                elif len(text) - start <= MAX_TEXT:
                    end = len(text)
                else:
                    raise PrivacyError("record_size", "Непрерывная строка превысила предел для разбора.")
            if engine and end < len(text):
                # Look across the cut so a name or structured field spanning it is given to one pass.
                offset = max(start, end - 512)
                for hit, _ in engine.find(text[offset:end + 512]):
                    if offset + hit.start < end < offset + hit.end:
                        end = offset + hit.end
        yield text[start:end]
        start = end
    if start < len(text):
        yield text[start:]


def redact_file(path, ext):
    from .files import extract_isolated

    text, note, table_secrets = extract_isolated(path, ext, with_counts=True)
    text, keys = _PRIVATE_KEY.subn(MASK, text)
    text, fields = mask_explicit_fields(text)
    counts = Counter()
    if keys or fields or table_secrets:
        counts["secret"] = keys + fields + table_secrets
    notes = [note] if note else []
    engine = Anonymizer(policy_for("faceless"))
    deadline = time.monotonic() + 1800
    parts = []
    known_secrets = set()
    for section in sections(text, engine):
        if time.monotonic() >= deadline:
            raise PrivacyError("verification_timeout", "Обработка документа превысила полчаса. Разделите материал.")
        result = verified(engine, section)
        if parts and independent_check(parts[-1][-512:] + result.text[:512], engine.policy):
            raise PrivacyError("verification_failed", "Проверка на границе фрагментов обнаружила остаточные данные.")
        counts.update(result.stats())
        known_secrets.update(r.original for r in result.replacements if r.category == "secret"
                             and len(r.original.strip()) >= 4 and MASK not in r.original)
        parts.append(result.text)
        notes.extend(n for n in result.warnings if n not in notes)
    combined, repeated = mask_known_values("".join(parts), known_secrets)
    if repeated:
        counts["secret"] += repeated
        previous = ""
        for part in sections(combined, engine):
            if independent_check(part, engine.policy) or (
                previous and independent_check(previous + part[:512], engine.policy)
            ):
                raise PrivacyError("verification_failed", "Проверка полного документа обнаружила остаточные данные.")
            previous = part[-512:]
    return combined, dict(counts), notes
