"""Независимая повторная проверка результата обезличивания.

Движок (`Anonymizer._verify`) уже перепроверяет секреты и фамилии участников. Здесь — второй, независимый от таблицы замен проход:
результат заново прогоняется через детекторы структурированных данных и секретов как «чужой» текст. Всё, что найдено в категории,
которую политика требует убрать, считается утечкой, и запрос блокируется (fail closed).

Проверяются только категории с однозначными форматами (контрольные суммы, адреса, номера) — контекстные (суммы, адреса, номера договоров)
дают ложные срабатывания на самих метках замен и проверяются движком.
"""
from __future__ import annotations

from .engine import Policy
from . import faceless
from .patterns import find_structured
from .secrets import credential_cells, explicit_fields, find_secrets, shadow

STRICT_CATEGORIES = ("email", "phone", "ip", "id_number", "bank")


def independent_check(text: str, policy: Policy) -> list[str]:
    """Список категорий, оставшихся в тексте (пусто — чисто). Секреты проверяются всегда."""
    leaks = ["secret" for _ in find_secrets(text)]
    normalized = shadow(text)
    if next(explicit_fields(normalized), None) or next(credential_cells(normalized), None):
        leaks.append("secret")
    if policy.use_faceless:
        leaks += [f.category for f in faceless.find(text, secrets_only=True)]
    want = {c for c in STRICT_CATEGORIES if policy.action(c) != "keep"}
    if want:
        leaks += [f.category for f in find_structured(text, internal_domains=policy.internal_domains,
                                                      public_domains=policy.public_domains, categories=want)]
    return leaks
