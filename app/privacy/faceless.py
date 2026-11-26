"""Faceless public detector catalogs; local context, validation and priority precede substitution."""
import json
import re
from functools import lru_cache
from pathlib import Path

import regex

from .patterns import inn_ok, snils_ok, luhn_ok
from .secrets import Found, entropy

VALIDATORS = {
    "validateInn10Checksum": (inn_ok, ("инн", "inn")),
    "validateInn12Checksum": (inn_ok, ("инн", "inn")),
    "validateSnilsChecksum": (snils_ok, ("снилс",)),
    "validateLuhn": (luhn_ok, ("карт", "card")),
}
CATEGORIES = {
    "email": "email", "phone_ru": "phone", "phone_international": "phone", "address_ru": "address",
    "ipv4": "ip", "ipv6": "ip", "cidr": "ip", "mac_address": "ip", "ldap_dn": "login",
    "unc_path": "host", "windows_path": "host", "internal_hostname": "host", "hostname": "host",
    "url_with_secret": "secret", "devops_token": "project", "generic_secret_value": "secret",
    "bank_account": "bank", "bik": "bank", "card_number": "bank", "card_expiry": "bank",
    "card_cvv_digits": "secret", "card_holder": "person", "login_user_dot_name": "login",
    "connection_username": "login", "login_domain_user": "login", "telegram_username": "login",
    "full_name_ru": "person", "name_initials_ru": "person", "latin_name": "person",
    "surname_ru": "person", "given_name_ru": "person", "patronymic_ru": "person",
    "commercial_amount": "money", "hr_confidential_note": "custom", "confidentiality_marker": "marker",
    "contract_number": "doc_number",
}
SCHEMA_LABELS = set("""negative authorization proxy-authorization password passwd pwd passphrase secret token
access_token refresh_token id_token authorization_code api_key api-key x-api-key api-token x-auth-token username
session_token aws_session_token request_id convertto-securestring proxy_set_header service_account""".split()) | {
    "user id", "client id", "client secret"}


@lru_cache(maxsize=1)
def rules():
    rows = json.loads(Path(__file__).with_name("faceless.json").read_text(encoding="utf-8"))
    for row in rows:
        for key in ("pattern", "allowlist", "companion_pattern"):
            if key in row:
                row[key] = regex.compile(row[key])
    return rows


def context(text, start, end, span=0):
    before = text[max(0, start-800):start].rsplit("\n", span+1)[-(span+1):]
    after = text[end:end+800].split("\n", span+1)[:span+1]
    return "\n".join(before) + text[start:end] + "\n".join(after)


def find(text, *, secrets_only=False):
    for rule in rules():
        is_secret = "type" in rule
        rep = rule["replacement"]
        cat = CATEGORIES.get(rep, "health" if rep.startswith(("medical_", "ophthalmology_")) else "id_number")
        if is_secret:
            cat = "login" if rep == "connection_username" else "secret"
        if secrets_only and cat != "secret":
            continue
        for match in rule["pattern"].finditer(text, timeout=1.5):
            group = rule.get("value_group", int(is_secret))
            if group > match.re.groups or match.start(group) < 0:
                group = 0
            start, end = match.span(group)
            value = match.group(group)
            if not value.strip() or value.startswith("[") and value.endswith("]"):
                continue
            if is_secret and value.strip(" \"'").lower() in SCHEMA_LABELS:
                continue
            if "allowlist" in rule and rule["allowlist"].search(value, timeout=.2):
                continue
            if not rule.get("min_length", 0) <= len(value) <= rule.get("max_length", len(value)):
                continue
            line = context(text, start, end)
            if rule.get("skip_heading_line") and line.lstrip().startswith("==="):
                continue
            span = rule.get("context_line_span", 0)
            nearby = context(text, start, end, span).lower() if span else line.lower()
            positive = rule.get("context_keywords", rule.get("keywords", []))
            if positive and not any(k.lower() in nearby for k in positive):
                companion = rule.get("companion_pattern")
                if not companion or not companion.search(line, timeout=.2):
                    continue
            if any(k.lower() in line.lower() for k in rule.get("context_negative_keywords", [])):
                continue
            if rule.get("validator"):
                validate, markers = VALIDATORS[rule["validator"]]
                if not validate(re.sub(r"\D", "", value)) and not any(k in nearby for k in markers):
                    continue
            if rule.get("reject_assignment_key") and (re.match(r"\s*[:=]", text[end:end+8]) or text[max(0,start-2):start] == "${" and text[end:end+1] == "}"):
                continue
            if rule.get("reject_public_material_value") and re.search(r"(?:client-certificate-data|certificate-authority-data)\s*[:=]\s*[\"']?$", text[max(0,start-100):start], re.I):
                continue
            if rule.get("type") == "entropy_context":
                charset = rule.get("charset", r"A-Za-z0-9+/_\-.=")
                if len(value) in (32, 40, 64, 128) and re.fullmatch("[a-f0-9]+", value, re.I):
                    continue
                if not regex.fullmatch("["+charset+"]+", value, timeout=.2) or entropy(value) < rule.get("entropy_threshold", 3.0):
                    continue
            confidence = rule.get("confidence", rule.get("base_confidence", 85))
            if rule.get("type") == "context" and positive:
                confidence += 5
            if confidence >= 70:
                yield Found(start, end, cat, "faceless_" + rule["id"])
