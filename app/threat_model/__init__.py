"""Анкета и расчёты генератора модели угроз."""

import json
import re
from pathlib import Path

CAT = json.loads(Path(__file__).with_name("catalog.json").read_text(encoding="utf-8"))
STEPS = (
    "Профиль системы",
    "Оператор и система",
    "Персональные данные",
    "Инфраструктура",
    "Последствия",
    "Нарушители",
    "Банк угроз",
    "Тип угроз и СКЗИ",
    "Комиссия и меры",
    "Комплект документов",
    "Результат",
)
CATEGORIES = {
    "special": "Специальные",
    "biometric": "Биометрические",
    "public": "Общедоступные",
    "other": "Иные",
}
CONCLUSIONS = {
    "actual": "Возможна",
    "no_impact_object": "Отсутствуют объекты воздействия угрозы",
    "no_violator": "Отсутствует нарушитель, способный реализовать угрозу",
    "no_consequences": "Негативные последствия реализации угрозы отсутствуют",
}
RANK = {"low": 1, "medium": 2, "high": 3}
CRYPTO = ("КС1", "КС2", "КС3", "КВ", "КА")
XML_INVALID = re.compile(r"[^\u0009\u000a\u000d\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")
FIELDS = {k: (label, kind, options) for k, label, kind, options in CAT["fields"] if k}
LABELS = {
    k: re.split(r"\s+\*| — (?:строка|что за система|где и как)", v[0])[0] for k, v in FIELDS.items()
}
for key in ("commissionName", "commissionPosition", "commissionRole"):
    key3 = key + "_3"
    label, kind, options = FIELDS[key + "_2"]
    FIELDS[key3] = (label.replace("2", "3"), kind, options)
    LABELS[key3] = label.replace("2", "3")
EXTRAS = {
    "commissionExtra": "Другие члены комиссии (должность | ФИО, по одному в строке)",
    "pdnExtra": "Дополнительные категории субъектов и состав данных (категория | данные)",
    "serverComponents": "Серверы и компоненты (имя | назначение | ОС | размещение)",
    "accessRoles": "Роли доступа (роль | назначение | права | ограничения)",
    "authorizedUsers": "Пользователи (ФИО | роль | сеть | порты | с | по)",
    "thirdParties": "Третьи лица (наименование | функция | данные | основание)",
    "modelScenarios": "Экспертная оценка сценариев, последствий и защитных мер",
}
for key, label in EXTRAS.items():
    FIELDS[key] = (label, "long_text", "")
    LABELS[key] = label
FIELDS["infrastructureMaxUzLevel"] = (
    "Предельный УЗ размещаемых систем",
    "enum",
    {str(i): f"УЗ-{i}" for i in range(1, 5)},
)
LABELS["infrastructureMaxUzLevel"] = FIELDS["infrastructureMaxUzLevel"][0]


def step_for(key):
    if key in ("systemType", "systemNetworkCondition", "objectType"):
        return 1
    if key.startswith(("operator", "approv", "infosystem")) or key == "systemPurpose":
        return 2
    if key.startswith(("dataCategory", "subject", "pdnCategory", "pdnGroup")) or key == "pdnExtra":
        return 3
    if key in ("usesAiTechnology", "aiTrainedInHouse", "modelScenarios"):
        return 7
    if key.startswith(
        (
            "foreign",
            "developer",
            "systemSoftware",
            "applicationSoftware",
            "usesCrypto",
            "cryptoViolator",
            "infrastructureMax",
        )
    ):
        return 8
    if key.startswith("commission"):
        return 9
    if key in EXTRAS or key in [row[0] for row in CAT["fields"][79:]]:
        return 10
    return 4


BY_STEP = {n: [k for k in FIELDS if step_for(k) == n] for n in range(1, 12)}
CONSEQUENCES = {
    f"{code}|{i}": item["title"]
    for code, group in CAT["consequences"].items()
    for i, item in enumerate(group["items"])
}
REQUIRED = set(CAT["required"])
DEFAULT = {
    "objectType": "ispdn",
    "approverPosition": "Генеральный директор",
    "commissionRole_1": "chairman",
    "commissionRole_2": "member",
    "commissionRole_3": "member",
    "backupRetentionDays": "30",
    "hasAccessDifferentiation": True,
}


def clean(key, raw):
    label, kind, options = FIELDS[key]
    if not isinstance(raw, str):
        raise ValueError(f"Проверьте поле «{LABELS[key]}».")
    value = raw.strip()
    if kind == "bool":
        if value.casefold() not in ("", "нет", "да", "on", "1", "0"):
            raise ValueError(f"Укажите да или нет в поле «{LABELS[key]}».")
        return value.casefold() in ("on", "1", "да")
    if kind == "enum" and value and value not in options:
        raise ValueError(f"Выберите значение из списка «{LABELS[key]}».")
    if len(value) > (8000 if kind == "long_text" else 512) or XML_INVALID.search(value):
        raise ValueError(f"Недопустимые символы или длина поля «{LABELS[key]}».")
    if (
        key == "backupRetentionDays"
        and value
        and (not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 3650)
    ):
        raise ValueError("Глубина хранения должна составлять от 1 до 3650 дней.")
    return value


def profile(data):
    system = CAT["systems"].get(data.get("systemType"), {})
    network = CAT["networks"].get(data.get("systemNetworkCondition"), {})
    flags = [CAT["significance"][v] for v in data.get("flags", []) if v in CAT["significance"]]
    limits = network.get("constraints", {})
    tags = set(system.get("architecturalTags", [])) | set(
        CAT["networkTags"].get(data.get("systemNetworkCondition"), [])
    )
    if re.search("скуд|контроля и управления доступом", data.get("physicalSecurityMeasures", ""), re.I):
        tags.add("acs")
    potential = max(
        (
            RANK[n]
            for n in [
                system.get("maxPotential"),
                network.get("maxPotential"),
                *(f["minPotential"] for f in flags),
            ]
            if n
        ),
        default=0,
    )
    actors = set(system.get("relevantViolators", [])) | set(network.get("relevantViolators", []))
    for flag in flags:
        actors.update(flag["addViolators"])
    foreign = any(f["forceAllowForeignIntelligence"] for f in flags) or limits.get(
        "allowForeignIntelligence", True
    )
    if not foreign:
        actors.discard("foreign_intelligence")
    preset = system.get("consequencePreset") or next(
        (f["consequencePreset"] for f in flags if f["consequencePreset"]), None
    )
    return {
        "rank": potential,
        "tags": tags,
        "actors": actors,
        "foreign": foreign,
        "consequences": CAT["presets"].get(preset, {}).get("relevantItems", []),
        "limits": limits,
    }


def conclusions(data):
    p = profile(data)
    keys = {v: k for k, v in CONCLUSIONS.items()}
    result = {}
    for code, row in CAT["bank"].items():
        decision = keys[row["defaultConclusion"]]
        blocked = p["rank"] and RANK[row["potential"]] > p["rank"]
        if decision not in ("no_impact_object", "no_consequences") and p["rank"]:
            if blocked:
                decision = "no_violator"
            elif row["tags"] and not p["tags"].intersection(row["tags"]):
                decision = "no_impact_object"
            else:
                decision = "actual"
        choice = data.get("decisions", {}).get(code, decision)
        result[code] = "no_violator" if blocked and choice == "actual" else choice
    return result


def commission(data):
    members = []
    for i in range(1, 4):
        name = data.get(f"commissionName_{i}")
        if name:
            members.append(
                (data.get(f"commissionRole_{i}"), data.get(f"commissionPosition_{i}", ""), name)
            )
    for line in data.get("commissionExtra", "").splitlines():
        if line.strip():
            parts = [s.strip() for s in line.split("|", 1)]
            if len(parts) != 2 or not all(parts):
                raise ValueError("Для дополнительного члена комиссии укажите должность и ФИО через |.")
            members.append(("member", *parts))
    return members


def check_step(data, n):
    missing = [LABELS[k] for k in BY_STEP[n] if k in REQUIRED and not data.get(k)]
    if missing:
        raise ValueError("Заполните поля: " + ", ".join(missing))
    if (
        n == 1
        and data.get("objectType") == "infrastructure_object"
        and profile(data)["limits"].get("allowInfrastructureObject") is False
    ):
        raise ValueError("Выбранные сетевые условия исключают объект информатизации. Уточните профиль.")
    if n == 3:
        if not any(data.get("dataCategory_" + k) for k in CATEGORIES):
            raise ValueError("Отметьте хотя бы одну категорию персональных данных.")
        if data.get("subjectType") == "non_employee" and not data.get("subjectVolume"):
            raise ValueError("Укажите порог числа субъектов, не являющихся сотрудниками.")
        if data.get("subjectType") == "non_employee" and data.get("subjectsCount"):
            if (data["subjectsCount"] == "over_100000") != (data["subjectVolume"] == "over_100k"):
                raise ValueError("Диапазон числа субъектов и расчётный порог противоречат друг другу.")
    if (
        n == 8
        and data.get("objectType") == "infrastructure_object"
        and not data.get("infrastructureMaxUzLevel")
    ):
        raise ValueError("Укажите предельный УЗ размещаемых систем.")
    if n == 9:
        members = commission(data)
        if sum(m[0] == "chairman" for m in members) != 1 or sum(m[0] == "member" for m in members) < 2:
            raise ValueError("Укажите ФИО председателя и не менее двух членов комиссии.")
        if any(not position or role not in ("chairman", "member") for role, position, _ in members):
            raise ValueError("Укажите должность и роль каждого члена комиссии.")


def assess(data):
    for n in (1, 2, 3, 8):
        check_step(data, n)
    source = data.get("developerUndeclaredRisk") or (
        profile(data)["foreign"] and data.get("foreignIntelligenceRelevant")
    )
    kind = 3
    if source:
        if data.get("systemSoftwareUndeclaredRisk"):
            kind = 1
        elif data.get("applicationSoftwareUndeclaredRisk"):
            kind = 2
    categories = [k for k in CATEGORIES if data.get("dataCategory_" + k)]
    if data.get("objectType") == "infrastructure_object":
        level = int(data["infrastructureMaxUzLevel"])
        basis = "Заявленный предельный уровень размещаемых ИСПДн."
    else:
        subject = data["subjectType"]
        volume = data.get("subjectVolume") or "under_100k"
        levels = [CAT["levels"][f"{kind}/{k}/{subject}/{volume}"] for k in categories]
        level = min(row["level"] for row in levels)
        basis = ". ".join(row["matchedRule"] for row in levels)
    crypto = None
    if data.get("usesCryptoTools"):
        minimum = CAT["cryptoMin"][f"{level}/{kind}"]
        candidates = [minimum["class"]]
        for group in CAT["cryptoCaps"]:
            if any(data.get(f"cryptoViolator_{group['group']}__{key}") for key in group["capabilities"]):
                candidates.append(group["resultingClass"])
        crypto = {"class": max(candidates, key=CRYPTO.index), "basis": minimum["basis"]}
    return {
        "type": kind,
        "level": level,
        "basis": basis,
        "categories": categories,
        "crypto": crypto,
        "measures": {k: r for k, r in CAT["measures"].items() if level in r["levels"]},
        "certified": CAT["certified"][f"{level}/{kind}"],
        "decisions": conclusions(data),
    }
