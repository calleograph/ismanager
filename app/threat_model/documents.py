"""Редактируемые документы для рассмотрения комиссией оператора."""

from datetime import date
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from PIL import Image
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt

from . import CAT, CATEGORIES, CONCLUSIONS, CONSEQUENCES, FIELDS, LABELS, assess, commission, profile

BASE = (
    "Модель угроз безопасности информации",
    "Акт определения уровня защищенности",
    "Акт выбора мер защиты персональных данных",
)
EXTENDED = (
    "Протокол оценки вреда субъектам персональных данных",
    "Технический паспорт",
    "Матрица ролей и прав доступа",
    "Перечень пользователей",
    "Перечень третьих лиц",
    "Акт ввода в эксплуатацию",
    "Акт оценки эффективности",
    "Приказ о создании комиссии",
)
OPTIONAL = {
    "includeSsdlcConclusion": "Заключение о безопасной разработке",
    "includePolicyDocument": "Политика обработки персональных данных",
    "includeOrganizationOrder": "Приказ об организации обработки персональных данных",
    "includePasswordPolicy": "Парольная политика",
    "includeIncidentResponsePolicy": "Регламент реагирования на инциденты",
    "includeAntivirusPolicy": "Положение об антивирусной защите",
    "includeAccessControlPolicy": "Политика управления доступом",
    "includeBackupPolicy": "Регламент резервного копирования",
    "includeVulnerabilityPolicy": "Политика управления обновлениями и уязвимостями",
}


def selected_documents(data):
    return [
        *BASE,
        *(EXTENDED if data.get("extendedDocumentSet") else ()),
        *(title for flag, title in OPTIONAL.items() if data.get(flag)),
    ]


def table(doc, headings, rows):
    t = doc.add_table(rows=0, cols=len(headings))
    t.style = "Table Grid"

    def add(values, header=False):
        row = t.add_row()
        props = row._tr.get_or_add_trPr()
        props.append(OxmlElement("w:cantSplit"))
        if header:
            props.append(OxmlElement("w:tblHeader"))
        for cell, value in zip(row.cells, values):
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1
            run = p.add_run(str(value or "—"))
            run.font.size = Pt(10)
            run.bold = header

    add(headings, True)
    for values in rows:
        add(values)


def setup(title, data):
    doc = Document()
    doc.core_properties.author = "IS Manager"
    doc.core_properties.title = title
    doc.core_properties.comments = ""
    sec = doc.sections[0]
    sec.page_height, sec.page_width = Cm(29.7), Cm(21)
    sec.top_margin, sec.bottom_margin, sec.left_margin, sec.right_margin = Cm(2), Cm(2), Cm(2), Cm(1.5)
    for name in ("Normal", "Title", "Heading 1", "Heading 2"):
        font = doc.styles[name].font
        font.name = "Times New Roman"
        font.size = Pt(12 if name == "Normal" else 14)
    sec.different_first_page_header_footer = True
    footer = sec.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)
    p = doc.add_paragraph(
        "УТВЕРЖДАЮ\n"
        + data.get("approverPosition", "")
        + "\n"
        + "____________ "
        + data.get("approverFullName", "")
        + "\n«____» ____________ 20____ г."
    )
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    doc.add_heading(title, level=0)
    doc.add_paragraph(data["operatorFullName"])
    doc.add_paragraph(data["infosystemFullName"])
    return doc


def signatures(doc, data):
    doc.add_heading("Подписи комиссии", 2)
    table(
        doc,
        ("Роль", "Должность", "ФИО", "Подпись"),
        (
            ("Председатель" if r == "chairman" else "Член комиссии", pos, name, "____________")
            for r, pos, name in commission(data)
        ),
    )


def values(doc, data, keys):
    table(
        doc,
        ("Характеристика", "Сведения оператора"),
        ((LABELS[k], format_field(k, data.get(k))) for k in keys if data.get(k) not in ("", None)),
    )


def format_field(key, value):
    _, kind, options = FIELDS[key]
    if kind == "enum":
        return options.get(value, value).split(" — ", 1)[-1]
    if kind == "bool":
        return "Да" if value else "Нет"
    return value


def rows_from(data, key, n):
    for line in data.get(key, "").splitlines():
        if line.strip():
            parts = [s.strip() for s in line.split("|", n - 1)]
            yield (parts + [""] * n)[:n]


def actor_selection(data):
    p = profile(data)
    chosen = set(data.get("actors", p["actors"]))
    if not p["foreign"]:
        chosen.discard("foreign_intelligence")
    return chosen


def overview(doc, data, result):
    values(
        doc,
        data,
        (
            "operatorFullName",
            "operatorShortName",
            "operatorLegalAddress",
            "systemType",
            "systemNetworkCondition",
            "objectType",
            "systemPurpose",
            "serverLocationAddress",
            "dataCenterName",
            "businessProcesses",
            "subsystems",
            "processingMode",
            "accessSubjectsDescription",
            "hasAccessDifferentiation",
            "serverComposition",
            "operatingSystems",
            "applicationSoftware",
            "dbms",
            "softwareRegistrationNumber",
            "virtualizationDescription",
            "corporateNetworkName",
            "remoteAccessDescription",
            "externalIpAddress",
        ),
    )
    p = profile(data)
    internet = p["limits"].get("hasInternetAccess")
    if internet is None:
        internet = data.get("hasInternetAccess")
    doc.add_paragraph("Доступ в Интернет: " + ("да" if internet else "нет"))
    doc.add_paragraph(
        "Категории персональных данных: "
        + ", ".join(CATEGORIES[k].lower() for k in result["categories"])
        + "."
    )
    values(doc, data, ("subjectType", "subjectVolume", "subjectsCount", "hasInternationalExchange"))
    pdn = [(data.get(f"pdnCategory_{i}"), data.get(f"pdnGroup_{i}")) for i in range(1, 4)]
    pdn = [r for r in pdn if any(r)] + list(rows_from(data, "pdnExtra", 2))
    if pdn:
        table(doc, ("Субъекты", "Состав ПДн"), pdn)
    values(
        doc,
        data,
        (
            "antivirusAndFirewall",
            "cryptoTools",
            "otherSecurityTools",
            "physicalSecurityMeasures",
            "physicalSecurityNotes",
        ),
    )


def model(doc, data, result, diagram):
    doc.add_paragraph(" ".join(filter(None, [data.get("approvalCity"), str(date.today().year)])))
    doc.add_page_break()
    doc.add_heading("Содержание", 1)
    toc = OxmlElement("w:fldSimple")
    toc.set(qn("w:instr"), 'TOC \\o "1-2" \\h')
    doc.add_paragraph()._p.append(toc)
    update = OxmlElement("w:updateFields")
    update.set(qn("w:val"), "true")
    doc.settings.element.append(update)
    doc.add_heading("1. Общие положения", 1)
    doc.add_paragraph(
        f"Объект оценки — {data['infosystemFullName']}. Оператор — {data['operatorFullName']}. "
        "Комиссия определяет актуальные угрозы и основания для выбора мер защиты. "
        "Исходные сведения зафиксированы в анкете системы."
    )
    doc.add_paragraph(
        "Основания оценки: Федеральный закон № 152-ФЗ, постановление Правительства РФ № 1119, "
        "методика оценки угроз безопасности информации ФСТЭК России от 05.02.2021. "
        "Справочник угроз — срез БДУ от 18.11.2026."
    )
    doc.add_heading("2. Характеристики объекта", 1)
    overview(doc, data, result)
    if diagram:
        with Image.open(BytesIO(diagram)) as image:
            scale = min(15 / image.width, 18 / image.height)
            doc.add_picture(
                BytesIO(diagram), width=Cm(scale * image.width), height=Cm(scale * image.height)
            )
        doc.add_paragraph("Схема системы, предоставленная оператором.")
    doc.add_heading("3. Негативные последствия", 1)
    relevant = data.get("consequences", profile(data)["consequences"])
    table(
        doc,
        ("Код", "Возможное последствие", "Признано актуальным"),
        ((k, v, "Да" if k in relevant else "Нет") for k, v in CONSEQUENCES.items()),
    )
    doc.add_heading("4. Объекты воздействия", 1)
    levels = {
        "user": "Пользовательский",
        "application": "Прикладной",
        "system": "Системный",
        "network": "Сетевой",
        "hardware": "Аппаратный",
    }
    tools = ", ".join(
        filter(
            None, [data.get(k) for k in ("antivirusAndFirewall", "cryptoTools", "otherSecurityTools")]
        )
    )
    table(
        doc,
        ("Уровень", "Группа", "Объекты для рассмотрения"),
        (
            (
                levels.get(level, level),
                CAT["objectGroups"][group],
                tools if obj == "__FROM_ANKETA__" else obj,
            )
            for level, groups in CAT["objects"].items()
            for group, obj in groups.items()
            if obj != "Отсутствуют"
        ),
    )
    doc.add_heading("5. Потенциальные нарушители", 1)
    actors = actor_selection(data)
    for k, r in CAT["violators"].items():
        actual = k in actors
        doc.add_paragraph(r["title"] + (" — актуален." if actual else " — исключён."))
        if actual:
            goals = data.get("goals", {}).get(k, r["goals"])
            if goals:
                doc.add_paragraph("Цели: " + "; ".join(goals) + ".")
    doc.add_heading("6. Способы реализации угроз", 1)
    table(doc, ("Код", "Способ"), CAT["methodGroups"].items())
    doc.add_heading("7. Банк угроз", 1)
    doc.add_paragraph(
        "В приложенной оценке рассмотрены 243 угрозы. Архивные УБИ.218–222 исключены. "
        "Конфиденциальность, целостность и доступность обозначены буквами К, Ц и Д."
    )
    table(
        doc,
        ("Код и угроза", "Объект и нарушитель", "Свойства", "Решение"),
        (
            (
                f"{code}. {r['name']}",
                r["objects"] + "\n" + r["violators"],
                ", ".join(
                    v
                    for k, v in (("confidentiality", "К"), ("integrity", "Ц"), ("availability", "Д"))
                    if r[k]
                ),
                CONCLUSIONS[result["decisions"][code]],
            )
            for code, r in CAT["bank"].items()
        ),
    )
    if data.get("usesAiTechnology"):
        for k in ["operator", "developer"] if data.get("aiTrainedInHouse") else ["operator"]:
            infra = CAT["ai"][k]
            doc.add_heading(infra["title"], 2)
            for threat in infra["threats"]:
                doc.add_paragraph(threat)
            table(doc, ("Код", "Способ реализации"), infra["methods"].items())
    doc.add_heading("8. Актуальные угрозы", 1)
    actual = [k for k, v in result["decisions"].items() if v == "actual"]
    doc.add_paragraph(", ".join(actual) if actual else "Комиссией не выбрано актуальных угроз.")
    doc.add_heading("9. Оценка сценариев", 1)
    doc.add_paragraph(
        "Основание — приложение 11 к методике ФСТЭК России от 05.02.2021. "
        "Комиссия оценивает применимость тактик к объектам и свойствам информации с учётом выбранных угроз."
    )
    relevant_tactics = {t for code in actual for t in CAT["bank"][code]["tactics"]}
    table(
        doc,
        ("Код", "Тактика", "Техники приложения 11", "По актуальным угрозам"),
        (
            (
                k,
                v,
                ", ".join(CAT["techniqueIds"][k]),
                "Рассмотреть" if k in relevant_tactics else "По решению комиссии",
            )
            for k, v in CAT["tactics"].items()
        ),
    )
    if data.get("modelScenarios"):
        doc.add_paragraph(data["modelScenarios"])
    doc.add_heading("10. Выводы оценки", 1)
    doc.add_paragraph(
        f"Рассмотрено угроз БДУ: {len(result['decisions'])}. Признано актуальными: {len(actual)}. "
        f"Уровень защищённости: УЗ-{result['level']}."
    )
    doc.add_heading("11. Тип актуальных угроз", 1)
    type_section(doc, data, result)
    doc.add_heading("12. Класс средств криптографической защиты", 1)
    crypto_section(doc, data, result)
    doc.add_heading("13. Пересмотр модели", 1)
    doc.add_paragraph(
        "Ответственный за безопасность инициирует пересмотр при изменении архитектуры, условий доступа, "
        "категорий данных, состава нарушителей, а также при выявлении новых угроз или по итогам инцидента. "
        "Комиссия документирует изменённые выводы и передаёт их на утверждение оператору."
    )
    signatures(doc, data)


def type_section(doc, data, result):
    kind = result["type"]
    explanations = {
        1: "Актуальны недекларированные возможности в системном ПО.",
        2: "Актуальны недекларированные возможности в прикладном ПО.",
        3: "Принятый профиль исключает актуальность угроз, связанных с недекларированными возможностями ПО.",
    }
    doc.add_paragraph(f"Тип {kind}. " + explanations[kind])
    values(
        doc,
        data,
        ("developerUndeclaredRisk", "systemSoftwareUndeclaredRisk", "applicationSoftwareUndeclaredRisk"),
    )
    doc.add_paragraph(
        "Специальные службы иностранных государств как источник угроз: "
        + (
            "рассматриваются."
            if profile(data)["foreign"] and data.get("foreignIntelligenceRelevant")
            else "не рассматриваются."
        )
    )


def crypto_section(doc, data, result):
    crypto = result["crypto"]
    if not crypto:
        doc.add_paragraph("По сведениям оператора СКЗИ в системе не применяются.")
        return
    doc.add_paragraph("Минимальный класс с учётом модели нарушителя — " + crypto["class"] + ".")
    doc.add_paragraph("Табличное основание: " + crypto["basis"] + ".")
    chosen = [
        label
        for g in CAT["cryptoCaps"]
        for k, label in g["capabilities"].items()
        if data.get(f"cryptoViolator_{g['group']}__{k}")
    ]
    for item in chosen:
        doc.add_paragraph(item)
    values(doc, data, ("cryptoViolatorModelApproverPosition", "cryptoViolatorModelApproverFullName"))


def measures(doc, data, result):
    doc.add_paragraph(
        f"Для УЗ-{result['level']} выбран базовый набор мер защиты по приказу ФСТЭК России № 21."
    )
    table(
        doc,
        ("Код", "Мера защиты", "Способ реализации, указанный оператором"),
        (
            (k, r["title"], data.get("implementations", {}).get(k, ""))
            for k, r in result["measures"].items()
        ),
    )
    if result["type"] in (1, 2):
        doc.add_heading("Дополнительные меры для угроз первого и второго типов", 2)
        for text in CAT["additionalMeasures"]:
            doc.add_paragraph(text)
    doc.add_heading("Требования к средствам защиты", 2)
    labels = {
        "svt": "Средства вычислительной техники",
        "sovAndAv": "СОВ и антивирусные средства",
        "firewall": "Межсетевые экраны",
        "ndvNote": "Контроль НДВ",
    }
    table(doc, ("Вид", "Требование"), ((labels[k], v) for k, v in result["certified"].items() if v))


def extended(doc, title, data, result):
    if title == EXTENDED[0]:
        doc.add_paragraph(
            "Комиссия оценивает возможный вред субъектам при нарушении порядка обработки данных "
            "в соответствии с требованиями приказа Роскомнадзора № 178 от 27.10.2022."
        )
        table(
            doc,
            ("Степень", "Обстоятельство", "Оценка комиссии"),
            (
                (
                    r["degree"],
                    r["basis"],
                    "Применимо" if r.get("category") in result["categories"] else "________________",
                )
                for r in CAT["harm"]
            ),
        )
        doc.add_paragraph(
            "Установленная степень вреда и обоснование: ____________________________________"
        )
    elif title == EXTENDED[1]:
        overview(doc, data, result)
        table(
            doc, ("Компонент", "Назначение", "ОС", "Размещение"), rows_from(data, "serverComponents", 4)
        )
        doc.add_paragraph(f"Установлен УЗ-{result['level']}. " + result["basis"] + ".")
    elif title in EXTENDED[2:5]:
        field, heads = {
            EXTENDED[2]: ("accessRoles", ("Роль", "Назначение", "Права", "Ограничения")),
            EXTENDED[3]: ("authorizedUsers", ("ФИО", "Роль", "Сеть", "Порты", "С", "По")),
            EXTENDED[4]: ("thirdParties", ("Третье лицо", "Функция", "Данные", "Основание")),
        }[title]
        doc.add_paragraph(
            "Реестр пересматривается при изменении состава лиц, оснований обработки или предоставленных полномочий."
        )
        table(doc, heads, rows_from(data, field, len(heads)))
    elif title == EXTENDED[5]:
        doc.add_paragraph(
            "Комиссия рассмотрела технический паспорт, модель угроз и акт выбора мер защиты. "
            "Решение о вводе принимается после проверки фактического выполнения мер."
        )
        doc.add_paragraph(
            "Реквизиты проверки и выявленные замечания: ____________________________________"
        )
        doc.add_paragraph(
            "Решение комиссии, условия и дата ввода: ______________________________________"
        )
    elif title == EXTENDED[6]:
        doc.add_paragraph(
            "Комиссия сопоставляет внедрённые меры с проектными решениями. Для каждой меры "
            "указываются метод проверки, реквизиты доказательства и фактический результат."
        )
        table(
            doc,
            ("Проверяемая мера", "Проверка и доказательство", "Результат"),
            ((f"{k}. {r['title']}", "", "") for k, r in result["measures"].items()),
        )
        doc.add_paragraph(
            "Заключение о достаточности и эффективности мер: ______________________________"
        )
    else:
        doc.add_paragraph("ПРИКАЗЫВАЮ")
        doc.add_paragraph(
            "1. Создать комиссию для оценки угроз безопасности персональных данных и выбора мер защиты системы."
        )
        doc.add_paragraph(
            "2. Утвердить состав комиссии, приведённый ниже. Председатель организует рассмотрение материалов, "
            "оформляет решения и представляет результаты на утверждение."
        )
        doc.add_paragraph("3. Представить акты и модель угроз на утверждение руководителю оператора.")
    signatures(doc, data)


POLICIES = {
    "includeSsdlcConclusion": (
        "Работы и результаты",
        "Учитывать внедрённые практики для разработки, тестирования и выпуска. "
        "Для каждой практики указать проект, ответственного и реквизиты свидетельства выполнения.",
        ("ssdlcResponsiblePosition", "ssdlcResponsibleFullName"),
        "ssdlcPractice_",
    ),
    "includePolicyDocument": (
        "Цели и основания",
        "Обработка допускается для заявленных целей и в пределах необходимых данных. "
        "Обращения субъектов регистрируются. Ответственный проверяет основания запроса, обеспечивает доступ, уточнение, "
        "блокирование или уничтожение данных и фиксирует исполнение.",
        (
            "systemPurpose",
            "subjectType",
            "pdnContactPhone",
            "pdnContactEmail",
            "pdnResponsiblePosition",
            "pdnResponsibleFullName",
        ),
        "legalBasis_",
    ),
    "includeOrganizationOrder": (
        "Распорядительная часть",
        "Назначить ответственного за организацию обработки персональных данных. "
        "Ответственному организовать учёт процессов, ознакомление работников с локальными актами и контроль исполнения. "
        "Руководителям подразделений представлять сведения об изменениях обработки.",
        ("pdnResponsiblePosition", "pdnResponsibleFullName", "pdnContactEmail"),
        "",
    ),
    "includePasswordPolicy": (
        "Выдача и смена учётных данных",
        "Использовать уникальные пароли и многофакторную проверку для привилегированного доступа. "
        "Первичный секрет выдать по защищённому каналу и сменить при первом входе. При подозрении на компрометацию "
        "прекратить использование секрета, отозвать сеансы и уведомить ответственное подразделение.",
        ("securityTeamEmail",),
        "",
    ),
    "includeIncidentResponsePolicy": (
        "Регистрация и реагирование",
        "Зарегистрировать время, затронутые активы, признаки инцидента и источник сообщения. "
        "Ответственному сохранить свидетельства, определить масштаб, локализовать последствия и проверить восстановление. "
        "При затрагивании персональных данных определить обязанность и сроки уведомления уполномоченного органа. "
        "Результаты расследования и корректирующие действия включить в журнал.",
        ("incidentReportEmail", "securityTeamEmail"),
        "",
    ),
    "includeAntivirusPolicy": (
        "Контроль средств защиты",
        "Определить защищаемые узлы, проверить установку и обновление средств обнаружения. "
        "Изоляцию заражённых объектов и восстановление согласовывать с ответственным за систему. "
        "Фиксировать исключения и срок их пересмотра.",
        ("antivirusAndFirewall", "serverComposition"),
        "",
    ),
    "includeAccessControlPolicy": (
        "Предоставление и отзыв доступа",
        "Выдавать права по утверждённой заявке и должностным обязанностям. "
        "Владельцу системы и администратору разделить согласование и исполнение. Регулярно сверять права; при увольнении "
        "или смене обязанностей отзывать избыточный доступ.",
        ("accessSubjectsDescription", "remoteAccessDescription"),
        "",
    ),
    "includeBackupPolicy": (
        "Копирование и восстановление",
        "Определить состав данных и конфигураций, ответственных, расписание и место хранения. "
        "Ограничить доступ к копиям, вести журнал выполнения и проводить контрольное восстановление в изолированной среде. "
        "Результат восстановления и фактическое время фиксировать в протоколе.",
        ("backupRetentionDays", "serverComposition", "dbms"),
        "",
    ),
    "includeVulnerabilityPolicy": (
        "Учёт и устранение",
        "Вести перечень версий и сверять его с сообщениями разработчиков. "
        "Определять приоритет обновлений по применимости и влиянию на систему. Проверять обновления и восстановление "
        "на стенде, согласовывать сроки внедрения и фиксировать установленную версию.",
        ("operatingSystems", "applicationSoftware", "securityTeamEmail"),
        "",
    ),
}

# Процедуры локального акта остаются редактируемыми перед утверждением.
PROCEDURES = {
    "includePasswordPolicy": [
        (
            "Персональные и служебные учётные записи",
            "Разделить рабочую и административную учётные записи. Сервисную запись закрепить за владельцем, ограничить набор разрешённых операций и исключить интерактивный вход.",
        ),
        (
            "Обращение с секретами",
            "Не помещать рабочие пароли и ключи в переписку, заявки, исходный код или общие документы. Передавать новый секрет персонально. При передаче обязанностей обновить секрет и отозвать прежние права.",
        ),
    ],
    "includeIncidentResponsePolicy": [
        (
            "Обнаружение",
            "Дежурный регистрирует сообщения пользователей и сигналы средств защиты. В карточке зафиксировать время обнаружения, контакт заявителя, систему, признаки события и выполненные действия.",
        ),
        (
            "Приоритет",
            "Определить влияние на непрерывность процессов, данные и объём затронутых лиц. При изменении оценки пересмотреть приоритет и состав участников. По высокоприоритетным событиям немедленно уведомить руководителя реагирования.",
        ),
        (
            "Уведомление и расследование",
            "Ответственному за обработку ПДн зафиксировать момент выявления инцидента. При наличии оснований по части 3.1 статьи 21 закона № 152-ФЗ направить первоначальное уведомление в течение 24 часов, сведения о результатах внутреннего расследования — в течение 72 часов.",
        ),
        (
            "Восстановление",
            "Перед возвратом системы в работу проверить целостность конфигурации, прекратить действие скомпрометированных учётных данных и подтвердить работоспособность вместе с владельцем процесса.",
        ),
    ],
    "includeOrganizationOrder": [
        (
            "Поручения подразделениям",
            "Обеспечить ознакомление сотрудников с локальными актами, ведение перечня лиц с доступом и своевременное прекращение доступа при изменении обязанностей.",
        ),
        (
            "Исполнение",
            "Ответственному за организацию обработки вести реестр поручений и представлять руководителю сведения о выполнении. Дату вступления приказа в силу и сроки поручений определить при утверждении.",
        ),
    ],
    "includePolicyDocument": [
        (
            "Состав и способы обработки",
            "Для каждой цели определить категории субъектов, состав сведений, операции с ними и применяемые способы обработки. При поручении обработки документировать переданные данные, действия и обязанности исполнителя.",
        ),
        (
            "Обращения субъектов",
            "Обращение направляется ответственному по указанным контактам. После установления личности заявителя проверяются объём запрошенных данных, основание ограничения доступа и необходимость уточнения, блокирования или уничтожения сведений.",
        ),
        (
            "Сроки хранения",
            "По каждой цели установить срок или событие, прекращающее обработку. При достижении цели проверить иные основания хранения, уничтожить данные, срок хранения которых истёк, и зафиксировать результат.",
        ),
        (
            "Защита данных",
            "Вести учёт допущенных лиц и носителей, определять угрозы, принимать меры защиты по установленному УЗ, контролировать обращения и изменения. Факты нарушения регистрируются и передаются ответственному за реагирование.",
        ),
    ],
    "includeSsdlcConclusion": [
        (
            "Материалы оценки",
            "Рассмотреть принятый порядок разработки, записи о проверке изменений, результаты испытаний и порядок выпуска. Включить ссылки на документы и задачи, подтверждающие использование каждой отмеченной практики.",
        ),
        (
            "Риски и вывод комиссии",
            "Зафиксировать неохваченные этапы и остаточные риски, назначить ответственных и сроки доработок. Заключение о применении практик оформить после проверки свидетельств.",
        ),
    ],
    "includeAntivirusPolicy": [
        (
            "Эксплуатация средств",
            "Администратор ведёт перечень защищаемых узлов, контролирует получение обновлений и проверяет доступность централизованного управления. Согласованные исключения документировать с указанием владельца и даты пересмотра.",
        ),
        (
            "Реакция на обнаружение",
            "При обнаружении вредоносного объекта сохранить сведения о событии, ограничить распространение, согласовать изоляцию узла и передать материалы ответственному за инциденты. Возврат в работу проводить после контрольной проверки.",
        ),
    ],
    "includeAccessControlPolicy": [
        (
            "Жизненный цикл полномочий",
            "В заявке указывать лицо, систему, роль, срок и основание. Владелец информационного ресурса согласует объём, администратор исполняет заявку и фиксирует результат. Временный доступ отзывать по истечении срока.",
        ),
        (
            "Привилегированный и удалённый доступ",
            "Использовать именованные записи, согласованный защищённый канал и дополнительную проверку при превышении обычного уровня полномочий. Сеансы и изменения прав регистрировать.",
        ),
        (
            "Сверка",
            "Периодически сопоставлять список действующих записей с кадровыми событиями, матрицей ролей и договорами. Выявленные расхождения устранять и фиксировать в журнале проверок.",
        ),
    ],
    "includeBackupPolicy": [
        (
            "Состав копии",
            "Для системы определить набор баз данных, конфигурации, журналы, ключи восстановления и зависимости запуска. Указать владельца, допустимую потерю данных и предельное время восстановления.",
        ),
        (
            "Ротация и доступ",
            "Соблюдать установленный срок хранения, разграничивать доступ к созданию и удалению копий. По завершении ротации фиксировать уничтожение или перенос архива.",
        ),
        (
            "Контрольное восстановление",
            "Выбрать точку восстановления и изолированное назначение. Проверить читаемость и целостность копии, запустить систему и передать результат владельцу для проверки пользовательской операции.",
        ),
    ],
    "includeVulnerabilityPolicy": [
        (
            "Учёт",
            "По каждому извещению указывать источник, компонент, версию, владельца, условия применимости и доступность исправления. Сопоставить сообщение с фактически развёрнутой версией и конфигурацией.",
        ),
        (
            "План и внедрение",
            "По результатам оценки выбрать обновление, изменение конфигурации или временные компенсирующие меры. До изменения подготовить резервную копию и проверить возможность отката.",
        ),
        (
            "Закрытие",
            "После обновления сверить установленную версию, проверить функциональность и записать результат повторной оценки. Для отложенного исправления согласовать владельца риска и срок пересмотра.",
        ),
    ],
}


def optional(doc, title, data):
    flag = next(k for k, v in OPTIONAL.items() if v == title)
    heading, body, keys, prefix = POLICIES[flag]
    doc.add_heading("Область применения", 1)
    doc.add_paragraph(
        f"Документ распространяется на {data['infosystemFullName']} и работников {data['operatorShortName']}, "
        "участвующих в соответствующих процессах."
    )
    doc.add_heading(heading, 1)
    doc.add_paragraph(body)
    values(doc, data, keys)
    if prefix:
        for k in FIELDS:
            if k.startswith(prefix) and data.get(k):
                doc.add_paragraph(LABELS[k].removesuffix("?"))
    for subtitle, paragraph in PROCEDURES[flag]:
        doc.add_heading(subtitle, 2)
        doc.add_paragraph(paragraph)
    if flag == "includePasswordPolicy":
        doc.add_heading("Параметры парольных правил", 2)
        table(
            doc,
            (
                "Тип записи",
                "Мин. длина",
                "Групп символов",
                "Макс. срок, дни",
                "Мин. срок, дни",
                "История",
            ),
            (
                ("Пользовательская", "12", "4", "180", "1", "12"),
                ("Административная", "15", "4", "90", "1", "24"),
                ("Сервисная", "25", "4", "—", "—", "—"),
            ),
        )
    doc.add_heading("Контроль и пересмотр", 1)
    doc.add_paragraph(
        "Лица, ответственные за исполнение, представляют руководителю результаты контроля. "
        "Принятые решения, выявленные отклонения, сроки исправления и результаты повторной проверки подлежат регистрации."
    )


def archive(data, diagram=None):
    result = assess(data)
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as z:
        for index, title in enumerate(selected_documents(data), 1):
            doc = setup(title, data)
            if title == BASE[0]:
                model(doc, data, result, diagram)
            elif title == BASE[1]:
                type_section(doc, data, result)
                doc.add_paragraph(f"Решение комиссии: установить УЗ-{result['level']}.")
                doc.add_paragraph(result["basis"] + ".")
                crypto_section(doc, data, result)
                signatures(doc, data)
            elif title == BASE[2]:
                measures(doc, data, result)
                signatures(doc, data)
            elif title in EXTENDED:
                extended(doc, title, data, result)
            else:
                optional(doc, title, data)
            content = BytesIO()
            doc.save(content)
            z.writestr(f"{index:02}_{title}.docx", content.getvalue())
    return output.getvalue()
