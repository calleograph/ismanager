from io import BytesIO
from zipfile import BadZipFile, ZipFile

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils.exceptions import InvalidFileException
from openpyxl.worksheet.datavalidation import DataValidation
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError
from lxml.etree import XMLSyntaxError

from . import CAT, FIELDS, REQUIRED, clean


def rows():
    # Первые строки сохраняют расположение и названия полей ранее выданных анкет.
    yield from CAT["fields"]
    yield None, "Дополнительные сведения", "text", ""
    original = {row[0] for row in CAT["fields"]}
    for key, (label, kind, options) in FIELDS.items():
        if key not in original:
            yield key, label, kind, options


def workbook(data):
    book = Workbook()
    sheet = book.active
    sheet.title = "Анкета"
    sheet.append(["Что заполняем", "Значение"])
    sheet.freeze_panes = "B2"
    sheet.column_dimensions["A"].width = 72
    sheet.column_dimensions["B"].width = 65
    for key, label, kind, options in rows():
        value = data.get(key, "")
        if kind == "bool":
            value = "да" if value else "нет"
        sheet.append([label, value])
        a, b = sheet[sheet.max_row]
        b.data_type = "s"
        a.alignment = b.alignment = Alignment(vertical="top", wrap_text=True)
        if not key:
            a.fill = PatternFill("solid", fgColor="DAE7F0")
            a.font = Font(bold=True)
        if key and kind in ("bool", "enum"):
            dv = DataValidation(type="list", formula1='"' + ",".join(options) + '"', allow_blank=True)
            dv.showErrorMessage = True
            sheet.add_data_validation(dv)
            dv.add(b)
    stream = BytesIO()
    book.save(stream)
    stream.seek(0)
    return stream


def read_workbook(raw):
    if len(raw) > 2_000_000:
        raise ValueError("Файл анкеты должен быть меньше 2 МБ.")
    labels = {label: key for key, label, _, _ in rows() if key}
    values = {}
    try:
        with ZipFile(BytesIO(raw)) as z:
            entries = z.infolist()
            if len(entries) > 250 or sum(e.file_size for e in entries) > 8_000_000:
                raise ValueError("Превышен размер распакованной книги.")
        book = load_workbook(BytesIO(raw), read_only=True, keep_links=False)
        try:
            if "Анкета" not in book.sheetnames:
                raise ValueError("В книге должен быть лист «Анкета».")
            sheet = book["Анкета"]
            sheet.reset_dimensions()
            for row, (a, b) in enumerate(sheet.iter_rows(max_col=2), 1):
                if row > 350:
                    raise ValueError("Слишком много строк в анкете.")
                key = labels.get(a.value)
                if key:
                    if key in values or b.data_type == "f":
                        raise ValueError("В книге есть повторяющиеся поля или формулы.")
                    values[key] = clean(key, str(b.value) if b.value is not None else "")
        finally:
            book.close()
    except (
        BadZipFile,
        InvalidFileException,
        KeyError,
        OSError,
        ParseError,
        XMLSyntaxError,
        DefusedXmlException,
        RuntimeError,
        TypeError,
        IndexError,
        OverflowError,
    ) as error:
        raise ValueError("Не удалось прочитать книгу XLSX. Используйте шаблон анкеты.") from error
    if REQUIRED - values.keys():
        raise ValueError("В книге нет обязательных строк шаблона.")
    return values
