"""Build fresh Office packages exclusively from the verified text projection."""
import re
from io import BytesIO
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile

MIMES = {
    "odt": "application/vnd.oasis.opendocument.text",
    "ods": "application/vnd.oasis.opendocument.spreadsheet",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
OFFICE = "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}"
TEXT = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
TABLE = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"
MANIFEST = "{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}"


def export(ext, text):
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]", text):
        raise ValueError("Текст содержит управляющие символы. Выберите TXT.")
    buf = BytesIO()
    lines = text.split("\n")
    if ext == "docx":
        from docx import Document
        doc = Document()
        doc.core_properties.author = "IS Manager"
        doc.core_properties.comments = ""
        for line in lines:
            doc.add_paragraph(line)
        doc.save(buf)
    elif ext == "xlsx":
        from openpyxl import Workbook
        from openpyxl.cell import WriteOnlyCell
        book = Workbook(write_only=True)
        sheet = book.create_sheet("Результат")
        if any(len(line.split("\t")) > 16384 or any(len(value) > 32767 for value in line.split("\t")) for line in lines):
            raise ValueError("Текст превышает размер строки или ячейки Excel. Выберите TXT или ODS.")
        for line in lines:
            cells = []
            for value in line.split("\t"):
                cell = WriteOnlyCell(sheet, value)
                cell.data_type = "s"  # Preserve literal text even for cells beginning with an equals sign.
                cells.append(cell)
            sheet.append(cells)
        book.save(buf)
    elif ext in ("odt", "ods"):
        mime = MIMES[ext]
        manifest = ET.Element(MANIFEST+"manifest", {MANIFEST+"version": "1.2"})
        for path, content_type in (("/", mime), ("content.xml", "text/xml")):
            ET.SubElement(manifest, MANIFEST+"file-entry", {MANIFEST+"full-path": path, MANIFEST+"media-type": content_type})
        root = ET.Element(OFFICE+"document-content", {OFFICE+"version": "1.2"})
        body = ET.SubElement(root, OFFICE+"body")
        if ext == "odt":
            doc = ET.SubElement(body, OFFICE+"text")
            for line in lines:
                ET.SubElement(doc, TEXT+"p").text = line
        else:
            sheet = ET.SubElement(ET.SubElement(body, OFFICE+"spreadsheet"), TABLE+"table", {TABLE+"name": "Результат"})
            for line in lines:
                row = ET.SubElement(sheet, TABLE+"table-row")
                for value in line.split("\t"):
                    cell = ET.SubElement(row, TABLE+"table-cell", {OFFICE+"value-type": "string"})
                    ET.SubElement(cell, TEXT+"p").text = value
        with ZipFile(buf, "w") as archive:
            archive.writestr("mimetype", mime)
            archive.writestr("content.xml", ET.tostring(root, encoding="utf-8", xml_declaration=True), ZIP_DEFLATED)
            archive.writestr("META-INF/manifest.xml", ET.tostring(manifest, encoding="utf-8", xml_declaration=True), ZIP_DEFLATED)
    else:
        raise ValueError("Неизвестный формат.")
    return buf.getvalue()
