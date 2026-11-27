"""Format coverage with synthetic documents. No customer data or network fixtures."""

import base64
import io
import shutil
import zipfile
import zlib

import pytest
from PIL import Image, ImageDraw, ImageFont

from app.privacy.files import (
    BATCH_MAX_TEXT,
    MAX_TEXT,
    FileError,
    extract,
    extract_isolated,
)
from app.privacy.known_values import MASK

# Small original samples from xlwt (BIFF8), a minimal BIFF12 package and LibreOffice Word 97.
XLS = zlib.decompress(
    base64.b64decode(
        "eNrtWE1oE0EU/mYzSZrQ/LWp0Io1Fqxae9DWoqjJJinag1pqL4oImtqA0pJqWg96sVpzFARPipdCL16qXvxBD3rzIFT0IAiF"
        "RI+eBAUPbdY3L7sl1R4a0KIy3/LevHnz3s7b+Xmzu2/mIsXphy0l/IQEXChbPniqdILI51TCoHbLUqJT1hFZGv8UfHU0kR43"
        "ngVee9UcqvkuwcAD+ZI48JHoJM6jfyyXja0h0hxDRqgY4sQF7pImiGaOqoH5GeaNzO+z5XPmSdbcYB4n26I4gTmzv2OPvYqP"
        "G23cFoS672P2+cCanWjCK7WKr9wUFVs3UvlzmdG/s6FV1mMGNG992Vw2nxktIkoTOINvVgz46uzUFzGtX1u9AOm/L9d7V9Df"
        "MiQwCes0L/AC5dSQrCTSweyFi9nxifEFnOUtqcgNsUEm5H7ZI5PSA7FR7iAhIffJw6q6SaZJkZa9MkVVpNK93bt6AhBxso/B"
        "JMO91L5bHpJdbMdOjaROE3UR+VV653QQXpYOArxN6okPI8RyhDdLmOJcuPfl7ZGhAfMUayb5CKgcFJvVs8HCVeVBzkFuMZi7"
        "iDpY3s78Gt91PcstzKP0tFS2DzTZwsEptrnOre3UTzfjnbmlSt5KcuHz0SethU/mNpJn+0qXo7PvzWm00cE1TP7qmkKn6BR3"
        "bis8NZ1S2EllnnnzLwmmzgjbsVv2aRjCIvwsRphXamp0xFLNsMdKeYsVvAV7u2x7wd5yqaa83eowNhrwiIcuWXUc+6GhoaGh"
        "oaGhoaFRI4T9Uq5eQSV/ZFRe+r32f51ForL+TfLfYhBjdE3Qh+kB5KjM41JN62cd3MK5l1ilj/O/UOEY9Z7HCIY4jpGa1y99"
        "tInq51m1Y/j3baFa+y/XEucf7v8H6+XJHw=="
    )
)

XLSB = zlib.decompress(
    base64.b64decode(
        "eNqdVE1v0zAYft16FQcQSKtQhYQIOSAQWtJ2G5NGW7oWDlURVBM3NE1u4rZR84XjjVZcgO2K+BBHfkAPnHfn93Ca4AfwOl1p"
        "EzqEsPQkr+3Xz2vneZxOO0vzoNqEvdr7PjkpbWGscBkxcs2XgRh2g2BodB3/iMB7Al/IbZVPEBQhoAU2lOACxrvA4QUc4DMC"
        "ifhA4JhAJ1GjfjS+c4qxwrVpjX3B3ShRyVAjlV3uMukEfjRwwkgbea4fVfWBlOG2aUbWgHssMoKQ+zjTC4THJHZF3wyZNWR9"
        "bpaLxXumWOTQawlOrWVXddGyS7r2bBzyf+EOej3H4g8D68DjvlxSIj5GNOBcIikTfS6r+u+hyIxfJXVE3axVzMQJa8kPdbd6"
        "/PUHxgqFuRh/EL0h8JlcmUmiWgbxETt5WNJyV2fRCuI6rdEK3aR1mivMlucQN2gRx2r0Pn2MM5mFmZu0gXMN2qQ7FPJkWYUC"
        "LOTvQAOasA4bsAm5W7P8S4gq1tXgAVbZRsYt2qblmDldcRUzGogy4hOBt2lH/ayfbnzDWGEV8bwZ+BLV2VeiRnsGSliJw/+0"
        "kDWlW5OKAy309JAL4dhc6zAhnzAPjWOmboqune1h6isWhq5jxUqbh75teNEaH1ncNWIV1QImxobHLBE88lnX5ZjCziwS7xyt"
        "QTL57Pk3ddZexx84tZv04vQVnC+2/3oh0zxph8553pHz/ZpmScs3ZznJLBWz015RtsC/D4WLWGiSVb1fg9QrkA=="
    )
)

DOC = zlib.decompress(
    base64.b64decode(
        "eNrtmU1MXFUUx8998+EMtjAMiJVimU5HQNrCAG0FC6UMlE6nhaEFi4laMzAgg2UGYVBMjDExJi60wbhwY2Jt6ErToMZNN7py"
        "Z2TTReMGlyYuqnHDooz/c9997ThC+2YgGuQd8uN+vHfvue/ec8/9mOWfSlc+/6ryF8qR42SjtYybnFl5AhQbCQ+RpvLWMpmM"
        "kZ2xZFvJXRXyGNoxfg7AY/4IcAE3KAKPgl1gtxrvEhVasr3lAqXwlyYfnaIkwhl6k/KRClhMdn1myqyZfM+sWPoL12/473zm"
        "P68BJfoSQKXAC8pAOXhM2gTR42APeELVvxdhlYrvQ1gNfGA/8IMDIACeAjWgFtSBp0E9OAgOgcOgATSCIGgCzaAFHAFHwTHw"
        "DGgFbeBZuZ4RtYMOcAJ0gpOgC4RAN+gBp0AvOA3C4AyIgLPgHOgD/SAKBsB5cAEMgiHwnPrG4W3iHwVaaSvSbcjp1qRNfK+b"
        "Ri+PX19idCY1mxpP+4ZTM/HDPalX56bGkmlpE32DnNeTGpWWwPEGJOTzhlb6s+3r1x5ui0LfRhQsXlhdEWp5QVqkLpdgmr9n"
        "NA5hy/3wbzM0RTG6rOy4KUD1AdEVYKsJ1VM0YqPzoDuyh6bCbvssOBvWaCBip2TY7kqDS4jH8PzlcJv9ge3ppbVqQZrolXMo"
        "TGPQG6cEfOsrcvaUUNniHSpfnCdnQGCGRCMOKHdAeZVUqCuqgi2HPFzPETkHh1DPvPTSIXxNXPpoD/688XIhUCPm3uIHcoY1"
        "eoTwCp5pdthrgmZRiru4VNq/H3X6RbtsWzdaNo2nCdSYlG3zoqZ52bZdaFux7JBjLsHf/ZJL+OWXNQu/9BJnUCYuW8WpMllC"
        "l06pW98oSo8EN/K2S/csRtyZ9S6L5snKGNA9j3zpdMWCMGMGQ/iMKTRnFl3Uj/ANhLy08bDzxx1FPWbsbBBdO0UjKMnG0lJj"
        "TnsXDCyhDKzLZIt70MpJlLlIc2jrIFJcxzj3gbOwGvhLZ7l8zebKhzB8wvUhZv8yumxCrDNl1cJwQqaEHPB3pdK/5xpFa23S"
        "10u7sGQTzi649XXmzAqfyUHKuyXvbLQXYTPR1lsXaOW9z/5YjU54vvjIRQdrv7nNOt9SjkGo9d2t1vEitT6zf39e7VXiar8y"
        "rT7z17tE+1Q8qMoZYia+nvx2XYg+nxt9dsf7XXbXKE8HLxpLXY4lW9fpMLe9gjqK76c7H7rPK5FeVKi4MyueK+/L/1fUDLxi"
        "wiHwO+V5DOg1offyDRUa8jPS82LzhnmzwDoGbUQjWQb1g9B3pZb8P+Vmjv39W6LRbavzLbFkRwsfGPjebAKbaT5LjWIHlZYH"
        "ET6tjcuzp4+GZRhHbBphCm+NITWHOL/ZgPxzMpePEPo7CXodqVHU7sMbMRxKpvFsDKlWnFrbqBmldlvd/9+L2udZsiNFGOO/"
        "avXFDhGcumwBigWILxDFcWoP0skBotCARtVLy42+pZWO/UtXHX5wYOGqIwCa8bxpIU5BPolSC1J1zVQcfND5l3O0Wz/e+rRh"
        "r+fjT3D+PbR6g++nHTl5L5J+z25ct3iyzrob5WfLVv7+w3py75DXK2PTC6oJ1C2v6aYpSiM0mf+VCL5KUzdLmTx+V5m8N4Gj"
        "cl0tVIqgnfXa8tDP7TVO2k00hNV9pOA2FCv9+fz+w2391qHHHdjBzKH/+aKUx57vdcfv3Zjfvx3eSOqg3/jNyKz+SvClihs7"
        "ox65/5mTl7hJeWdtTioL+P4ngXHv4viH5vz6o7UA/RdBegs90mZ+//sLG4fdvA=="
    )
)


def package(parts):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in parts.items():
            archive.writestr(name, content)
    return stream.getvalue()


@pytest.mark.parametrize("ext,payload", [("xls", XLS), ("xlsb", XLSB)])
def test_binary_workbooks(ext, payload):
    text, _ = extract(ext, payload)
    assert "ABC345" in text and "Готово" in text and MASK in text
    assert "не показывать" not in text


@pytest.mark.parametrize("ext", ["xlsx", "xlsm"])
@pytest.mark.parametrize("strict", [False, True])
def test_ooxml_excel_strict_shared_inline_custom_paths_and_repeats(ext, strict):
    ns = ("http://purl.oclc.org/ooxml/" if strict else "http://schemas.openxmlformats.org/") + (
        "spreadsheetml/main" if strict else "spreadsheetml/2006/main"
    )
    rns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    book = package(
        {
            "xl/workbook.xml": f'<workbook xmlns="{ns}" xmlns:r="{rns}"><sheets><sheet name="Архив" r:id="chosen"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": f'<Relationships><Relationship Id="chosen" Type="{rns}/worksheet" Target="worksheets/custom.xml"/>'
            f'<Relationship Id="strings" Type="{rns}/sharedStrings" Target="sharedStrings.xml"/></Relationships>',
            "xl/sharedStrings.xml": f'<sst xmlns="{ns}"><si><r><t>API </t></r><r><t>key</t></r></si></sst>',
            "xl/worksheets/custom.xml": f'''<worksheet xmlns="{ns}"><sheetData>
          <row><c r="A1" t="inlineStr"><is><t>Комментарий</t></is></c><c r="C1" t="s"><v>0</v></c></row>
          <row><c r="A2" t="inlineStr"><is><t>Упомянут лунный луч.</t></is></c></row>
          <row><c r="C3" t="inlineStr"><is><t>лунный луч</t></is></c></row></sheetData></worksheet>''',
        }
    )
    value, _ = extract(ext, book)
    assert "Архив" in value and "Упомянут" in value and value.count(MASK) == 2
    assert "лунный луч" not in value


@pytest.mark.parametrize("enc", ["utf-8-sig", "utf-16", "utf-16-be", "cp1251", "cp866", "koi8-r"])
@pytest.mark.parametrize("sep", [";", ",", "\t", "|"])
def test_csv_separators_and_encodings(enc, sep):
    data = f"Номер{sep}PIN-код{sep}Комментарий\r\n1{sep}4781{sep}Заявка 4781 принята\r\n"
    text, _ = extract("csv", data.encode(enc))
    assert "Комментарий" in text and "Заявка" in text and "4781" not in text and text.count(MASK) == 2


def test_csv_quoted_multiline_and_sheet_aliases():
    text, _ = extract("csv", b'sep=;\r\nNote;temporary password\r\nearlier winter moon;\r\nA;"winter\nmoon"')
    assert "winter" not in text and text.count(MASK) == 2
    xml = """<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:s="urn:schemas-microsoft-com:office:spreadsheet">
    <Worksheet s:Name="Заявки"><Table><Row><Cell s:Index="2"><Data>Пароль</Data></Cell></Row>
    <Row><Cell><Data>Открыто</Data></Cell><Cell><Data>скрытая фраза</Data></Cell></Row></Table></Worksheet></Workbook>"""
    for ext in ("xml", "xls"):
        value, _ = extract(ext, xml.encode())
        assert "Открыто" in value and "скрытая фраза" not in value and MASK in value
    html = (
        "<html><table><tr><th>OTP</th><th>Номер</th></tr><tr><td>739325</td><td>REQ001</td></tr></table></html>"
    )
    value, _ = extract("xls", html.encode("cp1251"))
    assert "REQ001" in value and "739325" not in value


def test_rtf_and_large_isolated_document(tmp_path):
    payload = r"{\rtf1\ansi\ansicpg1251 Запрос \u8470?123}".encode("cp1251")
    for ext in ("rtf", "doc"):
        assert "Запрос №123" in extract(ext, payload)[0]
    path = tmp_path / "raw-upload"
    path.write_text("начало\n" + "б" * 90_000 + "\nконец")
    assert len(extract_isolated(path, "txt")[0]) > MAX_TEXT
    with pytest.raises(FileError):
        extract_isolated(path, "txt", batch=False)
    path.write_text("содержимое" + "a" * BATCH_MAX_TEXT)
    with pytest.raises(FileError) as error:
        extract_isolated(path, "txt")
    assert "содержимое" not in str(error.value)
    path.write_bytes(b"secret-value-not-for-diagnostics")
    with pytest.raises(FileError) as error:
        extract_isolated(path, "xls")
    assert "secret-value" not in str(error.value)


def test_ods_secret_column_span_and_html_rowspan():
    office = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    table = office.replace("office:1.0", "table:1.0")
    text = office.replace("office:1.0", "text:1.0")
    rows = """<t:table-row><t:table-cell t:number-columns-spanned="2"><p:p>Пароли</p:p></t:table-cell><t:covered-table-cell/>
        <t:table-cell><p:p>Заявка</p:p></t:table-cell></t:table-row>
        <t:table-row><t:table-cell><p:p>луна</p:p></t:table-cell><t:table-cell><p:p>звезда</p:p></t:table-cell>
        <t:table-cell><p:p>Слово звезда встречалось.</p:p></t:table-cell></t:table-row>"""
    ods = package(
        {
            "mimetype": "application/vnd.oasis.opendocument.spreadsheet",
            "content.xml": f'<o:document-content xmlns:o="{office}" xmlns:t="{table}" xmlns:p="{text}"><t:table t:name="Архив">{rows}</t:table></o:document-content>',
        }
    )
    value, _ = extract("ods", ods)
    assert value.count(MASK) == 3 and "звезда" not in value and "луна" not in value
    html = b'<table><tr><th rowspan="2">Ticket</th><th>OTP</th></tr><tr><td>4771</td></tr></table>'
    assert "4771" not in extract("xls", html)[0]


def test_invalid_rtf_cannot_return_partial_text():
    with pytest.raises(FileError) as error:
        extract("doc", rb"{\rtf1\ansi raw-content-failure {incomplete}")
    assert "raw-content-failure" not in str(error.value)


@pytest.mark.parametrize("batch", [True, False])
def test_table_mask_count_is_optional_and_includes_repeated_mentions(tmp_path, batch):
    path = tmp_path / "upload"
    path.write_text("Комментарий;Пароль\nЗаявка;малиновый дождь")
    value, note, count = extract_isolated(path, "csv", batch=batch, with_counts=True)
    assert count == 1 and MASK in value
    assert extract_isolated(path, "csv", batch=batch) == extract("csv", path.read_bytes()) == (value, note)
    path.write_text("Комментарий;Пароль\nРанее малиновый дождь;\nЗаявка;малиновый дождь\n"
                    f"Повтор малиновый дождь;малиновый дождь\nСтарая маска;{MASK}")
    value, note, count = extract_isolated(path, "csv", batch=batch, with_counts=True)
    assert count == 4
    assert "малиновый дождь" not in value + note
    path.write_text("Обычная запись")
    assert extract_isolated(path, "txt", batch=batch, with_counts=True) == ("Обычная запись", "", 0)


@pytest.mark.skipif(not shutil.which("catdoc"), reason="Requires Debian catdoc and antiword")
def test_real_word97():
    value, _ = extract("doc", DOC)
    assert "Local privacy sample 8392" in value


def mixed_pdf():
    raster = Image.new("RGB", (800, 100), "white")
    ImageDraw.Draw(raster).text(
        (20, 20), "SCANNED NUMBER 8392", font=ImageFont.load_default(size=45), fill="black"
    )
    compressed = zlib.compress(raster.tobytes())
    commands = b"BT /F1 18 Tf 32 740 Td (Native heading with more than twenty characters) Tj ET\nq 550 0 0 70 32 585 cm /I Do Q"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> /XObject << /I 5 0 R >> >> /Contents 6 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /XObject /Subtype /Image /Width 800 /Height 100 /BitsPerComponent 8 /ColorSpace /DeviceRGB /Filter /FlateDecode /Length "
        + str(len(compressed)).encode()
        + b" >>\nstream\n"
        + compressed
        + b"\nendstream",
        b"<< /Length " + str(len(commands)).encode() + b" >>\nstream\n" + commands + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    positions = []
    for i, obj in enumerate(objects, 1):
        positions.append(len(output))
        output.extend(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(b"xref\n0 7\n0000000000 65535 f \n")
    for n in positions:
        output.extend(f"{n:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(output)


@pytest.mark.skipif(not shutil.which("tesseract"), reason="Requires Poppler and Tesseract")
def test_mixed_page_uses_both_layers(tmp_path):
    path = tmp_path / "mixed.pdf"
    path.write_bytes(mixed_pdf())
    text, note = extract_isolated(path, "pdf")
    assert "Native heading" in text and "8392" in text and "OCR" in note


def test_helpdesk_comment_does_not_turn_the_column_into_passwords():
    text, _ = extract("csv", "Номер;Описание\n1;Пользователь забыл пароль\n2;Печать восстановлена".encode())
    assert "Печать восстановлена" in text


@pytest.mark.parametrize("ext", ["csv", "docx"])
def test_property_catalog_protects_the_value_and_its_earlier_copies(ext):
    rows = [
        ("Category", "Raw value", "Expected action"),
        ("Description", "See silver orchid and RG-5027-2984", "Keep"),
        ("Password", "silver orchid", "Protect"),
        ("Internal document", "RG-5027-2984", "Flag for review"),
        ("Colour", "Azure", "Keep"),
    ]
    if ext == "docx":
        w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        table = "".join("<w:tr>" + "".join(f"<w:tc><w:p><w:r><w:t>{v}</w:t></w:r></w:p></w:tc>"
                                         for v in row) + "</w:tr>" for row in rows)
        data = package({"word/document.xml": f'<w:document xmlns:w="{w}"><w:body><w:tbl>{table}</w:tbl></w:body></w:document>'})
    else:
        data = "\n".join(";".join(row) for row in rows).encode()
    text, _ = extract(ext, data)
    assert "See " in text and "Colour\tAzure\tKeep" in text and "Password" in text
    assert text.count(MASK) == 4
    assert "silver orchid" not in text and "RG-5027-2984" not in text


def test_outlook_message_and_attachment_share_redaction_context(tmp_path):
    # Original synthetic CFB v3 message with a Unicode body and one password-column CSV.
    data = zlib.decompress(base64.b64decode(
        "eNrt2stOwkAUBuBTEBW83xVvVXcuDOiCRI07XRriwi2B2mgjOIYOGB/HR/BJ9BH0QRT/lsE0RpJqjAnk/5q/p3S0h05JExqen6ZeHh6zr"
        "/LFkSTlvZWWwcg+yyQ0KRhvtYLNTg20qKe8IQlzDQdQU0hwzYeQYSSNZMz4KOoYMo5MtD8CMoVMm/FZ1DlkHllAFpElJGvGV1BXkTVkHb"
        "GRDWTTjNP/OxOFReNaHMsNal3u5SfmJWV1jmXF/J/o/aKE5RZdFdYuqhYP1cfeZvjax2uFd5aXHcl9c6ycJKzg85s09544/ZPm/tXp70t"
        "DKlhruTR9Sqi5zyUvJ12PtY3+0fmM03/kS/8yOmusHbnqct4l2Yq8n/bSdijWZ/+BX87/d+e/JwXUQqzzT0Xu+3H6z8SY/3b/vMnun87/"
        "cqQ/EREREREREVG/OxcvfNZUkaq4YksN65oo2cd2M3wGFewPng8qqeOvPGzvcNqIiIiIiIiIeooT/spEh7/AqeKbvSM+vvcTERERERERU"
        "T85Vdo9KJZ9/07VLzLFRqXqObb2nGtXHzQ9VXW1reoVT2dsIiIiIiIiIupVHzT8x+U="
    ))
    path = tmp_path / "memo.msg"
    path.write_bytes(data)
    text, _, count = extract_isolated(path, "msg", with_counts=True)
    assert "Visible memo:" in text and "Public ticket" in text and "Вложение 1" in text
    assert "violet orbit" not in text and count == 2
    with pytest.raises(FileError):
        extract("msg", XLS)
