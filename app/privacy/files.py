"""Extract only document text. Uploaded Office archives are never returned to users."""
import io
import json
import os
import re
import resource
import subprocess
import sys
import tempfile
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from defusedxml import ElementTree as ET

MAX_BYTES = 12 * 1024 * 1024
MAX_TEXT = 60_000
TEXT = {"txt", "log", "md", "csv", "json", "yaml", "yml", "xml", "ini", "cfg", "conf", "env"}
OFFICE = {"docx", "odt", "xlsx", "ods"}
IMAGES = {"png", "jpeg", "jpg", "tif", "tiff"}
SUPPORTED = sorted(TEXT | OFFICE | IMAGES | {"html", "htm", "pdf"})
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
OD = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
TAB = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"


class FileError(ValueError):
    pass


def decode_text(data):
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        return data.decode("utf-16")
    if b'\x00' in data or sum(c < 9 or 13 < c < 32 for c in data[:4096]) > 4:
        raise FileError("Файл не похож на текстовый.")
    for encoding in ("utf-8-sig", "cp1251"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    raise FileError("Сохраните текст в UTF-8 или Windows-1251.")


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.out = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in ("p", "br", "div", "li", "tr", "h1", "h2", "h3"):
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def office(ext, data):
    blocks = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        names = set(archive.namelist())
        if (len(members) > 2048 or len(names) != len(members)
            or sum(item.file_size for item in members) > 32 * 1024**2
            or any(item.flag_bits & 1 or item.file_size > max(1024, item.compress_size * 200) for item in members)):
            raise FileError("Документ превышает лимиты распаковки или зашифрован.")
        def xml(name):
            return ET.fromstring(archive.read(name))

        if ext == "docx":
            parts = ["word/document.xml"] + sorted(n for n in names if re.fullmatch(r"word/(header\d*|footer\d*|footnotes|endnotes|comments)\.xml", n))
            for part in parts:
                for p in xml(part).iter(W+"p"):
                    blocks.append("".join(x.text or "" if x.tag in (W+"t", W+"delText", W+"instrText") else
                                          "\n" if x.tag == W+"br" else "\t" if x.tag == W+"tab" else "" for x in p.iter()))
        elif ext in ("odt", "ods"):
            if archive.read("mimetype").strip() != ("application/vnd.oasis.opendocument." + ("text" if ext == "odt" else "spreadsheet")).encode():
                raise FileError("Содержимое не соответствует формату OpenDocument.")
            for part in ["content.xml"] + (["styles.xml"] if "styles.xml" in names else []):
                root = xml(part)
                if ext == "ods" and part == "content.xml":
                    for table in root.iter(TAB+"table"):
                        blocks.append(table.get(TAB+"name", ""))
                        for row in table.iter(TAB+"table-row"):
                            blocks.append("\t".join(" ".join("".join(p.itertext()) for p in c.iter(OD+"p"))
                                                    for c in row if c.tag in (TAB+"table-cell", TAB+"covered-table-cell")))
                else:
                    blocks.extend("".join(p.itertext()) for p in root.iter() if p.tag in (OD+"p", OD+"h"))
        else:
            xml("xl/workbook.xml")
            shared = []
            if "xl/sharedStrings.xml" in names:
                shared = ["".join(node.text or "" for node in si.iter(S+"t")) for si in xml("xl/sharedStrings.xml").iter(S+"si")]
            parts = sorted(n for n in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n))
            if not parts:
                raise FileError("В таблице отсутствуют листы.")
            for number, part in enumerate(parts, 1):
                blocks.append(f"Лист {number}")
                for row in xml(part).iter(S+"row"):
                    cells = []
                    for c in row.findall(S+"c"):
                        ref = re.match(r"([A-Z]{1,3})[0-9]+$", c.get("r", ""))
                        if ref:
                            col = 0
                            for letter in ref[1]:
                                col = col * 26 + ord(letter) - 64
                            if col > 16384:
                                raise FileError("Недопустимый номер столбца Excel.")
                            cells.extend([""] * max(0, col - len(cells) - 1))
                        value = c.findtext(S+"v", "")
                        if c.get("t") == "s":
                            idx = int(value)
                            if not 0 <= idx < len(shared):
                                raise FileError("Нарушена таблица общих строк XLSX.")
                            value = shared[idx]
                        elif c.get("t") == "inlineStr":
                            value = "".join(t.text or "" for t in c.iter(S+"t"))
                        if c.find(S+"f") is not None:
                            value = " ".join(filter(None, [value, c.findtext(S+"f")]))
                        cells.append(value)
                    blocks.append("\t".join(cells))
            for part in sorted(n for n in names if re.fullmatch(r"xl/(?:comments\d+|comments/comment\d+)\.xml", n)):
                blocks.extend("".join(t.text or "" for t in c.iter(S+"t")) for c in xml(part).iter(S+"comment"))
        images = any(n.startswith(("word/media/", "Pictures/", "xl/media/")) and not n.endswith("/") for n in names)
    text = "\n".join(blocks).strip()
    if images and not text:
        raise FileError("Документ содержит только изображения. Загрузите изображения по отдельности для OCR.")
    return text, ("Изображения внутри офисного документа опущены." if images else "")


def run_tool(args):
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=22, check=True)
    except FileNotFoundError:
        raise FileError("В образе отсутствует Poppler или Tesseract. Проверьте установку.") from None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise FileError("Документ повреждён, защищён или превысил время обработки.") from None
    return proc.stdout


def media(ext, data):
    with tempfile.TemporaryDirectory(prefix="ismanager-ocr-") as work:
        path = Path(work) / ("input." + ext)
        path.write_bytes(data)
        def ocr(path):
            text = run_tool(["tesseract", str(path), "stdout", "-l", "rus+eng"]).decode("utf-8")
            if not text.strip():
                raise FileError("OCR не смог прочитать текст. Проверьте качество изображения.")
            return text
        if ext in IMAGES:
            valid = {"png": b"\x89PNG\r\n\x1a\n", "jpeg": b"\xff\xd8\xff", "jpg": b"\xff\xd8\xff",
                     "tif": (b"II*\x00", b"MM\x00*"), "tiff": (b"II*\x00", b"MM\x00*")}
            if not data.startswith(valid[ext]):
                raise FileError("Содержимое файла не соответствует формату изображения.")
            return ocr(path), "Текст распознан локально. Проверьте чтение имён и цифр."
        if b"%PDF-" not in data[:1024]:
            raise FileError("Содержимое файла не соответствует формату PDF.")
        info = run_tool(["pdfinfo", str(path)]).decode("utf-8", errors="replace")
        if re.search(r"(?mi)^Encrypted:\s*yes", info):
            raise FileError("Снимите пароль с PDF перед загрузкой.")
        pages = re.search(r"(?m)^Pages:\s*(\d+)\s*$", info)
        if not pages or not 1 <= int(pages[1]) <= 60:
            raise FileError("Предел для PDF — 60 страниц.")
        blocks = []
        had_ocr = False
        for i in range(1, int(pages[1]) + 1):
            page_range = ["-f", str(i), "-l", str(i)]
            text = run_tool(["pdftotext", *page_range, "-layout", "-nopgbrk", "-enc", "UTF-8", str(path), "-"]).decode("utf-8")
            if len(text.strip()) < 20 and re.search(rb"(?m)^\s*\d+\s+\d+\s+",
                                                    run_tool(["pdfimages", *page_range, "-list", str(path)])):
                prefix = str(Path(work) / "page")
                run_tool(["pdftoppm", "-f", str(i), "-l", str(i), "-scale-to", "3000", "-singlefile",
                          "-png", str(path), prefix])
                text = ocr(prefix+".png")
                had_ocr = True
            blocks.append(text)
            if sum(map(len, blocks)) > MAX_TEXT:
                raise FileError("Извлечённый текст длиннее 60 000 знаков.")
        return "\n\n".join(blocks), ("Использован OCR. Проверьте имена и цифры." if had_ocr else "")


def extract(ext, data):
    if ext not in SUPPORTED:
        raise FileError("Формат файла не поддерживается.")
    if not data or len(data) > MAX_BYTES:
        raise FileError("Требуется непустой файл до 12 МиБ.")
    if ext in OFFICE:
        text, note = office(ext, data)
    elif ext in IMAGES or ext == "pdf":
        text, note = media(ext, data)
    else:
        text, note = decode_text(data), ""
        if ext in ("html", "htm"):
            parser = VisibleText()
            parser.feed(text)
            text = "".join(parser.out)
    if not text.strip() or len(text) > MAX_TEXT:
        raise FileError("Требуется от 1 до 60 000 знаков извлечённого текста.")
    return text, note


if __name__ == "__main__":
    # File parsers run outside the web process with a shared CPU, memory and file-size ceiling.
    resource.setrlimit(resource.RLIMIT_CPU, (50, 50))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (48 * 1024**2,) * 2)
    os.environ["OMP_THREAD_LIMIT"] = "1"
    os.environ["LC_ALL"] = "C"
    try:
        value, note = extract(sys.argv[1], sys.stdin.buffer.read(MAX_BYTES + 1))
        print(json.dumps({"text": value, "note": note}, ensure_ascii=False))
    except ValueError as exc:
        # Third-party parser messages may contain input bytes. Only expose our known errors.
        message = str(exc) if type(exc) is FileError else "Не удалось прочитать файл."
        print(json.dumps({"error": message}, ensure_ascii=False))
    except Exception:
        print(json.dumps({"error": "Файл повреждён или не соответствует формату."}, ensure_ascii=False))
