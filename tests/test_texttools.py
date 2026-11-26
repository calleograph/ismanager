import io
import re
import secrets
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app, passwords
from app.auth import digest
from app.db import get_db
from app.privacy import names
from app.privacy.engine import PrivacyError
from app.privacy.export import export
from app.privacy.faceless import rules
from app.privacy.files import extract
from app.redaction import analyze


class PasswordTests(unittest.TestCase):
    def test_four_modes(self):
        options = [
            {"mode": "random", "random_length": "24", "upper": "on", "lower": "on", "digits": "on",
             "special": "on", "specials": "+", "exclude": "on"},
            {"mode": "custom", "phrase": "парус маячок волна", "position": "start"},
            {"mode": "dictionary", "word_length": "12"},
            {"mode": "dictionary", "word_length": "18"},
            {"mode": "story"},
        ]
        for opt in options:
            for _ in range(14):
                item = passwords.make_password(opt)
                pwd = item["password"]
                if opt["mode"] == "random":
                    self.assertEqual(len(pwd), 24)
                    for regex in ("[A-Z]", "[a-z]", "[2-9]", r"\+"):
                        self.assertRegex(pwd, regex)
                    self.assertNotRegex(pwd, "[Il1O0|]")
                elif opt["mode"] == "custom":
                    self.assertRegex(pwd, r"^[2-9!@#$%+]{2,3}ParusMayachokVolna$")
                elif opt["mode"] == "dictionary":
                    self.assertLessEqual(len(pwd), int(opt["word_length"]))
                    self.assertEqual(len(set(item["words"])), 2 if opt["word_length"] == "12" else 3)
                else:
                    self.assertEqual(len(item["words"]), 4)
        for opt in [{"mode":"custom","phrase":"дом дом дом"}, {"mode":"random","random_length":"4"},
                    {"mode":"dictionary","word_length":"42"}, {"mode":"invalid"}]:
            with self.assertRaises(ValueError):
                passwords.make_password(opt)


class TextTests(unittest.TestCase):
    def test_rules_and_package_roundtrip(self):
        self.assertEqual(len(rules()), 240)
        from openpyxl import load_workbook
        for ext in ("docx", "odt", "xlsx", "ods"):
            blob = export(ext, "=A1\tИмя\nстрока")
            text, _ = extract(ext, blob)
            self.assertIn("=A1", text)
            self.assertIn("строка", text)
            if ext == "xlsx":
                workbook = load_workbook(io.BytesIO(blob))
                self.assertEqual(workbook.active["A1"].data_type, "s")
                workbook.close()
        with self.assertRaises(ValueError):
            extract("png", b"wrong format")
        with self.assertRaises(ValueError):
            extract("txt", b"AB\x00")
        with self.assertRaises(ValueError):
            export("xlsx", "x" * 32768)

    @unittest.skipUnless((names.NLP_DIR / names.NER_FILE).exists(), "Install NLP models as documented")
    def test_detection_and_controls(self):
        sample = "Full name: Alice Winters\nИван Петров. x@example.org\nПароль: NeverUse88!X\nВерсия 8.3.24.1559"
        for profile in ("basic", "strict", "faceless"):
            result = analyze(sample, profile)
            self.assertNotIn("Winters", result.text)
            self.assertNotIn("Петров", result.text)
            self.assertNotIn("example.org", result.text)
            self.assertNotIn("NeverUse", result.text)
            self.assertIn("8.3.24.1559", result.text)
        self.assertEqual(analyze("На встрече обсудили итоги.", "faceless").text, "На встрече обсудили итоги.")
        self.assertNotIn("Wintermark", analyze("Проект Wintermark завершён.", "faceless", "Wintermark").text)
        with self.assertRaises(ValueError):
            analyze(sample, "strict", "re:.*")

    def test_missing_model_fails_closed(self):
        with patch.object(names, "models", side_effect=names.NlpUnavailable("model unavailable")):
            with self.assertRaises((names.NlpUnavailable, PrivacyError)) as e:
                analyze("Имя: Иван Петров", "faceless")
            self.assertIn("model", str(e.exception))

    @unittest.skipUnless(shutil.which("tesseract"), "Install Tesseract rus+eng for OCR")
    def test_real_ocr(self):
        from PIL import Image, ImageDraw, ImageFont
        image = Image.new("RGB",(1100,150),"white")
        font = ImageFont.load_default(size=54)
        ImageDraw.Draw(image).text((20,25),"Mail: sample@example.org",font=font,fill="black")
        raw = io.BytesIO()
        image.save(raw, "PNG")
        text, _ = extract("png", raw.getvalue())
        self.assertIn("example",text.lower())
        pdf = io.BytesIO()
        image.save(pdf, "PDF")
        text, info = extract("pdf", pdf.getvalue())
        self.assertIn("example", text.lower())
        self.assertIn("OCR", info)


class RouteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.app = create_app({"DATA_DIR":temp.name,"TESTING":True,"SECRET_KEY":secrets.token_hex(32)})
        self.client = self.app.test_client()
        with self.app.app_context(), get_db() as db:
            db.executemany("INSERT INTO users(identity,username,display_name,admin) VALUES(?,?,?,0)",
                           [(u,u,u) for u in ("one", "two")])
        self.login("one")

    def login(self, user):
        sid = secrets.token_hex(24)
        self.csrf = secrets.token_hex(24)
        with self.app.app_context(), get_db() as db:
            db.execute("INSERT INTO sessions SELECT ?,id,? FROM users WHERE identity=?", (digest(sid),int(time.time())+600,user))
        with self.client.session_transaction() as session:
            session["sid"], session["csrf"] = sid, self.csrf

    def post(self, url, **fields):
        return self.client.post(url,data={"csrf_token":self.csrf, **fields})

    def test_server_passwords_and_invalid_files(self):
        self.assertEqual(self.client.get("/passwords/").status_code, 200)
        response = self.post("/passwords/generate",mode="story")
        self.assertEqual(len(response.json["results"]),7)
        self.assertIn("no-store",response.headers["Cache-Control"])
        self.assertEqual(self.post("/passwords/generate",mode="invalid").status_code,422)
        self.assertEqual(self.post("/redaction/",file=(io.BytesIO(b"invalid"),"test.xlsx")).status_code,422)

    @unittest.skipUnless((names.NLP_DIR / names.NER_FILE).exists(), "Install NLP models as documented")
    def test_owner_result_and_preview(self):
        data = "Mailbox: test@example.org\nПароль: KeepPrivate123!"
        page = self.post("/redaction/",text=data,profile="faceless",preview="1")
        self.assertEqual(page.status_code,200)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT count(*) FROM redactions").fetchone()[0],0)
        nonce = secrets.token_hex(16)
        page = self.post("/redaction/",file=(io.BytesIO(data.encode()),"notes.txt"), nonce=nonce)
        self.assertEqual(page.status_code,200)
        self.assertEqual(self.post("/redaction/",text=data,nonce=nonce).status_code,302)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT count(*) FROM redactions").fetchone()[0],1)
        path = "/redaction/1"
        for body in (self.client.get(path).get_data(as_text=True),self.client.get(path+"/download").get_data(as_text=True)):
            self.assertNotIn("test@example.org",body)
            self.assertNotIn("KeepPrivate",body)
        self.assertEqual(self.client.get(path+"/download?format=docx").status_code,200)
        self.login("two")
        for action in [path,path+"/download",path+"/download?format=ods"]:
            self.assertEqual(self.client.get(action).status_code,404)
        self.assertEqual(self.post(path+"/delete").status_code,404)
        self.login("one")
        self.assertEqual(self.post(path+"/delete").status_code,302)
        self.assertEqual(self.client.get(path).status_code,404)
