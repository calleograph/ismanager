import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from docx import Document
from flask import Flask, g
from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader
from openpyxl import load_workbook

from app import threats
from app.db import close_db, get_db
from app.threat_model import CAT, DEFAULT, assess, conclusions
from app.threat_model.documents import OPTIONAL
from app.threat_model.workbook import read_workbook, workbook

SAMPLE = {
    **DEFAULT,
    "systemType": "erp_1c",
    "systemNetworkCondition": "corporate_internet",
    "operatorFullName": "Синтетический оператор",
    "operatorShortName": "Пример",
    "operatorLegalAddress": "Тестовый адрес",
    "infosystemFullName": "Учебная система",
    "infosystemShortName": "Учёт",
    "dataCategory_other": True,
    "subjectType": "employee",
}


class ThreatCalculations(unittest.TestCase):
    def test_reference_profiles(self):
        # Контрольные суммы решений исходного калькулятора по всем 243 строкам.
        cases = [
            (SAMPLE, "6ced54240aba8819adb6acae4e54b11a650c2782ce3a2b5628da3bc64c25a5af"),
            (
                {
                    **SAMPLE,
                    "systemType": "custom_mixed",
                    "systemNetworkCondition": "cloud_saas_platform",
                    "flags": ["government_restricted"],
                    "physicalSecurityMeasures": "СКУД",
                },
                "c944b661efeb30335c592b39fa36df9f6dafc18a8fea3e9660cea03371df42b1",
            ),
        ]
        for data, expected in cases:
            decisions = conclusions(data)
            self.assertEqual(
                hashlib.sha256("\n".join(decisions.values()).encode()).hexdigest(), expected
            )
            self.assertEqual(len(decisions), 243)
            self.assertNotIn("УБИ.218", decisions)

    def test_assessment(self):
        self.assertEqual(assess(SAMPLE)["level"], 4)
        severe = {
            **SAMPLE,
            "developerUndeclaredRisk": True,
            "systemSoftwareUndeclaredRisk": True,
            "usesCryptoTools": True,
        }
        self.assertEqual(assess(severe)["type"], 1)
        self.assertEqual(assess(severe)["crypto"]["class"], "КА")
        infra = {
            **SAMPLE,
            "objectType": "infrastructure_object",
            "infrastructureMaxUzLevel": "2",
            "usesCryptoTools": True,
            "cryptoViolator_kv__research_center_resources": True,
        }
        self.assertEqual(assess(infra)["level"], 2)
        self.assertEqual(assess(infra)["crypto"]["class"], "КВ")
        self.assertEqual(assess({**SAMPLE, "dataCategory_special": True})["level"], 3)
        self.assertEqual(sum(map(len, CAT["techniqueIds"].values())), 145)

    def test_workbook_validation(self):
        raw = workbook({**SAMPLE, "operatorFullName": "=текст"}).getvalue()
        self.assertEqual(read_workbook(raw)["operatorFullName"], "=текст")
        b = load_workbook(io.BytesIO(raw))
        b.active["B3"] = "=1+1"
        malformed = io.BytesIO()
        b.save(malformed)
        with self.assertRaises(ValueError):
            read_workbook(malformed.getvalue())
        with self.assertRaises(ValueError):
            read_workbook(b"not an xlsx")


class ThreatWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True, DATABASE=str(Path(self.tmp.name) / "test.db"), SECRET_KEY="test"
        )
        self.app.register_blueprint(threats.bp)
        self.app.jinja_loader = ChoiceLoader(
            [
                DictLoader({"base.html": "{% block content %}{% endblock %}"}),
                FileSystemLoader(Path(threats.__file__).parent / "templates"),
            ]
        )
        self.app.jinja_env.globals["csrf_token"] = lambda: "test"
        self.owner = 1

        @self.app.before_request
        def auth():
            g.user = {"id": self.owner}

        self.app.teardown_appcontext(close_db)
        with self.app.app_context():
            d = get_db()
            d.executescript(
                "CREATE TABLE users(id INTEGER PRIMARY KEY); INSERT INTO users VALUES(1),(2);"
            )
            threats.init_db(d)
        self.client = self.app.test_client()

    def test_wizard_and_documents(self):
        self.assertEqual(self.client.get("/threats/").status_code, 200)
        uploaded = workbook(SAMPLE)
        self.assertEqual(
            self.client.post("/threats/new", data={"sheet": (uploaded, "анкета.xlsx")}).status_code, 302
        )
        base = "/threats/1/"
        self.assertEqual(self.client.get(base + "11").location, base + "1")
        rev = 1
        stages = {
            1: {
                "systemType": SAMPLE["systemType"],
                "systemNetworkCondition": SAMPLE["systemNetworkCondition"],
                "objectType": "ispdn",
            },
            2: {
                k: SAMPLE[k]
                for k in (
                    "infosystemFullName",
                    "infosystemShortName",
                    "operatorFullName",
                    "operatorShortName",
                    "operatorLegalAddress",
                )
            },
            3: {"dataCategory_other": "on", "subjectType": "employee"},
            7: {"usesAiTechnology": "on", "aiTrainedInHouse": "on", "УБИ.001": "no_consequences"},
            9: {
                **{f"commissionRole_{i}": "member" if i > 1 else "chairman" for i in range(1, 4)},
                **{f"commissionName_{i}": f"Участник {i}" for i in range(1, 4)},
                **{f"commissionPosition_{i}": f"Должность {i}" for i in range(1, 4)},
            },
            10: {"extendedDocumentSet": "on", **{k: "on" for k in OPTIONAL}},
        }
        invalid = self.client.post(base + "1", data={"revision": rev, "action": "next"})
        self.assertEqual(invalid.status_code, 422)
        for n in range(1, 11):
            with self.subTest(step=n):
                self.assertEqual(self.client.get(base + str(n)).status_code, 200)
                r = self.client.post(
                    base + str(n), data={**stages.get(n, {}), "action": "next", "revision": rev}
                )
                self.assertEqual(r.location, base + str(n + 1), r.get_data(as_text=True)[-1000:])
                rev += 1
        self.assertEqual(
            self.client.post(
                base + "1", data={**stages[1], "revision": 1, "action": "save"}
            ).status_code,
            409,
        )
        self.assertEqual(self.client.get(base + "11").status_code, 200)
        self.assertEqual(self.client.post(base + "generate", data={"revision": rev}).status_code, 302)
        with ZipFile(io.BytesIO(self.client.get(base + "documents.zip").data)) as z:
            self.assertEqual(len(z.namelist()), 20)
            docs = [Document(io.BytesIO(z.read(name))) for name in z.namelist()]
            self.assertTrue(all(doc.tables or len(doc.paragraphs) > 6 for doc in docs))
            model = docs[0]
            self.assertIn(CAT["ai"]["developer"]["title"], [p.text for p in model.paragraphs])
            self.assertTrue(any(len(t.rows) == 244 for t in model.tables))
            self.assertTrue(any("УЗ-4" in p.text for p in docs[1].paragraphs))
        self.owner = 2
        for resource in ("1", "11", "documents.zip", "questionnaire.xlsx"):
            self.assertEqual(self.client.get(base + resource).status_code, 404)
        self.assertEqual(self.client.post(base + "delete", data={"revision": rev + 1}).status_code, 404)
        self.owner = 1
        self.assertEqual(self.client.post(base + "delete", data={"revision": rev + 1}).status_code, 302)
        self.assertEqual(self.client.get(base + "11").status_code, 404)


if __name__ == "__main__":
    unittest.main()
