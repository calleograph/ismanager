import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask, g
from jinja2 import DictLoader

from app import asr_store, transcription, worker
from app.db import close_db, get_db


class RecordingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.app = Flask(__name__)
        self.app.config.update(DATA_DIR=self.folder, DATABASE=self.folder / "queue.sqlite3",
                               SECRET_KEY="test", TESTING=True)
        self.app.jinja_loader = DictLoader({"base.html": "{% block content %}{% endblock %}"})
        self.app.jinja_env.globals["csrf_token"] = lambda: "test"
        self.app.register_blueprint(transcription.bp)
        # The production package supplies the templates and global authentication.
        from jinja2 import ChoiceLoader, FileSystemLoader
        self.app.jinja_loader = ChoiceLoader([self.app.jinja_loader,
            FileSystemLoader(Path(transcription.__file__).parent / "templates")])
        self.app.teardown_appcontext(close_db)
        self.owner = 1

        @self.app.before_request
        def identify():
            g.user = {"id": self.owner}

        with self.app.app_context():
            db = get_db()
            db.executescript("CREATE TABLE users (id INTEGER PRIMARY KEY); INSERT INTO users VALUES (1),(2);")
            asr_store.init_db(db)
        self.db = sqlite3.connect(self.app.config["DATABASE"])
        self.addCleanup(self.db.close)
        self.client = self.app.test_client()

    def upload(self, content=b"synthetic recording"):
        response = self.client.post("/transcription/", data={"media": (io.BytesIO(content), "../../sample.wav")})
        self.assertEqual(response.status_code, 302)
        return response.location

    def test_owner_retry_save_conflict_export_delete(self):
        page = self.upload()
        job_id = page.rsplit("/", 1)[1]
        self.assertTrue(asr_store.source_path(self.folder, job_id).exists())
        self.assertIn("sample.wav", self.client.get(page).get_data(as_text=True))
        self.owner = 2
        for verb, path in (("get", ""), ("get", "/export"), ("post", "/retry"), ("post", "/delete"), ("post", "/save")):
            self.assertEqual(getattr(self.client, verb)(page + path).status_code, 404)
        self.owner = 1
        with patch.object(worker, "transcribe", side_effect=worker.RecordingError("Ошибка записи")):
            self.assertTrue(worker.work(self.db, self.folder, None))
        self.assertIn("Ошибка записи", self.client.get(page).get_data(as_text=True))
        self.assertEqual(self.client.post(page + "/retry").status_code, 302)
        with patch.object(worker, "transcribe", return_value="Исходный текст."):
            self.assertTrue(worker.work(self.db, self.folder, None))
        save_data = {"revision": "0", "body": "Правка."}
        self.assertEqual(self.client.post(page + "/save", data=save_data).status_code, 302)
        self.assertEqual(self.client.post(page + "/save", data=save_data).status_code, 409)
        self.assertEqual(self.client.get(page + "/export").get_data(as_text=True), "Правка.\n")
        self.assertIn("Исходный текст.", self.client.get(page).get_data(as_text=True))
        self.assertEqual(self.client.post(page + "/delete").status_code, 302)
        self.assertFalse(asr_store.source_path(self.folder, job_id).exists())

    def test_zero_byte_upload_and_size_limit(self):
        self.upload(b"")
        self.assertIsNone(self.db.execute("SELECT id FROM transcripts").fetchone())
        with patch.object(transcription, "MAX_UPLOAD", 5):
            response = self.client.post("/transcription/", data={"media": (io.BytesIO(b"oversize"), "f")})
        self.assertEqual(response.status_code, 413)
        self.assertFalse(list((self.folder / "media").iterdir()))

    def test_restart_reclaims_once_and_protects_active_recording(self):
        page = self.upload()
        with self.db:
            self.assertIsNotNone(asr_store.claim(self.db))
        self.assertEqual(self.client.post(page + "/delete").status_code, 409)
        worker.recover(self.db)
        self.assertEqual(self.db.execute("SELECT status FROM transcripts").fetchone()[0], "queued")
        with self.db:
            self.assertIsNotNone(asr_store.claim(self.db))
        worker.recover(self.db)
        self.assertEqual(self.db.execute("SELECT status FROM transcripts").fetchone()[0], "failed")
        self.assertEqual(self.client.post(page + "/retry").status_code, 302)
        self.assertEqual(self.db.execute("SELECT recoveries FROM transcripts").fetchone()[0], 0)

    def test_model_cache_accepts_only_pinned_contents(self):
        import hashlib

        digest = hashlib.sha256(b"model").hexdigest()
        with patch.object(worker, "MODEL_FILES", {"weights": digest}):
            (self.folder / "weights").write_bytes(b"corrupt")
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b"broken")):
                with self.assertRaises(ValueError):
                    worker.prepare_models(self.folder, lambda _: None)
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b"model")):
                worker.prepare_models(self.folder, lambda _: None)
            with patch("urllib.request.urlopen", side_effect=AssertionError("network used")):
                worker.prepare_models(self.folder, lambda _: None)

    def test_resumes_partial_model_after_interrupt(self):
        import hashlib

        (self.folder / "weights.part").write_bytes(b"mo")
        response = io.BytesIO(b"del")
        response.status = 206
        with patch.object(worker, "MODEL_FILES", {"weights": hashlib.sha256(b"model").hexdigest()}):
            with patch("urllib.request.urlopen", return_value=response) as fetch:
                worker.prepare_models(self.folder, lambda _: None)
        self.assertEqual(fetch.call_args.args[0].get_header("Range"), "bytes=2-")
        self.assertEqual((self.folder / "weights").read_bytes(), b"model")

    def test_probe_invalid_or_no_audio(self):
        import subprocess

        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, b'{"streams":[]}')):
            with self.assertRaisesRegex(worker.RecordingError, "нет звуковой"):
                worker.probe(self.folder / "dummy")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ffprobe", 30)):
            with self.assertRaises(worker.RecordingError):
                worker.probe(self.folder / "dummy")


    def test_status_owner_isolated_and_real_milestones(self):
        index = "/transcription/"
        response = self.client.post(index, data={"media": (io.BytesIO(b"audio"), "demo.wav")},
                                     headers={"Accept": "application/json"})
        assert response.status_code == 201
        page = response.json["location"]
        assert self.client.get(page + "/status").json["state"] == "queued"

        def inference(path, engine, progress):
            progress(5, 50)
            state = self.client.get(page + "/status").json
            assert state["state"] == "running" and state["stage"] == "Распознавание русской речи"
            assert state["seconds"] == 5 and state["percent"] == 50
            return "Результат."

        with patch.object(worker, "transcribe", side_effect=inference):
            worker.work(self.db, self.folder, None)
        result = self.client.get(page + "/status").json
        assert result["state"] == "done" and result["percent"] == 100 and len(result["events"]) == 4
        assert "Результат" not in str(result)
        self.owner = 2
        assert self.client.get(page + "/status").status_code == 404


if __name__ == "__main__":
    unittest.main()
