import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import asr_store, folder_watch as watch, watch_storage, worker


class FolderWatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.data = Path(temporary.name)
        self.root = self.data / "shares"
        self.source = self.root / "Вход"
        self.source.mkdir(parents=True)
        self.output = self.source / watch.DEFAULT_FOLDER
        self.db = watch.connect(self.data / "queue.db")
        self.addCleanup(self.db.close)
        asr_store.init_db(self.db)
        with self.db:
            self.db.execute("INSERT INTO watch_resources(name,kind,path) VALUES ('Обмен','local','Вход')")
            self.db.execute("INSERT INTO watch_rules(name,input_resource) VALUES ('Правило',1)")
        self.clock = 100
        self.recording = self.source / "Запись.wav"
        self.txt = self.output / "Запись.txt"
        self.transcribed = []

    def fake_asr(self, path, engine, progress, *, timed):
        self.assertTrue(timed)
        words = path.read_text()
        self.transcribed.append(words)
        return "[00:00:01.250 – 00:00:02.300] " + words + "\n"

    def scan(self, seconds=15):
        self.clock += seconds
        watch.scan_once(self.db, "", self.root, now=self.clock)

    def remove_option(self, on):
        with self.db:
            self.db.execute("UPDATE watch_rules SET delete_source=?", (on,))

    def step(self, transcribe=None):
        with patch.object(worker, "transcribe", side_effect=transcribe or self.fake_asr):
            return watch.work(self.db, self.data, None, "", self.root, now=self.clock)

    def drain(self):
        for _ in range(20):
            if not self.step():
                return
        self.fail("Worker did not empty the ready queue")

    def item(self):
        return self.db.execute("SELECT * FROM watch_files ORDER BY id LIMIT 1").fetchone()

    def test_waits_for_stability_skips_duplicates_and_reuses_identical_audio(self):
        self.recording.write_text("первая")
        self.scan()
        self.recording.write_text("новая")
        self.scan()
        self.assertFalse(self.step())
        self.assertEqual(self.item()["state"], "settling")
        self.scan()
        self.drain()
        os.utime(self.recording, ns=(800000000, 800000000))
        self.scan()
        self.scan()
        self.drain()
        self.assertEqual(self.transcribed, ["новая"])
        self.assertFalse((self.data / "watch-source.tmp").exists())
        self.assertEqual(self.item()["state"], "done")
        self.scan()
        self.assertFalse(self.step())

    def test_new_version_replaces_own_txt_and_conflict_preserves_foreign_edit(self):
        self.recording.write_text("один")
        self.scan()
        self.scan()
        self.drain()
        self.recording.write_text("два")
        self.scan()
        self.scan()
        self.drain()
        self.assertIn("два", self.txt.read_text())
        self.txt.write_text("Ручная редакция")
        self.scan()
        self.assertEqual(self.item()["state"], "conflict")
        self.recording.write_text("три")
        self.scan()
        self.scan()
        self.drain()
        self.assertEqual(self.txt.read_text(), "Ручная редакция")
        self.assertIn("три", (self.output / self.item()["output_name"]).read_text())
        self.assertEqual(self.transcribed, ["один", "два", "три"])

    def test_foreign_txt_skipped_without_source_deletion_and_missing_triggers_asr(self):
        self.remove_option(True)
        self.output.mkdir()
        self.txt.write_text("Проверен редактором")
        self.recording.write_text("запись")
        self.scan()
        self.scan()
        self.drain()
        self.assertEqual(self.item()["state"], "existing")
        self.assertEqual(self.transcribed, [])
        self.assertTrue(self.recording.exists())
        self.txt.unlink()
        self.scan()
        self.drain()
        self.assertEqual(self.transcribed, ["запись"])
        self.assertIn("запись", self.txt.read_text())
        self.assertFalse(self.recording.exists())

    def test_empty_placeholder_and_truncation_are_repaired_without_late_deletion(self):
        self.output.mkdir()
        self.txt.touch()
        self.recording.write_text("речь")
        self.scan()
        self.scan()
        self.drain()
        original = self.txt.read_bytes()
        self.assertIn("речь", original.decode())
        self.remove_option(True)
        self.scan()
        self.drain()
        self.assertTrue(self.recording.exists())
        self.txt.write_bytes(b"")
        self.scan()
        self.drain()
        self.assertEqual(self.txt.read_bytes(), original)
        self.assertTrue(self.recording.exists())
        self.assertEqual(self.transcribed, ["речь"])

    def test_deleted_source_and_missing_result_recovered_across_restart(self):
        self.remove_option(True)
        self.recording.write_text("источник")
        self.scan()
        self.scan()
        self.drain()
        self.assertFalse(self.recording.exists())
        result = self.txt.read_bytes()
        self.txt.unlink()
        self.scan()
        assert self.item()["state"] == "publishing"
        (self.data / "watch-source.tmp").write_bytes(b"orphan")
        watch.recover(self.db, self.data)
        self.drain()
        self.assertEqual(self.txt.read_bytes(), result)
        self.assertFalse((self.data / "watch-source.tmp").exists())
        self.assertEqual(self.transcribed, ["источник"])

    def test_source_replaced_during_inference_is_neither_published_nor_deleted(self):
        self.remove_option(True)
        self.recording.write_text("первый")
        self.scan()
        self.scan()

        def replacement(*args, **kwargs):
            self.recording.write_text("новый источник")
            return self.fake_asr(*args, **kwargs)

        self.assertTrue(self.step(replacement))
        self.drain()
        self.assertFalse(self.txt.exists())
        self.assertEqual(self.recording.read_text(), "новый источник")
        self.scan()
        self.scan()
        self.drain()
        self.assertIn("новый источник", self.txt.read_text())
        self.assertFalse(self.recording.exists())

    def test_smb_style_lost_ack_retries_publication_and_keeps_upload_queue_separate(self):
        self.remove_option(True)
        self.recording.write_text("голос")
        self.scan()
        self.scan()
        self.step()
        publish = watch_storage.Directory.publish_text

        def disconnected(store, *args, **kwargs):
            publish(store, *args, **kwargs)
            raise ConnectionResetError("lost acknowledgement")

        with patch.object(watch_storage.Directory, "publish_text", disconnected):
            self.step()
        self.assertEqual(self.item()["state"], "publishing")
        self.assertTrue(self.txt.exists())
        self.assertTrue(self.recording.exists())
        self.assertFalse(self.step())
        self.clock += watch.RETRY_DELAY
        self.drain()
        self.assertFalse(self.recording.exists())
        self.assertEqual(self.transcribed, ["голос"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM transcripts").fetchone()[0], 0)

    def test_safe_deletion_unavailable_keeps_published_result_without_repeating_asr(self):
        self.remove_option(True)
        self.recording.write_text("запись")
        self.scan()
        self.scan()
        self.step()
        with patch.object(watch_storage.Directory, "delete_source", side_effect=watch_storage.SourceRetainedError):
            self.step()
        self.assertEqual(self.item()["state"], "done")
        self.assertIn("TXT сохранён", self.item()["error"])
        self.assertTrue(self.txt.exists() and self.recording.exists())
        self.scan()
        self.assertFalse(self.step())

    def test_output_override_same_stem_and_disable_pending_deletion(self):
        target = self.root / "Архив"
        target.mkdir()
        self.remove_option(True)
        with self.db:
            self.db.execute("INSERT INTO watch_resources(name,kind,path) VALUES ('Вывод','local','Архив')")
            self.db.execute("UPDATE watch_rules SET output_resource=2,output_folder='Результаты'")
        self.recording.write_text("один")
        (self.source / "Запись.mp3").write_text("два")
        self.scan()
        self.scan()
        self.assertTrue(self.step())
        self.remove_option(False)
        self.drain()
        outcomes = [p.read_text() for p in (target / "Результаты").glob("*.txt")]
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(any("один" in result for result in outcomes))
        self.assertTrue(any("два" in result for result in outcomes))
        self.assertTrue(self.recording.exists())
        self.assertTrue((self.source / "Запись.mp3").exists())

    def test_two_resource_names_addressing_one_output_reserve_distinct_slots(self):
        (self.root / "Архив").mkdir()
        (self.source / "Второй").mkdir()
        self.recording.write_text("один")
        (self.source / "Второй" / self.recording.name).write_text("два")
        with self.db:
            self.db.execute("INSERT INTO watch_resources(name,kind,path) VALUES ('Архив','local','Архив')")
            self.db.execute("INSERT INTO watch_resources(name,kind,path) VALUES ('Корень','local','')")
            self.db.execute("UPDATE watch_rules SET output_resource=2")
            self.db.execute("""INSERT INTO watch_rules(name,input_resource,input_folder,output_resource,output_folder)
                               VALUES ('Вторая папка',1,'Второй',3,'Архив')""")
        self.scan()
        self.scan()
        self.drain()
        self.assertEqual(len(list((self.root / "Архив").glob("*.txt"))), 2)
        self.assertEqual(set(self.transcribed), {"один", "два"})

    def test_external_symlink_does_not_block_other_missing_texts(self):
        self.recording.write_text("первый")
        (self.source / "Я.wav").write_text("второй")
        self.scan()
        self.scan()
        self.drain()
        external = self.data / "личный.txt"
        external.write_text("чужой")
        self.txt.unlink()
        self.txt.symlink_to(external)
        other = self.output / "Я.txt"
        other.unlink()
        self.scan()
        self.drain()
        self.assertTrue(self.txt.is_symlink())
        self.assertEqual(external.read_text(), "чужой")
        self.assertIn("второй", other.read_text())
        self.assertEqual(self.item()["state"], "conflict")

    def test_identical_copies_use_one_inference_after_authorized_read(self):
        (self.source / "Другая.wav").write_text("тот же файл")
        self.recording.write_text("тот же файл")
        self.scan()
        self.scan()
        self.drain()
        self.assertEqual(self.transcribed, ["тот же файл"])
        self.assertEqual(self.txt.read_bytes(), (self.output / "Другая.txt").read_bytes())
        (self.source / "Закрытая.wav").write_text("тот же файл")
        self.scan()
        self.scan()
        with patch.object(watch_storage.Directory, "copy_source", side_effect=PermissionError):
            self.assertTrue(self.step())
        self.assertFalse((self.output / "Закрытая.txt").exists())

    def test_disabled_rule_cannot_publish_and_recovery_requeues_only_its_active_job(self):
        self.recording.write_text("тихо")
        self.scan()
        self.scan()
        with self.db:
            self.db.execute("UPDATE watch_files SET state='running'")
        watch.recover(self.db, self.data)
        self.assertEqual(self.item()["state"], "queued")
        self.step()
        with self.db:
            self.db.execute("UPDATE watch_rules SET enabled=0")
        self.assertFalse(self.step())
        self.assertFalse(self.txt.exists())
        with self.db:
            self.db.execute("UPDATE watch_rules SET enabled=1")
        self.drain()
        self.assertIn("тихо", self.txt.read_text())

    def test_existing_media_error_does_not_spin_and_new_version_recovers(self):
        self.recording.write_text("сломана")
        self.scan()
        self.scan()
        self.step(lambda *args, **kwargs: (_ for _ in ()).throw(worker.RecordingError("Нет дорожки.")))
        self.scan()
        self.assertFalse(self.step())
        self.assertEqual(self.item()["error"], "Нет дорожки.")
        self.recording.write_text("исправлена")
        self.scan()
        self.scan()
        self.drain()
        self.assertIn("исправлена", self.txt.read_text())

    def test_large_directory_releases_writer_between_batches(self):
        rule = watch.current_rule(self.db, 1)
        snapshots = [watch_storage.Snapshot(f"{i}.ogg", 42, 10, str(i)) for i in range(400)]
        inserted = []
        in_transaction = 0

        def trace(sql):
            nonlocal in_transaction
            if sql.startswith("INSERT INTO watch_files"):
                in_transaction += 1
            elif sql == "COMMIT":
                inserted.append(in_transaction)
                in_transaction = 0

        self.db.set_trace_callback(trace)
        watch.observe(self.db, rule, snapshots, self.clock, watch.INTERVAL)
        self.db.set_trace_callback(None)
        self.assertEqual(sum(inserted), 400)
        self.assertLess(max(inserted), 400)
