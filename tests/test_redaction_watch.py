from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Barrier
from unittest.mock import patch

import pytest

from app import asr_store, folder_watch as watch, watch_storage
from app.privacy import processing


@pytest.fixture
def queue(tmp_path):
    source = tmp_path / "watch"
    source.mkdir()
    with closing(watch.connect(tmp_path / "state.db")) as db:
        asr_store.init_db(db)
        with db:
            db.execute("INSERT INTO watch_resources(name,kind) VALUES ('Документы','local')")
            db.execute("INSERT INTO watch_rules(name,kind,input_resource) VALUES ('Архив','redaction',1)")
        yield db, source
        private = watch.scratch_path(tmp_path, "redaction").parent
        private.rmdir()


def discover(db, source, kind="redaction", now=100):
    for t in (now, now + 15):
        watch.scan_once(db, "", source, kind=kind, now=t)


def step(db, source, kind="redaction", now=116):
    return watch.work(db, source.parent, None, "", source, kind=kind, now=now)


def drain(db, source, kind="redaction", now=116):
    for _ in range(25):
        if not step(db, source, kind, now):
            return
    pytest.fail("Очередь активных заданий не опустела")


def item(db, name, kind="redaction"):
    return db.execute("""SELECT f.* FROM watch_files f JOIN watch_rules r ON f.rule_id=r.id
                         WHERE f.name=? AND r.kind=?""", (name, kind)).fetchone()


def test_redaction_validates_foreign_txt_and_finds_opaque_name(queue):
    db, source = queue
    name = "Иван Петров - обращение.txt"
    (source / name).write_text("исходный секрет")
    discover(db, source)
    output = source / watch.REDACTION_FOLDER
    output.mkdir()
    planned = output / item(db, name)["output_name"]
    planned.write_text("чужой черновик")
    note = "Использован OCR. Проверьте имена и цифры."
    with patch.object(processing, "redact_file", return_value=("проверено", {}, [note, "личное значение"])) as redact:
        drain(db, source)
        row = item(db, name)
        saved = output / row["output_name"]
        assert row["state"] == "done" and saved != planned
        assert row["processing_note"] == note
        assert watch.REDACTED_OUTPUT.fullmatch(saved.name)
        assert planned.read_text() == "чужой черновик" and saved.read_text() == "проверено"
        assert (source / name).read_text() == "исходный секрет"
        assert redact.call_count == 1
        scratch, ext = redact.call_args.args
        assert ext == "txt" and not scratch.is_relative_to(source.parent) and not scratch.exists()
        saved.write_text("правка другого пользователя")
        discover(db, source, now=150)
        drain(db, source, now=166)
        restored = output / item(db, name)["output_name"]
        assert restored != saved and restored.read_text() == "проверено"
        assert saved.read_text() == "правка другого пользователя" and redact.call_count == 1
        restored.unlink()
        discover(db, source, now=200)
        drain(db, source, now=216)
        assert restored.read_text() == "проверено" and redact.call_count == 1


def test_upgrade_rechecks_existing_folders_without_reusing_legacy_text(queue):
    import time

    db, source = queue
    name = "пример.txt"
    (source / name).write_text("контрольный документ")
    discover(db, source)
    with patch.object(processing, "redact_file", return_value=("прежний результат", {}, [])):
        drain(db, source)
    published = source / watch.REDACTION_FOLDER / item(db, name)["output_name"]
    assert published.read_text() == "прежний результат"
    with db:
        db.execute("ALTER TABLE watch_files DROP COLUMN redaction_revision")
    asr_store.init_db(db)
    assert item(db, name)["state"] == "settling"
    now = int(time.time()) + 30
    discover(db, source, now=now)
    with patch.object(processing, "redact_file", return_value=("проверено заново", {}, [])) as redact:
        drain(db, source, now=now + 16)
        assert redact.call_count == 1
    assert published.read_text() == "проверено заново"
    asr_store.init_db(db)
    assert item(db, name)["state"] == "done"


@pytest.mark.parametrize("foreign", ["совпадение", ""])
def test_redaction_never_adopts_existing_txt_on_first_attempt(queue, foreign):
    db, source = queue
    (source / "данные.md").write_text("вход")
    discover(db, source)
    with patch.object(processing, "redact_file", return_value=("совпадение", {}, [])):
        assert step(db, source)
    before = source / watch.REDACTION_FOLDER / item(db, "данные.md")["output_name"]
    before.write_text(foreign)
    drain(db, source)
    after = source / watch.REDACTION_FOLDER / item(db, "данные.md")["output_name"]
    assert after != before and before.read_text() == foreign and after.read_text() == "совпадение"


def test_lost_publication_ack_restores_exact_verified_result(queue):
    db, source = queue
    (source / "данные.md").write_text("вход")
    discover(db, source)
    with patch.object(processing, "redact_file", return_value=("проверено", {}, [])) as redact:
        assert step(db, source)
        publish = watch_storage.Directory.publish_text

        def lost(store, *args, **kwargs):
            publish(store, *args, **kwargs)
            raise ConnectionResetError

        with patch.object(watch_storage.Directory, "publish_text", lost):
            assert step(db, source)
        watch.recover(db, source.parent, kind="redaction")
        drain(db, source, now=166)
        assert redact.call_count == 1
    assert item(db, "данные.md")["state"] == "done"
    assert len(list((source / watch.REDACTION_FOLDER).glob("*.txt"))) == 1


def test_repeated_worker_crash_isolates_document_and_new_version_resets_attempts(queue):
    db, source = queue
    (source / "А.txt").write_text("тяжёлый")
    (source / "Б.txt").write_text("следующий")
    discover(db, source)
    for expected in ("queued", "failed"):
        with db:
            db.execute("UPDATE watch_files SET state='running' WHERE name='А.txt'")
        watch.recover(db, source.parent, kind="redaction")
        assert item(db, "А.txt")["state"] == expected
    assert item(db, "А.txt")["recoveries"] == 2
    with patch.object(processing, "redact_file", return_value=("обработан", {}, [])) as redact:
        drain(db, source)
        assert redact.call_count == 1 and item(db, "Б.txt")["state"] == "done"
        (source / "А.txt").write_text("исправленная версия")
        discover(db, source, now=160)
        drain(db, source, now=176)
        assert item(db, "А.txt")["state"] == "done" and item(db, "А.txt")["recoveries"] == 0


def test_worker_detects_an_input_remounted_as_its_output(queue):
    db, source = queue
    (source / "А.txt").write_text("вход")
    # An administrator can remount configured paths after the web form has been validated.
    with db:
        db.execute("UPDATE watch_rules SET output_resource=input_resource")
    discover(db, source)
    with patch.object(processing, "redact_file") as redact:
        drain(db, source)
        assert not redact.called
    row = item(db, "А.txt")
    assert row["state"] == "failed" and "физический каталог" in row["error"]
    assert not (source / row["output_name"]).exists()


def test_kind_scopes_queue_recovery_cache_and_format(queue):
    db, source = queue
    with db:
        db.execute("INSERT INTO watch_rules(name,input_resource) VALUES ('Речь',1)")
    for name in ("тема.wav", "тема.txt", "копия.txt", "ошибка.pdf"):
        (source / name).write_text("совпадающие байты")
    (source / "ismanager-redacted-1234567890abcdef1234567890abcdef.txt").write_text("ok")
    (source / "ismanager-redacted-1234567890abcdef1234567890abcdef.previous-012345678901-abcdefabcd.txt").write_text("ok")
    discover(db, source)
    assert not step(db, source, "transcription")
    assert db.execute("SELECT count(*) FROM watch_files").fetchone()[0] == 3
    discover(db, source, "transcription")
    with db:
        db.execute("UPDATE watch_files SET state='running'")
    audio_scratch = watch.scratch_path(source.parent, "transcription")
    doc_scratch = watch.scratch_path(source.parent, "redaction")
    audio_scratch.write_text("речь")
    doc_scratch.write_text("документ")
    watch.recover(db, source.parent, kind="transcription")
    assert doc_scratch.exists() and not audio_scratch.exists()
    assert item(db, "тема.txt")["state"] == "running"
    with patch("app.worker.transcribe", return_value="незащищённая стенограмма"):
        drain(db, source, "transcription")
    watch.recover(db, source.parent, kind="redaction")
    assert not doc_scratch.exists()

    def redact(path, ext):
        if ext == "pdf":
            raise ValueError("секретное значение из исключения")
        return "проверенный результат", {}, []

    with patch.object(processing, "redact_file", side_effect=redact) as process:
        drain(db, source)
        assert sorted(call.args[1] for call in process.call_args_list) == ["pdf", "txt"]
    error = item(db, "ошибка.pdf")
    assert error["state"] == "failed" and "секретное значение" not in error["error"]
    good = item(db, "тема.txt")
    output = source / watch.REDACTION_FOLDER
    assert (output / good["output_name"]).read_text() == "проверенный результат"
    assert not (output / error["output_name"]).exists()
    assert (source / watch.DEFAULT_FOLDER / "тема.txt").read_text() == "незащищённая стенограмма"


def test_migrate_old_database_preserves_ids_fk_sequences_and_existing_work(tmp_path):
    # The table definition shipped in 0.3.0 has a single input constraint across all rules.
    database = tmp_path / "0.3.0.db"
    with closing(watch.connect(database)) as db:
        asr_store.init_db(db)
        db.execute("DROP TABLE watch_rules")
        db.execute("ALTER TABLE watch_files DROP COLUMN publish_intent")
        db.execute("ALTER TABLE watch_files DROP COLUMN processing_note")
        db.execute("ALTER TABLE watch_files DROP COLUMN recoveries")
        db.executescript("""
            CREATE TABLE watch_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
                input_resource INTEGER NOT NULL REFERENCES watch_resources(id), input_folder TEXT NOT NULL DEFAULT '',
                output_resource INTEGER REFERENCES watch_resources(id), output_folder TEXT NOT NULL DEFAULT '',
                delete_source INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
                last_scan INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', UNIQUE(input_resource,input_folder));
            INSERT INTO watch_resources(name,kind) VALUES('Папка','local');
            INSERT INTO watch_rules(id,name,input_resource,delete_source,last_scan) VALUES(41,'Заседания',1,1,555);
            INSERT INTO watch_rules(id,name,input_resource,input_folder) VALUES(70,'Удалено',1,'другая');
            DELETE FROM watch_rules WHERE id=70;
            INSERT INTO watch_files(rule_id,name,stamp,state,seen_since,updated,output_key,output_name,timed_text)
                VALUES(41,'файл.ogg','версия','done',42,100,'путь','файл.txt','Проверенная стенограмма.');
        """)
    barrier = Barrier(2)

    def worker_start():
        with closing(watch.connect(database)) as db:
            barrier.wait(timeout=5)
            asr_store.init_db(db)
            assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker_start) for _ in range(2)]
        for f in futures:
            f.result(timeout=15)
    with closing(watch.connect(database)) as db, db:
        row = db.execute("SELECT * FROM watch_rules").fetchone()
        assert (row["kind"], row["id"], row["delete_source"], row["last_scan"]) == ("transcription", 41, 1, 555)
        assert item(db, "файл.ogg", "transcription")["timed_text"] == "Проверенная стенограмма."
        new = db.execute("INSERT INTO watch_rules(name,kind,input_resource) VALUES('Документы','redaction',1)")
        assert new.lastrowid == 71
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE watch_rules SET delete_source=1 WHERE kind='redaction'")
        db.execute("DELETE FROM watch_rules WHERE id=41")
        assert db.execute("SELECT count(*) FROM watch_files").fetchone()[0] == 0


def test_speech_worker_needs_no_privacy_modules(tmp_path):
    python = """
import builtins, sys
from pathlib import Path
original = builtins.__import__
def guard(name, *args, **kwargs):
    if 'privacy' in name or name in {'slovnet','defusedxml','flask'}:
        raise AssertionError(name)
    return original(name, *args, **kwargs)
builtins.__import__ = guard
from app import asr_store, folder_watch
with folder_watch.connect(':memory:') as db:
    asr_store.init_db(db)
    db.execute("INSERT INTO watch_resources(name,kind) VALUES('test','local')")
    db.execute("INSERT INTO watch_rules(name,kind,input_resource) VALUES('doc','redaction',1)")
    db.commit()
    folder_watch.scan_once(db,'')
    folder_watch.recover(db,Path(sys.argv[1]))
    assert not folder_watch.work(db,Path(sys.argv[1]),None,'')
"""
    subprocess.run([sys.executable, "-c", python, str(tmp_path)], check=True)
