"""Shared SQLite queue for uploaded recordings."""
import json
import time
from pathlib import Path


def init_db(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS transcripts (
            id TEXT PRIMARY KEY,
            owner INTEGER NOT NULL REFERENCES users(id),
            filename TEXT NOT NULL,
            created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M','now')),
            status TEXT NOT NULL DEFAULT 'queued',
            progress INTEGER NOT NULL DEFAULT 0,
            recoveries INTEGER NOT NULL DEFAULT 0,
            seconds INTEGER NOT NULL DEFAULT 0,
            original TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            revision INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS transcripts_owner ON transcripts(owner);
        CREATE INDEX IF NOT EXISTS transcripts_queue ON transcripts(status);
    """)


def source_path(data_dir, job_id):
    return Path(data_dir) / "media" / job_id


def model_status(data_dir):
    try:
        state = json.loads((Path(data_dir) / "asr-status.json").read_text())
        if 0 <= time.time() - state["time"] < 180 and isinstance(state["label"], str):
            return state["label"]
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return "Нет связи с обработчиком. Загрузка в очередь доступна."


def claim(db):
    return db.execute("""
        UPDATE transcripts SET status='running', progress=0, seconds=0, error=''
        WHERE id=(SELECT id FROM transcripts WHERE status='queued' ORDER BY rowid LIMIT 1)
        RETURNING id
    """).fetchone()
