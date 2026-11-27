"""Shared SQLite queue for uploaded recordings."""
import json
import time
from pathlib import Path


RULE_TABLE = """CREATE TABLE {table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL DEFAULT 'transcription' CHECK(kind IN ('transcription','redaction')),
            input_resource INTEGER NOT NULL REFERENCES watch_resources(id), input_folder TEXT NOT NULL DEFAULT '',
            output_resource INTEGER REFERENCES watch_resources(id), output_folder TEXT NOT NULL DEFAULT '',
            delete_source INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
            last_scan INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
            CHECK(kind!='redaction' OR delete_source=0),
            UNIQUE(kind,input_resource,input_folder)
        )"""


def migrate_rules(db):
    # SQLite cannot drop the 0.3.0 UNIQUE(input_resource,input_folder) constraint in place.
    # Preserve child rows and the old ID high-water mark across the atomic parent-table swap.
    foreign_keys = db.execute("PRAGMA foreign_keys").fetchone()[0]
    db.execute("PRAGMA foreign_keys=OFF")
    try:
        with db:
            db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in db.execute("PRAGMA table_info(watch_rules)")}
            if not columns:
                db.execute(RULE_TABLE.format(table="watch_rules"))
            elif "kind" not in columns:
                ident = db.execute("SELECT seq FROM sqlite_sequence WHERE name='watch_rules'").fetchone()
                db.execute(RULE_TABLE.format(table="watch_rules_new"))
                fields = "id,name,input_resource,input_folder,output_resource,output_folder,delete_source,enabled,last_scan,error"
                db.execute(f"INSERT INTO watch_rules_new ({fields}) SELECT {fields} FROM watch_rules")
                db.execute("DROP TABLE watch_rules")
                db.execute("ALTER TABLE watch_rules_new RENAME TO watch_rules")
                if ident:
                    db.execute("UPDATE sqlite_sequence SET seq=? WHERE name='watch_rules'", (ident[0],))
            file_columns = {row[1] for row in db.execute("PRAGMA table_info(watch_files)")}
            if "publish_intent" not in file_columns:
                db.execute("ALTER TABLE watch_files ADD COLUMN publish_intent INTEGER NOT NULL DEFAULT 0")
            if "processing_note" not in file_columns:
                db.execute("ALTER TABLE watch_files ADD COLUMN processing_note TEXT NOT NULL DEFAULT ''")
            if "recoveries" not in file_columns:
                db.execute("ALTER TABLE watch_files ADD COLUMN recoveries INTEGER NOT NULL DEFAULT 0")
            if "redaction_revision" not in file_columns:
                db.execute("ALTER TABLE watch_files ADD COLUMN redaction_revision INTEGER NOT NULL DEFAULT 0")
                # Existing TXT files may still contain fields missed by the 0.4 rules.
                db.execute("""UPDATE watch_files SET state='settling',seen_since=unixepoch(),result_stamp='',
                              retry_at=0,recoveries=0,publish_intent=0,error=''
                              WHERE rule_id IN (SELECT id FROM watch_rules WHERE kind='redaction')""")
            transcript_columns = {row[1] for row in db.execute("PRAGMA table_info(transcripts)")}
            for name in ("accepted_at", "started_at", "recognizing_at", "finished_at"):
                if name not in transcript_columns:
                    db.execute(f"ALTER TABLE transcripts ADD COLUMN {name} INTEGER")
    finally:
        db.execute("PRAGMA foreign_keys=" + ("ON" if foreign_keys else "OFF"))


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
            accepted_at INTEGER, started_at INTEGER, recognizing_at INTEGER, finished_at INTEGER,
            original TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            revision INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS transcripts_owner ON transcripts(owner);
        CREATE INDEX IF NOT EXISTS transcripts_recent ON transcripts(owner,created DESC,id DESC);
        CREATE INDEX IF NOT EXISTS transcripts_queue ON transcripts(status);
        CREATE TABLE IF NOT EXISTS watch_resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('local','smb')), path TEXT NOT NULL DEFAULT '',
            server TEXT NOT NULL DEFAULT '', share TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 445,
            domain TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', password TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS watch_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER NOT NULL REFERENCES watch_rules(id) ON DELETE CASCADE,
            name TEXT NOT NULL, stamp TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'settling',
            seen_since INTEGER NOT NULL, updated INTEGER NOT NULL, retry_at INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT '', output_name TEXT NOT NULL, output_key TEXT NOT NULL UNIQUE,
            source_sha TEXT NOT NULL DEFAULT '', timed_text TEXT NOT NULL DEFAULT '', result_stamp TEXT NOT NULL DEFAULT '',
            published_sha TEXT NOT NULL DEFAULT '', output_stamp TEXT NOT NULL DEFAULT '',
            replaced INTEGER NOT NULL DEFAULT 0, remove_after INTEGER NOT NULL DEFAULT 0,
            fallback_sha TEXT NOT NULL DEFAULT '', publish_intent INTEGER NOT NULL DEFAULT 0,
            processing_note TEXT NOT NULL DEFAULT '', recoveries INTEGER NOT NULL DEFAULT 0,
            UNIQUE(rule_id,name)
        );
        CREATE INDEX IF NOT EXISTS watch_files_queue ON watch_files(state,retry_at,updated);
        CREATE INDEX IF NOT EXISTS watch_files_recent ON watch_files(rule_id,updated DESC,id DESC);
        CREATE INDEX IF NOT EXISTS watch_files_open ON watch_files(rule_id,state,error)
            WHERE state IN ('settling','queued','running','publishing','failed','conflict','missing');
        CREATE INDEX IF NOT EXISTS watch_content ON watch_files(source_sha) WHERE source_sha!='';
    """)
    migrate_rules(db)


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
    if not db.execute("SELECT 1 FROM transcripts WHERE status='queued' LIMIT 1").fetchone():
        return None
    return db.execute("""
        UPDATE transcripts SET status='running', progress=0, seconds=0, error='',
            started_at=unixepoch(),recognizing_at=NULL,finished_at=NULL
        WHERE id=(SELECT id FROM transcripts WHERE status='queued' ORDER BY rowid LIMIT 1)
        RETURNING id
    """).fetchone()
