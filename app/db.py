"""Shared database and account state."""
import sqlite3

from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=20)
        g.db.row_factory = sqlite3.Row
        # SQLite NOCASE only covers ASCII. Directory names and audit searches may be Cyrillic.
        g.db.create_function("casefold", 1, str.casefold, deterministic=True)
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db):
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, identity TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL, display_name TEXT NOT NULL, admin INTEGER NOT NULL,
            password TEXT, must_change INTEGER NOT NULL DEFAULT 0,
            totp TEXT, last_step INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            expires INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id,expires);
        CREATE TABLE IF NOT EXISTS attempts (
            key TEXT PRIMARY KEY, count INTEGER NOT NULL, until INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS directories (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
            config TEXT NOT NULL, password TEXT NOT NULL, enabled INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_settings (
            id INTEGER PRIMARY KEY CHECK(id=1), hours INTEGER NOT NULL,
            attempts_user INTEGER NOT NULL, attempts_ip INTEGER NOT NULL, minutes INTEGER NOT NULL,
            admin_totp INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO auth_settings VALUES(1,12,12,80,5,0);
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            actor INTEGER, event TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_event ON audit(event);
    """)

    # Gunicorn workers may open an existing database concurrently after an update.
    with db:
        db.execute("BEGIN IMMEDIATE")
        if "disabled" not in {col[1] for col in db.execute("PRAGMA table_info(users)")}:
            db.execute("ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")
        if "target_user" not in {col[1] for col in db.execute("PRAGMA table_info(audit)")}:
            db.execute("ALTER TABLE audit ADD COLUMN target_user INTEGER REFERENCES users(id)")
        db.execute("CREATE INDEX IF NOT EXISTS audit_actor ON audit(actor) WHERE actor IS NOT NULL")
        db.execute("CREATE INDEX IF NOT EXISTS audit_target ON audit(target_user) WHERE target_user IS NOT NULL")
        db.execute("CREATE INDEX IF NOT EXISTS users_admin_list ON users(id,identity) WHERE identity NOT LIKE 'guest:%'")


def audit(event, actor=None, *, target=None):
    db = get_db()
    db.execute("INSERT INTO audit(actor,event,target_user) VALUES (?,?,?)", (actor, event, target))


def auth_settings():
    if "auth_settings" not in g:
        g.auth_settings = get_db().execute("SELECT * FROM auth_settings WHERE id=1").fetchone()
    return g.auth_settings
