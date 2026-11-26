"""User-scoped redaction. Only the result and aggregate counts enter the database."""
import json
import os
import re
import secrets
import tempfile
import subprocess
import sys

from flask import Blueprint, Response, abort, g, redirect, render_template, request, url_for

from .db import get_db
from .privacy.export import MIMES, export
from .privacy.engine import Anonymizer, CATEGORIES, Policy, PrivacyError, Term
from .privacy.files import MAX_BYTES, MAX_TEXT, SUPPORTED
from .privacy.names import NlpUnavailable
from .privacy.verify import independent_check

bp = Blueprint("redaction", __name__, url_prefix="/redaction")
PROFILES = {"faceless": "Полный · Faceless", "strict": "Строгий · Переговорка", "basic": "Базовый · Переговорка"}


def init_db(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS redactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, profile TEXT NOT NULL, result TEXT NOT NULL,
            stats TEXT NOT NULL, notes TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS redaction_owner ON redactions(user_id, id);
        CREATE TABLE IF NOT EXISTS redaction_requests (
            user_id INTEGER NOT NULL, nonce TEXT NOT NULL,
            record_id INTEGER NOT NULL REFERENCES redactions(id) ON DELETE CASCADE, PRIMARY KEY(user_id,nonce)
        );
    """)


GROUPS = {
    "personal": ("Люди, контакты и документы", ("person", "location", "address", "phone", "email", "id_number", "health", "bank")),
    "business": ("Организации и коммерческие сведения", ("organization", "doc_number", "money", "marker", "project")),
    "network": ("Учётные записи и инфраструктура", ("ip", "host", "url", "login")),
}


def analyze(source, profile, glossary="", groups=None):
    if profile not in PROFILES:
        raise ValueError("Выберите профиль обработки.")
    if not source.strip() or len(source) > MAX_TEXT:
        raise ValueError("Требуется от 1 до 60 000 знаков исходного текста.")
    words = [s.strip() for s in glossary.splitlines() if s.strip()]
    if len(words) > 48 or any(len(w) > 96 or w.startswith("re:") for w in words):
        raise ValueError("Допустимо до 48 буквальных терминов длиной до 96 знаков.")
    policy = Policy.from_profile("strict" if profile == "faceless" else profile,
                                 use_faceless=profile == "faceless", terms=[Term(w) for w in words])
    if groups is not None:
        if set(groups) - GROUPS.keys():
            raise ValueError("Неизвестная группа данных.")
        for key, (_, categories) in GROUPS.items():
            if key not in groups:
                policy.actions.update(dict.fromkeys(categories, "keep"))
    engine = Anonymizer(policy)
    result = engine.process(source)
    if independent_check(result.text, policy):
        again = engine.process(result.text)
        if independent_check(again.text, policy):
            raise PrivacyError("verification_failed", "Повторная проверка обнаружила остаточные данные. Выдача результата остановлена.")
        result.text = again.text
        result.replacements.extend(again.replacements)
        result.warnings.extend(again.warnings + ["Проведён дополнительный проход."])
    return result


def page(*, original="", record=None, error="", status=200, preview=False):
    rows = get_db().execute("SELECT id,created,profile FROM redactions WHERE user_id=? ORDER BY id DESC",
                            (g.user["id"],)).fetchall()
    return render_template("redaction/index.html", rows=rows, record=record, original=original,
                           error=error, profiles=PROFILES, formats=SUPPORTED, categories=CATEGORIES, groups=GROUPS, preview=preview, nonce=secrets.token_hex(16)), status


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return page()
    if request.content_length is None or request.content_length > MAX_BYTES + 300_000:
        return page(error="Максимальный размер файла — 12 МиБ.", status=413)
    owner = g.user["id"]
    db = get_db()
    nonce = request.form.get("nonce")
    if nonce and not re.fullmatch("[0-9a-f]{32}", nonce):
        abort(400)
    def previous():
        return db.execute("SELECT record_id FROM redaction_requests WHERE user_id=? AND nonce=?", (owner, nonce)).fetchone()
    if nonce and not request.form.get("preview") and (record := previous()):
        return redirect(url_for("redaction.show", record_id=record["record_id"]))
    source = request.form.get("text", "")
    upload = request.files.get("file")
    note = ""
    try:
        if upload and upload.filename:
            if source.strip():
                raise ValueError("Используйте один источник за раз — текстовое поле или файл.")
            ext = upload.filename.rsplit(".", 1)[-1].lower()
            raw = upload.stream.read(MAX_BYTES+1)
            if ext not in SUPPORTED or len(raw) > MAX_BYTES:
                raise ValueError("Проверьте формат и размер файла (до 12 МиБ).")
            with tempfile.TemporaryDirectory(prefix="ismanager-extract-") as staging:
                proc = subprocess.run([sys.executable, "-m", "app.privacy.files", ext],
                                      input=raw, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      env=dict(os.environ, TMPDIR=staging), timeout=63)
            if proc.returncode:
                raise ValueError("Файл превысил пределы обработки.")
            decoded = json.loads(proc.stdout)
            if "error" in decoded:
                raise ValueError(decoded["error"])
            source, note = decoded["text"], decoded["note"]
        profile = request.form.get("profile", "faceless")
        groups = request.form.getlist("groups") if request.form.get("groups_shown") else None
        result = analyze(source, profile, request.form.get("glossary", ""), groups)
    except (TimeoutError, subprocess.TimeoutExpired):
        return page(error="Обработка превысила время ожидания. Разделите материал на части.", status=422)
    except (PrivacyError, NlpUnavailable):
        return page(error="Не удалось подтвердить обезличивание. Проверьте доступность моделей и формат текста.", status=422)
    except ValueError as exc:
        return page(error=str(exc), status=422)
    notes = ([note] if note else []) + result.warnings
    if request.form.get("preview"):
        return page(original=source, record={"profile": profile, "stats": result.stats(), "notes": notes,
                                            "result": result.text}, preview=True)
    with db:
        db.execute("BEGIN IMMEDIATE")
        if nonce and (record := previous()):
            return redirect(url_for("redaction.show", record_id=record["record_id"]))
        row = db.execute("INSERT INTO redactions (user_id,profile,result,stats,notes) VALUES (?,?,?,?,?)",
                         (g.user["id"], profile, result.text, json.dumps(result.stats()), json.dumps(notes)))
        if nonce:
            db.execute("INSERT INTO redaction_requests VALUES (?,?,?)", (owner, nonce, row.lastrowid))
    return page(original=source, record=load_record(row.lastrowid))


def load_record(record_id):
    row = get_db().execute("SELECT * FROM redactions WHERE id=? AND user_id=?", (record_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    return dict(row, stats=json.loads(row["stats"]), notes=json.loads(row["notes"]))


@bp.get("/<int:record_id>")
def show(record_id):
    return page(record=load_record(record_id))


@bp.get("/<int:record_id>/download")
def download(record_id):
    record = load_record(record_id)
    ext = request.args.get("format", "txt")
    if ext == "txt":
        data, mimetype = record["result"], "text/plain"
    elif ext in MIMES:
        try:
            data, mimetype = export(ext, record["result"]), MIMES[ext]
        except ValueError as exc:
            abort(422, description=str(exc))
    else:
        abort(404)
    return Response(data, mimetype=mimetype,
                    headers={"Content-Disposition": f"attachment; filename=redacted-{record_id}.{ext}"})


@bp.post("/<int:record_id>/delete")
def delete(record_id):
    db = get_db()
    with db:
        row = db.execute("DELETE FROM redactions WHERE id=? AND user_id=?", (record_id, g.user["id"]))
        if not row.rowcount:
            abort(404)
    return redirect(url_for("redaction.index"))
