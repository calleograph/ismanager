"""User-scoped redaction. Only the result and aggregate counts enter the database."""
import json
import re
import secrets
import tempfile

from flask import Blueprint, Response, abort, g, redirect, render_template, request, url_for

from . import redaction_batch
from .db import get_db
from .privacy.engine import CATEGORIES, PrivacyError
from .privacy.export import MIMES, export
from .privacy.files import MAX_BYTES, SUPPORTED, extract_isolated
from .privacy.names import NlpUnavailable
from .privacy.processing import GROUPS, PROFILES, analyze

bp = Blueprint("redaction", __name__, url_prefix="/redaction")
redaction_batch.register(bp)


def init_db(db):
    redaction_batch.init_db(db)
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


def page(*, original="", record=None, error="", status=200, preview=False):
    rows = get_db().execute("SELECT id,created,profile FROM redactions WHERE user_id=? ORDER BY id DESC",
                            (g.user["id"],)).fetchall()
    batches = redaction_batch.history(get_db(), g.user["id"], request.args.get("before_batch",type=int))
    return render_template("redaction/index.html", rows=rows, batches=batches[:20], more_batches=len(batches)>20, batch_limit=redaction_batch.BATCH_MAX_BYTES, record=record, original=original,
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
    table_secrets = 0
    try:
        if upload and upload.filename:
            if source.strip():
                raise ValueError("Используйте один источник за раз — текстовое поле или файл.")
            ext = upload.filename.rsplit(".", 1)[-1].lower()
            if ext not in SUPPORTED:
                raise ValueError("Формат файла не поддерживается.")
            with tempfile.NamedTemporaryFile(prefix="ismanager-upload-") as local:
                upload.save(local)
                local.flush()
                source, note, table_secrets = extract_isolated(local.name, ext, batch=False, with_counts=True)
        profile = request.form.get("profile", "faceless")
        groups = request.form.getlist("groups") if request.form.get("groups_shown") else None
        result = analyze(source, profile, request.form.get("glossary", ""), groups)
        result.field_secret_count += table_secrets
    except TimeoutError:
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
