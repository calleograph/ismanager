"""User-scoped redaction. Only the result and aggregate counts enter the database."""
import hashlib
import json
import re
import secrets
import tempfile

from flask import Blueprint, Response, abort, current_app, g, redirect, render_template, request, session, url_for

from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import redaction_batch
from .db import get_db
from .personal_history import history_page
from .privacy.engine import CATEGORIES, PrivacyError
from .privacy.export import MIMES, export
from .privacy.files import BATCH_MAX_BYTES, MAX_TEXT, SUPPORTED, extract_isolated
from .privacy.names import NlpUnavailable
from .privacy.processing import EMPTY_SOURCE, GROUPS, LONG_SOURCE, PROFILES, SettingsError, analyze, analyze_document, policy_for

bp = Blueprint("redaction", __name__, url_prefix="/redaction")
redaction_batch.register(bp)

INPUT_HINTS = {
    "empty": EMPTY_SOURCE, "long": LONG_SOURCE,
    "conflict": "Чтобы обезличить файлы, очистите поле «Исходный текст». Чтобы обработать текст, снимите выбор файлов.",
    "format": "Этот формат не поддерживается. Сохраните документ в TXT, DOCX или PDF и выберите его снова.",
    "empty_file": "Выбранный файл пуст. Выберите документ с текстом или сканом.",
    "large_file": "Файл больше 64 МиБ. Разделите его на части размером до 64 МиБ.",
    "multiple_preview": "Предпросмотр доступен для текста или одного файла. Оставьте один файл либо нажмите «Обезличить и сохранить».",
}

@bp.after_request
def mark_workspace(response):
    if request.method == "HEAD" and response.status_code == 200:
        response.headers["X-Workspace-Scope"] = session.get("csrf", "")[-16:]
    return response


def init_db(db):
    redaction_batch.init_db(db)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS redactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, profile TEXT NOT NULL, result TEXT NOT NULL,
            stats TEXT NOT NULL, notes TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS redaction_owner ON redactions(user_id, id);
        CREATE INDEX IF NOT EXISTS redaction_owner_created ON redactions(user_id, created DESC, id DESC);
        CREATE INDEX IF NOT EXISTS redaction_batches_created ON redaction_batches(owner, created DESC, id DESC);
        CREATE TABLE IF NOT EXISTS redaction_requests (
            user_id INTEGER NOT NULL, nonce TEXT NOT NULL,
            record_id INTEGER NOT NULL REFERENCES redactions(id) ON DELETE CASCADE, PRIMARY KEY(user_id,nonce)
        );
    """)
    redaction_batch.mark_legacy_results(db, "redactions")


HISTORY_QUERY = r"(?:[№#]?\s*[0-9]{1,18}|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{2}\.[0-9]{2}\.[0-9]{4})"


def materials():
    before = request.args.get("before_batch", type=int)
    if before is not None and not request.args.get("q"):
        # Old bookmarks use a batch-only keyset cursor.
        rows = redaction_batch.history(get_db(), g.user["id"], before)
        return dict(rows=rows[:20], more=len(rows)>20, page=1, query="", legacy=True)
    query = request.args.get("q", "").strip()
    where = ""
    if query:
        if not re.fullmatch(HISTORY_QUERY, query):
            where = " AND 0"
        elif "-" in query or "." in query:
            date = "substr(?2,7,4)||'-'||substr(?2,4,2)||'-'||substr(?2,1,2)" if "." in query else "?2"
            where = f" AND created >= ({date}) AND created < date(({date}), '+1 day')"
        else:
            where = " AND id = CAST(ltrim(?2,'№# ') AS INTEGER)"
    # Numbered bindings are reused by both owner-scoped branches of the merge.
    return history_page(f"""SELECT id,created,profile,'result' AS kind FROM redactions WHERE user_id=?1{where}
        UNION ALL SELECT id,created,NULL AS profile,'batch' AS kind FROM redaction_batches WHERE owner=?1{where}
        ORDER BY created DESC,id DESC,kind LIMIT 51 OFFSET ?3""")


def page(*, original="", record=None, error="", error_field="", status=200, preview=False, ticket=""):
    history = materials() if request.method == "GET" and record is None and not error else None
    return render_template("redaction/index.html", history=history, history_query=HISTORY_QUERY,
                           record=record, original=original if len(original) <= MAX_TEXT else "",
                           error=error, error_field=error_field, hints=INPUT_HINTS, text_limit=MAX_TEXT,
                           file_limit=BATCH_MAX_BYTES, profiles=PROFILES, formats=SUPPORTED, categories=CATEGORIES,
                           groups=GROUPS, preview=preview, ticket=ticket, nonce=secrets.token_hex(16)), status


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "HEAD":
        return ""
    if request.method == "GET":
        return page()
    source = request.form.get("text", "").replace("\r\n", "\n")
    files = redaction_batch.selected_files()
    preview = "preview" in request.form
    if files and source.strip():
        return page(error=INPUT_HINTS["conflict"], error_field="text", status=422)
    if len(files) > 1:
        if preview:
            return page(error=INPUT_HINTS["multiple_preview"], error_field="file", status=422)
        return redaction_batch.add_selected_files(redaction_batch.reserve_batch(), files)
    owner = g.user["id"]
    db = get_db()
    nonce = request.form.get("nonce")
    if nonce and not re.fullmatch("[0-9a-f]{32}", nonce):
        abort(400)

    def previous():
        return db.execute("SELECT record_id FROM redaction_requests WHERE user_id=? AND nonce=?", (owner, nonce)).fetchone()

    if nonce and not preview and (record := previous()):
        return redirect(url_for("redaction.show", record_id=record["record_id"]))
    profile = request.form.get("profile", "faceless")
    glossary = request.form.get("glossary", "")
    groups = request.form.getlist("groups") if request.form.get("groups_shown") else None
    field = "file" if files else "text"
    try:
        if files:
            upload = files[0]
            ext = upload.filename.rpartition(".")[2].lower() if "." in upload.filename else ""
            if ext not in SUPPORTED:
                raise ValueError(INPUT_HINTS["format"])
            policy = policy_for(profile, glossary, groups)
            with tempfile.NamedTemporaryFile(prefix="ismanager-upload-") as local:
                size = 0
                while chunk := upload.stream.read(redaction_batch.CHUNK):
                    size += len(chunk)
                    if size > BATCH_MAX_BYTES:
                        raise ValueError(INPUT_HINTS["large_file"])
                    local.write(chunk)
                if not size:
                    raise ValueError(INPUT_HINTS["empty_file"])
                local.flush()
                source, note, table_secrets = extract_isolated(local.name, ext, with_counts=True, timeout=63)
            result, stats, notes = analyze_document(source, policy, table_secrets, note, timeout=65)
        else:
            analyzed = analyze(source, profile, glossary, groups)
            result, stats, notes = analyzed.text, analyzed.stats(), analyzed.warnings
    except TimeoutError:
        return page(error="Обработка превысила время ожидания. Разделите материал на части и обработайте их по очереди.", status=422)
    except NlpUnavailable:
        return page(error=redaction_batch.ERRORS["model"], status=422)
    except PrivacyError as exc:
        return page(error=redaction_batch.ERRORS[redaction_batch.failure(exc)], status=422)
    except SettingsError as exc:
        return page(error=str(exc), error_field=exc.field, status=422)
    except ValueError as exc:
        return page(error=str(exc), error_field=field, status=422)
    record = {"profile": profile, "stats": stats, "notes": notes, "result": result}
    if preview:
        if len(result.encode()) > 8 * 1024**2:
            return page(error="Результат слишком велик для предпросмотра. Выберите файл снова и нажмите «Обезличить и сохранить».",
                        error_field=field, status=422)
        # Only a digest and the checked report are signed. The browser retains the preview.
        metadata = {k: record[k] for k in ("profile", "stats", "notes")}
        ticket = preview_signer().dumps([owner, secrets.token_hex(16), result_hash(result), metadata])
        return page(original=source, record=record, preview=True, ticket=ticket)
    record_id = save_result(owner, nonce, record)
    return page(original=source, record=load_record(record_id))


def preview_signer():
    key = current_app.secret_key
    assert key is not None  # Validated by the application factory.
    return URLSafeTimedSerializer(key, salt="verified-redaction-preview-" + current_app.config["VERSION"])


def result_hash(text):
    # HTML textareas normalize line endings during form submission.
    return hashlib.sha256(text.replace("\r\n", "\n").replace("\r", "\n").encode()).hexdigest()


@bp.post("/preview/save")
def save_preview():
    try:
        owner, nonce, expected, record = preview_signer().loads(request.form.get("ticket", ""), max_age=1800)
    except BadSignature:
        return page(error="Предпросмотр устарел. Повторите обработку исходного материала.", status=422)
    if owner != g.user["id"]:
        abort(404)
    result = request.form.get("result", "").replace("\r\n", "\n").replace("\r", "\n")
    if not secrets.compare_digest(expected, result_hash(result)):
        return page(error="Текст предпросмотра изменился. Повторите обработку исходного материала.", status=422)
    record["result"] = result
    return redirect(url_for(".show", record_id=save_result(owner, nonce, record)))


def save_result(owner, nonce, record):
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        if nonce:
            previous = db.execute("SELECT record_id FROM redaction_requests WHERE user_id=? AND nonce=?",
                                  (owner, nonce)).fetchone()
            if previous:
                return previous["record_id"]
        row = db.execute("INSERT INTO redactions (user_id,profile,result,stats,notes) VALUES (?,?,?,?,?)",
                         (owner, record["profile"], record["result"], json.dumps(record["stats"]), json.dumps(record["notes"])))
        if nonce:
            db.execute("INSERT INTO redaction_requests VALUES (?,?,?)", (owner, nonce, row.lastrowid))
        return row.lastrowid


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
