"""Authenticated recording uploads, transcript editor and exports."""
from pathlib import Path
import time
from datetime import datetime, timezone
from uuid import uuid4

from flask import (
    Blueprint, Response, abort, current_app, flash, g, redirect,
    render_template, request, url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge

from .asr_store import init_db, model_status, source_path
from .db import get_db
from .personal_history import history_page
from .telemetry import public_counters, worker_info

bp = Blueprint("transcription", __name__, url_prefix="/transcription")
STATUS = {"queued": "В очереди", "running": "Идёт распознавание",
          "done": "Готово", "failed": "Ошибка"}
MAX_UPLOAD = 512 * 1024 * 1024
MAX_TEXT = 2_000_000
UPLOAD_ERRORS = {
    "missing": "В поле «Аудио или видео» выберите запись, затем нажмите «Расшифровать запись».",
    "empty": "В выбранном файле 0 байт. Выберите копию записи со звуком.",
    "large": "Запись больше 512 МиБ. Разделите её на части до 512 МиБ и загрузите каждую отдельно.",
}


@bp.before_app_request
def limit_upload():
    if request.endpoint == "transcription.index" and request.method == "POST":
        request.max_content_length = MAX_UPLOAD + 1024 * 1024


def _data():
    return Path(current_app.config["DATA_DIR"])


def _job(job_id):
    row = get_db().execute("SELECT * FROM transcripts WHERE id=? AND owner=?",
                           (job_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    return row


def upload_page(error=None, status=200):
    if error and request.accept_mimetypes.best == "application/json":
        return {"error": error}, status
    history = history_page("""SELECT id,filename,status,created FROM transcripts
        WHERE owner=? AND instr(casefold(filename),?)>0 ORDER BY rowid DESC LIMIT 51 OFFSET ?""")
    return render_template("transcription/index.html", history=history, status=STATUS,
                           model_status=model_status(_data()), upload_errors=UPLOAD_ERRORS,
                           upload_error=error), status


@bp.route("/", methods=["GET", "POST"])
def index():
    db = get_db()
    if request.method == "POST":
        media = request.files.get("media")
        if media is None or not media.filename or not media.filename.strip():
            return upload_page(UPLOAD_ERRORS["missing"], 422)
        name = media.filename.replace("\\", "/").split("/")[-1].strip()[:200]
        job_id = uuid4().hex
        dest = source_path(_data(), job_id)
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        size = 0
        try:
            with dest.open("xb") as out:
                while chunk := media.stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_UPLOAD:
                        raise RequestEntityTooLarge()
                    out.write(chunk)
            if not size:
                dest.unlink()
                return upload_page(UPLOAD_ERRORS["empty"], 422)
            db.execute("INSERT INTO transcripts(id, owner, filename, accepted_at) VALUES (?,?,?,unixepoch())",
                       (job_id, g.user["id"], name or "Запись"))
            db.commit()
        except RequestEntityTooLarge:
            dest.unlink(missing_ok=True)
            return upload_page(UPLOAD_ERRORS["large"], 413)
        except Exception:
            dest.unlink(missing_ok=True)
            raise
        location = url_for(".detail", job_id=job_id)
        if request.accept_mimetypes.best == "application/json":
            return {"location": location}, 201
        return redirect(location)

    return upload_page()


@bp.get("/<job_id>")
def detail(job_id):
    job = _job(job_id)
    return render_template("transcription/detail.html", job=job, status=STATUS, report=job_report(job))


def job_report(job):
    state = job["status"]
    events = []
    for field, label in (("accepted_at", "Запись принята в очередь"), ("started_at", "Проверка звуковой дорожки"),
                         ("recognizing_at", "Распознавание русской речи"), ("finished_at", STATUS[state])):
        if job[field]:
            stamp = datetime.fromtimestamp(job[field], timezone.utc).strftime("%H:%M:%S")
            events.append(f"{stamp} UTC · {label}")
    stage = STATUS[state]
    if state == "running":
        stage = "Распознавание русской речи" if job["recognizing_at"] else "Проверка звуковой дорожки"
    active = state in {"queued", "running"}
    until = int(time.time()) if active else job["finished_at"]
    elapsed = max(0, until - job["accepted_at"]) if until and job["accepted_at"] else None
    counters = public_counters(worker_info(_data())) if active else {}
    return dict(state=state, stage=stage, events=events, elapsed=elapsed, seconds=job["seconds"],
                percent=job["progress"], resources=counters)


@bp.get("/<job_id>/status")
def job_status(job_id):
    row = get_db().execute("""SELECT status,accepted_at,started_at,recognizing_at,finished_at,seconds,progress
                              FROM transcripts WHERE id=? AND owner=?""", (job_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    return job_report(row)


@bp.post("/<job_id>/retry")
def retry(job_id):
    _job(job_id)
    db = get_db()
    with db:
        changed = db.execute("UPDATE transcripts SET status='queued',progress=0,seconds=0,recoveries=0,error='',"
                             "accepted_at=unixepoch(),started_at=NULL,recognizing_at=NULL,finished_at=NULL "
                             "WHERE id=? AND owner=? AND status='failed'", (job_id, g.user["id"])).rowcount
    if not changed:
        abort(409)
    return redirect(url_for(".detail", job_id=job_id))


@bp.post("/<job_id>/save")
def save(job_id):
    job = _job(job_id)
    if job["status"] != "done":
        abort(409, "Дождитесь готовности стенограммы и снова откройте запись.")
    submitted = request.form.get("body", "")
    body = submitted.strip()
    if not body or len(body) > MAX_TEXT:
        error = ("Введите текст стенограммы и нажмите «Сохранить правки»." if not body else
                 "В стенограмме больше 2 млн знаков. Сократите текст и сохраните правки ещё раз.")
        return render_template("transcription/detail.html", job=job, report=job_report(job),
                               edited_body=submitted, edit_error=error), 422
    db = get_db()
    with db:
        changed = db.execute("UPDATE transcripts SET body=?,revision=revision+1 "
                             "WHERE id=? AND owner=? AND status='done' AND revision=?",
                             (body, job_id, g.user["id"], request.form.get("revision", type=int))).rowcount
    if not changed:
        current = _job(job_id)
        return render_template("transcription/detail.html", job=current, report=job_report(current),
                               conflict_body=submitted), 409
    flash("Правки сохранены.", "success")
    return redirect(url_for(".detail", job_id=job_id))


@bp.get("/<job_id>/export")
def export(job_id):
    job = _job(job_id)
    if job["status"] != "done":
        abort(409)
    return Response(job["body"] + "\n", mimetype="text/plain",
                    headers={"Content-Disposition": 'attachment; filename="transcript.txt"'})


@bp.post("/<job_id>/delete")
def delete(job_id):
    _job(job_id)
    db = get_db()
    with db:
        changed = db.execute("DELETE FROM transcripts WHERE id=? AND owner=? AND status!='running'",
                             (job_id, g.user["id"])).rowcount
    if not changed:
        abort(409, "Дождитесь завершения обработки.")
    source_path(_data(), job_id).unlink(missing_ok=True)
    return redirect(url_for(".index"))
