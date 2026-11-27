"""Private batch redaction. SQLite owns jobs and results, the spool owns pending inputs."""
from contextlib import closing, contextmanager
import fcntl
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import zipfile

from flask import Response, abort, current_app, g, jsonify, redirect, render_template, request, url_for

from .db import get_db
from .privacy.engine import PrivacyError
from .privacy.files import BATCH_MAX_BYTES, FileError, SUPPORTED
from .privacy.names import NlpUnavailable
from .privacy.processing import redact_file


PAGE_SIZE = 40
CHUNK = 1024 * 1024
STATES = {"queued":"В очереди", "running":"Обрабатывается", "done":"Готов", "failed":"Ошибка"}
ERRORS = {
    "extension":"Формат не поддерживается. Сохраните документ в одном из доступных форматов.",
    "size":f"Файл превышает предел {BATCH_MAX_BYTES//1048576} МиБ. Разделите его на части.",
    "empty":"Файл пуст.",
    "format":"Не удалось извлечь текст. Проверьте формат, целостность документа и качество скана.",
    "large_text":"Превышен предел обработки документа. Разделите его на части.",
    "locked":"Снимите защиту документа или сохраните копию без шифрования.",
    "verification":"Проверка обезличивания не пройдена. Результат закрыт.",
    "model":"Не удалось загрузить локальные модели. Обратитесь к администратору.",
    "interrupted":"Обработка была прервана. Добавьте файл повторно.",
    "missing":"Временный оригинал отсутствует. Добавьте файл повторно.",
    "internal":"Обработчик не завершил задачу. Добавьте файл повторно или обратитесь к администратору.",
}


def mark_legacy_results(db, table):
    with db:
        db.execute("BEGIN IMMEDIATE")
        if "legacy_rules" not in {r[1] for r in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN legacy_rules INTEGER NOT NULL DEFAULT 0")
            where = " WHERE state='done'" if table == "redaction_batch_files" else ""
            db.execute(f"UPDATE {table} SET legacy_rules=1" + where)


def init_db(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS redaction_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT, owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            nonce TEXT NOT NULL, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(owner,nonce)
        );
        CREATE INDEX IF NOT EXISTS redaction_batches_owner ON redaction_batches(owner,id);
        CREATE TABLE IF NOT EXISTS redaction_batch_files (
            id INTEGER PRIMARY KEY, batch_id INTEGER NOT NULL REFERENCES redaction_batches(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL, ext TEXT NOT NULL, fingerprint TEXT NOT NULL, source TEXT,
            state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
            result TEXT, replacements INTEGER NOT NULL DEFAULT 0, warnings INTEGER NOT NULL DEFAULT 0,
            UNIQUE(batch_id,ordinal), UNIQUE(batch_id,ext,fingerprint)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS redaction_batch_spool ON redaction_batch_files(source) WHERE source IS NOT NULL;
        CREATE INDEX IF NOT EXISTS redaction_batch_queue ON redaction_batch_files(state,id);
        CREATE INDEX IF NOT EXISTS redaction_batch_cleanup ON redaction_batch_files(id)
            WHERE source IS NOT NULL AND state IN ('done','failed');
        CREATE INDEX IF NOT EXISTS redaction_batch_counts ON redaction_batch_files(batch_id,state,ordinal);
        CREATE TABLE IF NOT EXISTS redaction_batch_receipts (
            batch_id INTEGER NOT NULL REFERENCES redaction_batches(id) ON DELETE CASCADE,
            token TEXT NOT NULL, file_id INTEGER NOT NULL REFERENCES redaction_batch_files(id) ON DELETE CASCADE,
            PRIMARY KEY(batch_id,token)
        );
    """)
    mark_legacy_results(db, "redaction_batch_files")


@contextmanager
def spool(data_dir, *, exclusive=False):
    directory = Path(data_dir) / "redaction-batch"
    directory.mkdir(mode=0o700, exist_ok=True)
    # A recovery scan may discard unreferenced files only while no HTTP upload or
    # worker can be between its filesystem operation and its SQLite commit.
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield directory
    finally:
        os.close(fd)


def batch_lock(batch_id, *, exclusive=False):
    owned_batch(batch_id)
    directory = Path(current_app.config["DATA_DIR"]) / "redaction-batch"
    directory.mkdir(mode=0o700, exist_ok=True)
    lock_dir = directory / ".locks"
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    path = lock_dir / str(batch_id)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    lock = os.fdopen(fd,"rb")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB if exclusive else fcntl.LOCK_SH)
        owned_batch(batch_id)  # A delete may have won before we acquired the lock.
        return lock, path
    except BlockingIOError:
        lock.close()
        abort(409,description="Сейчас пакет принимает файлы или отдаёт архив. Повторите удаление после завершения.")
    except BaseException:
        lock.close()
        raise


def remove_input(directory, source):
    if not source or not re.fullmatch(r"[a-f0-9]{32}", source):
        return True
    try:
        (directory / source).unlink(missing_ok=True)
        return True
    except OSError:
        logging.getLogger(__name__).warning("Batch spool cleanup will be retried")
        return False


def recover(db, data_dir):
    with spool(data_dir, exclusive=True) as directory:
        with db:
            db.execute("UPDATE redaction_batch_files SET state='failed',error='interrupted' WHERE state='running' AND attempts>=2")
            db.execute("UPDATE redaction_batch_files SET state='queued' WHERE state='running'")
        after = 0
        while rows := db.execute("""SELECT id,source,state FROM redaction_batch_files
                WHERE source IS NOT NULL AND id>? ORDER BY id LIMIT 256""", (after,)).fetchall():
            after = rows[-1]["id"]
            clear, missing = [], []
            for row in rows:
                source = row["source"]
                if row["state"] in ("done","failed"):
                    if remove_input(directory, source):
                        clear.append((row["id"],))
                elif not re.fullmatch(r"[a-f0-9]{32}",source) or not (directory / source).is_file():
                    missing.append((row["id"],))
            with db:
                db.executemany("UPDATE redaction_batch_files SET source=NULL WHERE id=?", clear)
                db.executemany("UPDATE redaction_batch_files SET state='failed',source=NULL,error='missing' WHERE id=?", missing)
        for path in directory.iterdir():
            if re.fullmatch(r"[0-9a-f]{32}", path.name) and not db.execute(
                    "SELECT 1 FROM redaction_batch_files WHERE source=?", (path.name,)).fetchone():
                remove_input(directory,path.name)


def parser_warnings(notes):
    # Only fixed messages reach SQLite. Never persist arbitrary per-document diagnostics.
    flags = 0
    for note in notes:
        lowered = note.casefold()
        if "ocr" in lowered:
            flags |= 1
        if "изображения внутри офисного документа" in lowered and "опущены" in lowered:
            flags |= 2
    return flags


def failure(error):
    if isinstance(error, FileError):
        message = str(error).casefold()
        if "зашифрован" in message or "парол" in message:
            return "locked"
        if any(term in message for term in ("предел", "превыс", "лимит", "слишком")):
            return "large_text"
        return "format"
    if isinstance(error, PrivacyError):
        return "verification"
    if isinstance(error, NlpUnavailable):
        return "model"
    if isinstance(error, FileNotFoundError):
        return "missing"
    return "internal"


def work(db, data_dir):
    with spool(data_dir) as directory:
        with db:
            item = db.execute("""UPDATE redaction_batch_files SET state='running',attempts=attempts+1
                WHERE id=(SELECT id FROM redaction_batch_files WHERE state='queued' ORDER BY id LIMIT 1)
                RETURNING id,ext,source""").fetchone()
        if item is None:
            pending = db.execute("""SELECT id,source FROM redaction_batch_files
                WHERE source IS NOT NULL AND state IN ('done','failed') ORDER BY id LIMIT 1""").fetchone()
            if pending and remove_input(directory,pending["source"]):
                with db:
                    db.execute("UPDATE redaction_batch_files SET source=NULL WHERE id=? AND source=?", (pending["id"],pending["source"]))
                return True
            return False
        path = directory / item["source"]
        try:
            result, stats, notes = redact_file(path, item["ext"])
            warnings = parser_warnings(notes)
            replacements = sum(stats.values())
            status, error = "done", ""
        except Exception as exc:
            # Free-form parser diagnostics and source text must never reach the UI or logs.
            error = failure(exc)
            logging.getLogger(__name__).warning("Batch file %d: %s", item["id"], error)
            status, result, replacements, warnings = "failed", None, 0, 0
        with db:
            db.execute("UPDATE redaction_batch_files SET state=?,error=?,result=?,replacements=?,warnings=?,legacy_rules=0 WHERE id=?",
                       (status,error,result,replacements,warnings,item["id"]))
        if remove_input(directory,item["source"]):
            with db:
                db.execute("UPDATE redaction_batch_files SET source=NULL WHERE id=? AND source=?", (item["id"],item["source"]))
        return True


def register(bp):
    bp.add_url_rule("/batches", view_func=create_batch, methods=["POST"])
    bp.add_url_rule("/batches/<int:batch_id>", view_func=batch)
    bp.add_url_rule("/batches/<int:batch_id>/delete", view_func=delete_batch, methods=["POST"])
    bp.add_url_rule("/batches/<int:batch_id>/files", view_func=upload_file, methods=["POST"])
    bp.add_url_rule("/batches/<int:batch_id>/files/<int:ordinal>/download", view_func=batch_download)
    bp.add_url_rule("/batches/<int:batch_id>/archive.zip", view_func=batch_archive)
    bp.before_app_request(limit_request)


def limit_request():
    if request.endpoint == "redaction.upload_file":
        request.max_content_length = 8192 if request.is_json else BATCH_MAX_BYTES + 300_000


def history(db, owner, before=None):
    return db.execute("""SELECT id,created FROM redaction_batches WHERE owner=? AND (? IS NULL OR id<?)
                         ORDER BY id DESC LIMIT 21""", (owner,before,before)).fetchall()


def owned_batch(batch_id):
    db = get_db()
    row = db.execute("SELECT id,created FROM redaction_batches WHERE id=? AND owner=?", (batch_id,g.user["id"])).fetchone()
    if row is None:
        abort(404)
    return row


def create_batch():
    token = request.form.get("nonce","")
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        abort(400)
    db = get_db()
    with db:
        db.execute("INSERT OR IGNORE INTO redaction_batches (owner,nonce) VALUES (?,?)", (g.user["id"],token))
        row = db.execute("SELECT id FROM redaction_batches WHERE owner=? AND nonce=?", (g.user["id"],token)).fetchone()
    link = url_for(".batch", batch_id=row["id"])
    if request.accept_mimetypes.best == "application/json":
        return jsonify(id=row["id"],url=link,upload=url_for(".upload_file",batch_id=row["id"]))
    return redirect(link, 303)


def batch(batch_id):
    info = owned_batch(batch_id)
    db = get_db()
    counts = {row["state"]: row["n"] for row in db.execute(
        "SELECT state,count(*) AS n FROM redaction_batch_files WHERE batch_id=? GROUP BY state", (batch_id,))}
    legacy = db.execute("SELECT 1 FROM redaction_batch_files WHERE batch_id=? AND state='done' AND legacy_rules=1 LIMIT 1",
                        (batch_id,)).fetchone()
    total = sum(counts.values())
    last_page = max(1,(total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(last_page,max(1,request.args.get("page",1,type=int)))
    files = db.execute("""SELECT ordinal,ext,state,error,replacements,warnings FROM redaction_batch_files
                          WHERE batch_id=? AND ordinal>? ORDER BY ordinal LIMIT ?""",
                       (batch_id,(page-1)*PAGE_SIZE,PAGE_SIZE)).fetchall()
    return render_template("redaction/batch.html", batch=info, counts=counts, legacy=legacy, total=total, states=STATES,
                           errors=ERRORS, files=files, page=page, last_page=last_page, formats=SUPPORTED,
                           limit=BATCH_MAX_BYTES, nonce=secrets.token_hex(16))


def delete_batch(batch_id):
    lock, path = batch_lock(batch_id, exclusive=True)
    with lock, get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("""SELECT 1 FROM redaction_batch_files WHERE batch_id=?
                         AND (state IN ('queued','running') OR source IS NOT NULL) LIMIT 1""", (batch_id,)).fetchone():
            abort(409,description="Дождитесь завершения обработки и очистки оригиналов.")
        db.execute("DELETE FROM redaction_batches WHERE id=? AND owner=?", (batch_id,g.user["id"]))
    path.unlink(missing_ok=True)
    if request.accept_mimetypes.best == "application/json":
        return jsonify(url=url_for(".index"))
    return redirect(url_for(".index"),303)


def record(db, batch_id, key, ext, fingerprint, source, error):
    with db:
        db.execute("BEGIN IMMEDIATE")
        receipt = db.execute("""SELECT f.id,f.ordinal,f.ext,f.fingerprint,f.state,f.error FROM redaction_batch_receipts r JOIN redaction_batch_files f ON f.id=r.file_id
                                WHERE r.batch_id=? AND r.token=?""", (batch_id,key)).fetchone()
        if receipt and (receipt["ext"] != ext or receipt["fingerprint"] != fingerprint):
            abort(409, description="Этот запрос уже относится к другому файлу.")
        row = receipt or db.execute("SELECT id,ordinal,ext,fingerprint,state,error FROM redaction_batch_files WHERE batch_id=? AND ext=? AND fingerprint=?",
                                    (batch_id,ext,fingerprint)).fetchone()
        keep = False
        if row is None:
            ordinal = db.execute("SELECT coalesce(max(ordinal),0)+1 FROM redaction_batch_files WHERE batch_id=?",
                                 (batch_id,)).fetchone()[0]
            row = db.execute("""INSERT INTO redaction_batch_files(batch_id,ordinal,ext,fingerprint,source,state,error)
                                VALUES(?,?,?,?,?,?,?) RETURNING *""",
                             (batch_id,ordinal,ext,fingerprint,source,"failed" if error else "queued",error)).fetchone()
            keep = bool(source)
        elif source and row["state"] == "failed" and (not receipt or row["error"] in ("missing","interrupted")):
            row = db.execute("""UPDATE redaction_batch_files SET source=?,state='queued',attempts=0,error=''
                                WHERE id=? RETURNING *""", (source,row["id"])).fetchone()
            keep = True
        if not receipt:
            db.execute("INSERT INTO redaction_batch_receipts VALUES(?,?,?)", (batch_id,key,row["id"]))
    return row["ordinal"], keep


def upload_file(batch_id):
    lock, _ = batch_lock(batch_id)
    with lock:
        return receive_file(batch_id)


def receive_file(batch_id):
    db = get_db()
    key = request.headers.get("X-Upload-Key") or request.form.get("nonce","")
    if not re.fullmatch(r"[0-9a-f]{32}",key):
        abort(400)
    raw = request.mimetype == "application/octet-stream"
    metadata = request.get_json() if request.is_json else None
    multipart = not raw and metadata is None
    if multipart:
        upload = request.files.get("file")
        if not upload or not upload.filename:
            abort(400,description="Выберите файл.")
        filename = upload.filename.replace("\\","/").rsplit("/",1)[-1]
        ext = filename.rpartition(".")[2].lower() if "." in filename else ""
        stream, declared = upload.stream, None
    elif raw:
        ext = request.args.get("ext","").lower()
        stream, declared = request.stream, request.content_length
    else:
        if not isinstance(metadata,dict) or not isinstance(metadata.get("size"),int) or not isinstance(metadata.get("ext"),str):
            abort(400)
        ext, declared = metadata["ext"].lower(), metadata["size"]
        stream = None
    error = "extension" if ext not in SUPPORTED else "size" if declared and declared>BATCH_MAX_BYTES else ""
    if stream is None and not error:
        abort(400,description="Для обработки требуется содержимое файла.")
    ext = ext if ext in SUPPORTED else ""
    secret = current_app.secret_key
    mac = hmac.new(secret.encode() if isinstance(secret,str) else secret, f"batch:{batch_id}\0".encode(), hashlib.sha256)
    with spool(current_app.config["DATA_DIR"]) as directory:
        token = secrets.token_hex(16)
        path = directory / token
        keep = created = False
        try:
            if not error:
                size = 0
                with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as out:
                    created = True
                    while chunk := stream.read(CHUNK):
                        size += len(chunk)
                        if size > BATCH_MAX_BYTES:
                            error = "size"
                            break
                        mac.update(chunk)
                        out.write(chunk)
                    if size == 0:
                        error = "empty"
                    out.flush()
                    os.fsync(out.fileno())
                directory_fd = os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            if error:
                # Invalid submissions have no retained content. Hash only metadata supplied for retries.
                hint = filename[:512] if multipart else str((metadata or {}).get("hint",""))[:32]
                if not multipart and not re.fullmatch(r"[0-9a-f]{16}",hint):
                    hint = key if error != "empty" else ""
                mac.update(json.dumps([error,hint,declared,ext],ensure_ascii=False).encode())
            ordinal, keep = record(db,batch_id,key,ext,mac.hexdigest(),None if error else token,error)
        finally:
            if created and not keep:
                path.unlink(missing_ok=True)
    if multipart:
        return redirect(url_for(".batch", batch_id=batch_id),303)
    return jsonify(ordinal=ordinal, error=ERRORS.get(error,""))


def batch_download(batch_id, ordinal):
    owned_batch(batch_id)
    row = get_db().execute("SELECT result FROM redaction_batch_files WHERE batch_id=? AND ordinal=? AND state='done'",
                           (batch_id,ordinal)).fetchone()
    if row is None:
        abort(404)
    return Response(row["result"], mimetype="text/plain",
                    headers={"Content-Disposition":f'attachment; filename="redacted-{ordinal:06d}.txt"'})


class ZipBuffer:
    def __init__(self):
        self.data = bytearray()

    def write(self, value):
        self.data.extend(value)
        return len(value)

    def flush(self):
        pass

    def take(self):
        value = bytes(self.data)
        self.data.clear()
        return value


def batch_archive(batch_id):
    # Capture membership once without keeping a read transaction open for a slow download.
    lock, _ = batch_lock(batch_id)
    try:
        ordinals = [row[0] for row in get_db().execute(
            "SELECT ordinal FROM redaction_batch_files WHERE batch_id=? AND state='done' ORDER BY ordinal", (batch_id,))]
        if not ordinals:
            abort(404,description="В пакете пока нет готовых результатов.")
    except BaseException:
        lock.close()
        raise

    database = current_app.config["DATABASE"]

    def chunks():
        sink = ZipBuffer()
        with lock, closing(sqlite3.connect(database,timeout=20)) as reader, zipfile.ZipFile(
            sink,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=3
        ) as archive:
            for ordinal in ordinals:
                text = reader.execute("SELECT result FROM redaction_batch_files WHERE batch_id=? AND ordinal=?",
                                  (batch_id,ordinal)).fetchone()[0]
                with archive.open(f"redacted-{ordinal:06d}.txt","w") as member:
                    for start in range(0,len(text),65536):
                        member.write(text[start:start+65536].encode("utf-8"))
                        if sink.data:
                            yield sink.take()
        if sink.data:
            yield sink.take()
    response = Response(chunks(),mimetype="application/zip",
                        headers={"Content-Disposition":f'attachment; filename="redacted-batch-{batch_id}.zip"'})
    response.call_on_close(lock.close)
    return response
