"""Durable folder discovery and timestamped transcription on the single GigaAM worker."""
import hashlib
import json
import logging
import sqlite3
import time
import unicodedata
from pathlib import Path, PurePosixPath

from . import watch_storage

LOG = logging.getLogger("watch")
INTERVAL = 15
RETRY_DELAY = 30
MAX_BYTES = 512 * 1024**2
DEFAULT_FOLDER = "Тексты IS Manager"


def signature(snap):
    return json.dumps([snap.size, snap.mtime_ns, snap.file_id], separators=(",", ":"))


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def output_location(rule):
    if rule["output_resource"] is not None:
        return rule["output_resource"], rule["output_folder"]
    return rule["input_resource"], str(PurePosixPath(rule["input_folder"]) / DEFAULT_FOLDER)


def storage_location(resource, folder):
    """Canonical directory across named resources that address the same share or local path."""
    path = str(PurePosixPath(resource["path"], folder))
    if resource["kind"] == "local":
        return ("local", path)
    return ("smb", resource["server"].lower(), resource["port"], resource["share"].casefold(),
            unicodedata.normalize("NFC", path).casefold())


def storage(db, rule, secret, root, *, output=False):
    resource_id, folder = output_location(rule) if output else (rule["input_resource"], rule["input_folder"])
    row = db.execute("SELECT * FROM watch_resources WHERE id=?", (resource_id,)).fetchone()
    if row is None:
        raise OSError("Ресурс удалён.")
    return watch_storage.open_storage(row, secret, root, folder=folder, create=output)


def output_slot(db, rule, name, version=""):
    resource_id, folder = output_location(rule)
    resource = db.execute("SELECT * FROM watch_resources WHERE id=?", (resource_id,)).fetchone()
    directory = storage_location(resource, folder)
    stem = Path(name).stem
    # A second format with the same stem gets its extension in the TXT name.
    # Reserve names case-insensitively even when the source lives on Linux.
    index = 0
    while True:
        suffix = f".{version[:12]}" if version else ""
        if index > 1:
            suffix += f".{index}"
        base = stem if index == 0 else name
        suffix += ".txt"
        base = base.encode("utf-8")[:240 - len(suffix)].decode("utf-8", "ignore")
        filename = base + suffix
        key = json.dumps([*directory, unicodedata.normalize("NFC", filename).casefold()])
        if not db.execute("SELECT 1 FROM watch_files WHERE output_key=?", (key,)).fetchone():
            return filename, key
        index += 1


def change(db, item, now, **values):
    """Ignore stale work if the scanner has discovered a newer version or the rule was removed."""
    values["updated"] = now
    columns = ",".join(key + "=?" for key in values)
    with db:
        return db.execute(f"UPDATE watch_files SET {columns} WHERE id=? AND stamp=? AND state=?",
                          (*values.values(), item["id"], item["stamp"], item["state"])).rowcount == 1


def reserve_alternate(db, item, rule, now, sha, **values):
    with db:
        db.execute("BEGIN IMMEDIATE")
        filename, key = output_slot(db, rule, item["name"], sha)
        return change(db, item, now, output_name=filename, output_key=key, fallback_sha=sha,
                      published_sha="", output_stamp="", **values)


def current_rule(db, rule_id):
    return db.execute("SELECT * FROM watch_rules WHERE id=? AND enabled=1", (rule_id,)).fetchone()


def same_route(first, second):
    return second is not None and all(first[key] == second[key] for key in (
        "input_resource", "input_folder", "output_resource", "output_folder"))


def observe_one(db, rule, snap, now, interval):
    stamp = signature(snap)
    item = db.execute("""SELECT id,stamp,state,replaced,seen_since,output_stamp FROM watch_files
                         WHERE rule_id=? AND name=?""", (rule["id"], snap.name)).fetchone()
    if item is None:
        filename, key = output_slot(db, rule, snap.name)
        db.execute("""INSERT INTO watch_files(rule_id,name,stamp,seen_since,updated,output_name,output_key)
                      VALUES (?,?,?,?,?,?,?)""", (rule["id"], snap.name, stamp, now, now, filename, key))
    elif item["stamp"] != stamp or item["state"] == "missing":
        replaced = item["replaced"] or item["output_stamp"] or item["state"] in {"existing", "conflict"}
        db.execute("""UPDATE watch_files SET stamp=?,state='settling',seen_since=?,updated=?,
                      error='',retry_at=0,remove_after=0,replaced=? WHERE id=?""",
                   (stamp, now, now, int(bool(replaced)), item["id"]))
    elif item["state"] == "settling" and now - item["seen_since"] >= interval:
        db.execute("UPDATE watch_files SET state='queued',updated=?,remove_after=? WHERE id=?",
                   (now, rule["delete_source"], item["id"]))


def batches(items):
    for offset in range(0, len(items), 128):
        yield items[offset:offset + 128]


def observe(db, rule, snapshots, now, interval):
    snapshots.sort(key=lambda file: file.name)
    seen = {snap.name for snap in snapshots}
    for batch in batches(snapshots):
        with db:
            # Release SQLite's single writer between batches in large archives.
            db.execute("BEGIN IMMEDIATE")
            current = current_rule(db, rule["id"])
            if not same_route(rule, current):
                return
            for snap in batch:
                observe_one(db, current, snap, now, interval)
    rows = db.execute("""SELECT id,name FROM watch_files WHERE rule_id=?
                         AND state IN ('settling','queued','failed','existing')""", (rule["id"],))
    missing = [row["id"] for row in rows if row["name"] not in seen]
    for batch in batches(missing):
        with db:
            db.execute("BEGIN IMMEDIATE")
            if not same_route(rule, current_rule(db, rule["id"])):
                return
            db.executemany("""UPDATE watch_files SET state='missing',updated=?,error='' WHERE id=?
                              AND state IN ('settling','queued','failed','existing')""",
                           ((now, item_id) for item_id in batch))
    return seen


def check_outputs(db, rule, seen, secret, root, now):
    items = db.execute("""SELECT id,state,name,stamp,output_stamp,published_sha,result_stamp,output_name
                          FROM watch_files WHERE rule_id=? AND state IN ('done','existing','conflict')
                          ORDER BY id""", (rule["id"],)).fetchall()
    if not items:
        return
    with storage(db, rule, secret, root, output=True) as destination:
        for item in items:
            try:
                output = destination.stat(item["output_name"])
            except FileNotFoundError:
                output = None
            if output is None or output.size == 0:
                # Restore the exact saved TXT even after configured source removal.
                if item["result_stamp"] == item["stamp"]:
                    change(db, item, now, state="publishing", error="", retry_at=0)
                elif item["name"] in seen:
                    change(db, item, now, state="queued", remove_after=rule["delete_source"], error="", retry_at=0)
                continue
            if item["state"] != "done":
                continue
            out_stamp = signature(output)
            if out_stamp != item["output_stamp"]:
                try:
                    unchanged = digest(destination.read_text(item["output_name"])) == item["published_sha"]
                except (UnicodeError, ValueError):
                    unchanged = False
                if not unchanged:
                    change(db, item, now, state="conflict",
                           error="TXT изменён вне IS Manager. Для восстановления переименуйте или удалите его.")
                    continue
                change(db, item, now, output_stamp=out_stamp)


def scan_once(db, secret, root=None, *, now=None, interval=INTERVAL):
    now = int(time.time()) if now is None else now
    rules = db.execute("""SELECT * FROM watch_rules WHERE enabled=1 AND
                          (last_scan=0 OR last_scan<=? OR last_scan>?) ORDER BY last_scan,id""",
                       (now - interval, now)).fetchall()
    for rule in rules:
        with db:
            db.execute("UPDATE watch_rules SET last_scan=? WHERE id=?", (now, rule["id"]))
        try:
            with storage(db, rule, secret, root) as source:
                snapshots = list(source.list_media())
            seen = observe(db, rule, snapshots, now, interval)
            if seen is None:
                continue
            check_outputs(db, rule, seen, secret, root, now)
            error = ""
        except (OSError, ValueError) as exc:
            LOG.warning("Watch rule %s scan failed (%s)", rule["id"], type(exc).__name__)
            error = "Не удалось проверить папку. Проверьте подключение и права учётной записи."
        with db:
            db.execute("UPDATE watch_rules SET error=? WHERE id=?", (error, rule["id"]))


def connect(database):
    db = sqlite3.connect(database, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def scan_loop(database, secret, interval):
    # A long recording must not delay discovery in other folders.
    db = connect(database)
    while True:
        try:
            scan_once(db, secret, interval=interval)
        except Exception as exc:
            db.rollback()
            LOG.error("Folder discovery failed (%s)", type(exc).__name__)
        time.sleep(1)


def recover(db, data_dir):
    # The sole worker owns this fixed scratch path under its private data volume.
    (Path(data_dir) / "watch-source.tmp").unlink(missing_ok=True)
    with db:
        db.execute("UPDATE watch_files SET state='queued',retry_at=0 WHERE state='running'")


def stat_or_none(store, name):
    try:
        return store.stat(name)
    except FileNotFoundError:
        return None


def mark_changed(db, item, now):
    change(db, item, now, state="settling", seen_since=now, retry_at=0, error="")


def stage(db, item, rule, data_dir, engine, secret, root, now):
    from . import worker

    with storage(db, rule, secret, root, output=True) as destination:
        existing = stat_or_none(destination, item["output_name"])
    if existing and existing.size and not item["published_sha"] and not item["replaced"]:
        change(db, item, now, state="existing", output_stamp=signature(existing),
               remove_after=0, error="TXT с таким именем уже существует.")
        return
    scratch = Path(data_dir) / "watch-source.tmp"
    try:
        with storage(db, rule, secret, root) as source:
            snap = stat_or_none(source, item["name"])
            if snap is None:
                change(db, item, now, state="missing")
                return
            if signature(snap) != item["stamp"]:
                mark_changed(db, item, now)
                return
            if not 0 < snap.size <= MAX_BYTES:
                raise worker.RecordingError("Пустой файл или размер больше 512 МиБ.")
            sha = source.copy_source(snap, scratch, max_bytes=MAX_BYTES)
        # Only consult the cache after this resource's account has read and verified the entire file.
        cached = db.execute("SELECT timed_text FROM watch_files WHERE source_sha=? AND source_sha!='' LIMIT 1",
                            (sha,)).fetchone()
        if cached:
            timed = cached["timed_text"]
        else:
            def progress(seconds, percent):
                worker.status(Path(data_dir), "GigaAM обрабатывает запись из папки", True)
            timed = worker.transcribe(scratch, engine, progress, timed=True)
        result = dict(state="publishing", result_stamp=item["stamp"], source_sha=sha, timed_text=timed,
                      retry_at=0, error="")
        if existing and existing.size and not item["published_sha"] and item["replaced"]:
            reserve_alternate(db, item, rule, now, sha, **result)
        else:
            change(db, item, now, **result)
    finally:
        scratch.unlink(missing_ok=True)


def publish(db, item, rule, secret, root, now):
    with storage(db, rule, secret, root) as source:
        snap = stat_or_none(source, item["name"])
        if snap is not None and signature(snap) != item["stamp"]:
            mark_changed(db, item, now)
            return
        with storage(db, rule, secret, root, output=True) as destination:
            if not same_route(rule, current_rule(db, rule["id"])):
                return
            name = item["output_name"]
            try:
                before = stat_or_none(destination, name)
                previous = digest("") if before is not None and before.size == 0 else item["published_sha"] or None
                destination.publish_text(name, item["timed_text"], previous_sha256=previous)
            except FileExistsError:
                # Keep a user's TXT intact. Publish the changed source under a stable versioned name.
                if item["replaced"] and item["fallback_sha"] != item["source_sha"]:
                    reserve_alternate(db, item, rule, now, item["source_sha"])
                else:
                    change(db, item, now, state="conflict", remove_after=0,
                           error="В папке вывода другой TXT. Для восстановления переименуйте или удалите его.")
                return
            expected = digest(item["timed_text"])
            out_stamp = signature(destination.stat(name))
            if digest(destination.read_text(name)) != expected:
                raise OSError("TXT не прошёл проверку записи.")
            if not change(db, item, now, published_sha=expected, output_stamp=out_stamp):
                return
            current = current_rule(db, rule["id"])
            message = ""
            if same_route(rule, current) and current["delete_source"] and item["remove_after"]:
                # On POSIX a previous process may have died after moving the inode
                # into recovery but before unlinking it. Resume using the exact saved identity.
                expected_source = watch_storage.Snapshot(item["name"], *json.loads(item["stamp"]))
                try:
                    source.delete_source(expected_source, item["source_sha"])
                except watch_storage.SourceRetainedError:
                    message = "TXT сохранён. Для безопасного удаления исходника недостаточно прав или возможностей ресурса."
            change(db, item, now, state="done", remove_after=0, retry_at=0, error=message)


def work(db, data_dir, engine, secret, root=None, *, now=None):
    from .worker import RecordingError

    now = int(time.time()) if now is None else now
    with db:
        db.execute("BEGIN IMMEDIATE")
        item = db.execute("""SELECT f.* FROM watch_files f JOIN watch_rules r ON r.id=f.rule_id
                             WHERE r.enabled AND f.state IN ('publishing','queued') AND f.retry_at<=?
                             ORDER BY f.updated,f.id LIMIT 1""", (now,)).fetchone()
        if item is None:
            return False
        if item["state"] == "queued":
            db.execute("UPDATE watch_files SET state='running',updated=? WHERE id=?", (now, item["id"]))
            item = db.execute("SELECT * FROM watch_files WHERE id=?", (item["id"],)).fetchone()
        rule = current_rule(db, item["rule_id"])
    try:
        if item["state"] == "running":
            stage(db, item, rule, data_dir, engine, secret, root, now)
        else:
            publish(db, item, rule, secret, root, now)
    except watch_storage.SourceChangedError:
        mark_changed(db, item, now)
    except RecordingError as exc:
        change(db, item, now, state="failed", error=str(exc))
    except sqlite3.OperationalError:
        raise
    except (OSError, ValueError) as exc:
        LOG.warning("Watch job %s storage error (%s)", item["id"], type(exc).__name__)
        state = "queued" if item["state"] == "running" else "publishing"
        change(db, item, now, state=state, retry_at=now + RETRY_DELAY,
               error="Проверьте доступ к ресурсу и свободное место. Повтор через 30 секунд.")
    except Exception as exc:
        LOG.error("Watch job %s failed (%s)", item["id"], type(exc).__name__)
        change(db, item, now, state="failed", error="Сбой обработки. Проверьте worker и повторите.")
    return True
