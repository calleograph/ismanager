"""Run the private upload queue and folder redaction using the web image's local models."""
import fcntl
import logging
import os
from pathlib import Path
import sys
import time
from threading import Thread

from . import asr_store, folder_watch, redaction_batch

def main():
    data = Path(os.getenv("DATA_DIR", "/data"))
    lock_path = data / "redaction-worker.lock"
    if sys.argv[1:] == ["health"]:
        # The owning process holds the lock throughout long OCR and NLP jobs.
        with lock_path.open("rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
        raise SystemExit(1)
    if sys.argv[1:]:
        raise SystemExit(2)
    os.umask(0o077)
    database = os.getenv("DATABASE") or data / "ismanager.sqlite3"
    secret = os.environ["SECRET_KEY"]
    interval = max(1, int(os.getenv("WATCH_POLL_SECONDS", folder_watch.INTERVAL)))
    with lock_path.open("a+b") as lock, folder_watch.connect(database) as db:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        asr_store.init_db(db)
        redaction_batch.init_db(db)
        folder_watch.recover(db, data, kind="redaction")
        redaction_batch.recover(db, data)
        scanner = Thread(target=folder_watch.scan_loop, args=(database, secret, interval),
                         kwargs={"kind": "redaction"}, daemon=True)
        scanner.start()

        def upload():
            return redaction_batch.work(db, data)

        def folder():
            return folder_watch.work(db, data, None, secret, kind="redaction")

        uploads_first = True
        while scanner.is_alive():
            queues = (upload, folder) if uploads_first else (folder, upload)
            if any(work() for work in queues):
                uploads_first = not uploads_first
            else:
                time.sleep(1)
        raise RuntimeError("Обход папок обезличивания остановлен.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
