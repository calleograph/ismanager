#!/usr/bin/env python3
"""Restricted host helper. The web container never has access to the Docker socket."""
import hashlib
import secrets
import socket
import subprocess
import sys

from manage import ROOT, STATE, replace, settings
import json


def status(text):
    replace(STATE / "control" / "status.json", json.dumps({"message": text}, ensure_ascii=False), 0o644)


def main():
    if (STATE / "pending.json").exists() or (STATE / "control" / "maintenance").exists():
        subprocess.run([sys.executable, str(ROOT / "scripts/manage.py"), "recover"], cwd=ROOT)
    path = STATE / "control" / "operator.sock"
    path.unlink(missing_ok=True)
    job = None
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        # Write access for the container UID. Requests also require the installation's secret.
        path.chmod(0o666)
        server.listen(5)
        server.settimeout(1)
        while True:
            if job and job.poll() is not None:
                if job.returncode:
                    status("Ошибка операции. Подробности в журнале помощника.")
                else:
                    with (STATE / "operator.log").open("rb") as fd:
                        fd.seek(max(0, fd.seek(0, 2) - 4096))
                        lines = fd.read().decode(errors="replace").splitlines()
                    status(lines[-1][:300] if lines else "Операция завершена.")
                job = None
            try:
                client, _ = server.accept()
            except TimeoutError:
                continue
            with client:
                client.settimeout(2)
                try:
                    msg = client.makefile("rb").readline(128).decode("ascii").strip().split(" ")
                    token = hashlib.sha256((settings()["SECRET_KEY"] + ":operator").encode()).hexdigest()
                    if job or len(msg) != 2 or not secrets.compare_digest(msg[0], token) or msg[1] not in {"backup", "update", "rollback", "check"}:
                        client.sendall(b"no\n")
                        continue
                    with (STATE / "operator.log").open("wb") as log:
                        job = subprocess.Popen([sys.executable, str(ROOT / "scripts/manage.py"), msg[1]],
                                               cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                    status("Выполняется операция: " + msg[1])
                    client.sendall(b"ok\n")
                except (OSError, UnicodeError):
                    continue


if __name__ == "__main__":
    main()
