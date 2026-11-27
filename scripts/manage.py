#!/usr/bin/env python3
"""Host-side release, backup and restore commands. Requires Python 3.10+."""
import argparse
import fcntl
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".runtime"
ENV = ROOT / ".env"
GIT = ["git", "-C", str(ROOT)]


def run(*args, capture=False, **kwargs):
    if capture:
        kwargs["stdout"] = subprocess.PIPE
    result = subprocess.run(args, cwd=ROOT, check=True, **kwargs)
    return result.stdout.decode().strip() if capture else None


def settings():
    return dict(line.split("=", 1) for line in ENV.read_text().splitlines() if line and not line.startswith("#"))


def replace(path, content, mode=0o600):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as fd:
        fd.write(content.encode())
        os.fchmod(fd.fileno(), mode)
    os.replace(fd.name, path)


def save_config(cfg):
    replace(ENV, "".join(f"{key}={value}\n" for key, value in cfg.items()))


def git(*args):
    return run(*GIT, *args, capture=True)


def revision():
    return git("rev-parse", "--short=12", "HEAD")


def image(service):
    return f"{settings()['COMPOSE_PROJECT_NAME']}-{service}:{revision()}"


def compose(*args, **kwargs):
    return run("docker", "compose", "--project-name", settings()["COMPOSE_PROJECT_NAME"], *args,
               env={**os.environ, **settings(), "APP_REVISION": revision()}, **kwargs)


def build():
    for service, file in (("worker", "Dockerfile.worker"), ("web", "Dockerfile")):
        source = settings().get("TORCH_INDEX_URL") if service == "worker" else None
        args = ["--build-arg", "TORCH_INDEX_URL=" + source] if source else []
        run("docker", "build", *args, "-f", file, "-t", image(service), ".")


def start():
    cfg = settings()
    if cfg.get("APP_REVISION") != revision():
        save_config({**cfg, "APP_REVISION": revision()})
    compose("up", "--no-build", "--pull", "never", "-d", "--wait", "--wait-timeout", "1800")


def backup():
    STATE.joinpath("backups").mkdir(mode=0o700, exist_ok=True)
    target = STATE / "backups" / (time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3) + ".tar")
    manifest = json.dumps({"format": 1, "revision": git("rev-parse", "HEAD"), "key": settings()["SECRET_KEY"]}).encode()
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        data = Path(tmp) / "data.tar.gz"
        with data.open("wb") as fd:
            compose("run", "--rm", "-T", "--no-deps", "--entrypoint", "tar", "web", "--exclude=./redaction-batch", "-czf", "-", "-C", "/data", ".", stdout=fd)
        with tarfile.open(Path(tmp) / "archive", "w") as out:
            header = tarfile.TarInfo("manifest.json")
            header.mode = 0o600
            header.size = len(manifest)
            out.addfile(header, io.BytesIO(manifest))
            out.add(data, arcname="data.tar.gz")
        os.replace(Path(tmp) / "archive", target)
    return target


def restore_archive(archive):
    cfg = settings()
    with tarfile.open(archive, "r:") as full:
        info = full.getmember("manifest.json")
        if not info.isfile() or info.size > 4096:
            raise ValueError("Некорректный манифест копии.")
        meta = json.load(full.extractfile(info))
        if meta.get("format") != 1 or not re.fullmatch(r"[a-zA-Z0-9_-]{32,128}", meta.get("key", "")):
            raise ValueError("Неизвестный формат копии.")
        volume = cfg["COMPOSE_PROJECT_NAME"] + "_restore_" + secrets.token_hex(6)
        run("docker", "volume", "create", "--label", "com.docker.compose.project=" + cfg["COMPOSE_PROJECT_NAME"],
            "--label", "com.docker.compose.volume=data", volume, capture=True)
        # Extract only data files in a fresh container volume. The old volume stays intact.
        extractor = """import os,tarfile,sys,sqlite3
os.chdir('/data')
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|gz') as archive:
    for member in archive:
        if not (member.isfile() or member.isdir()): raise ValueError('unexpected archive member')
        archive.extract(member,filter='data')
db=sqlite3.connect('file:ismanager.sqlite3?mode=rw',uri=True)
assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
assert db.execute("SELECT count(*) FROM users WHERE identity='local:admin'").fetchone()[0]==1
with db: db.execute("DELETE FROM sessions")
"""
        # Docker initializes a new volume from the image's /data ownership.
        try:
            with tempfile.TemporaryFile(dir=STATE) as data:
                shutil.copyfileobj(full.extractfile("data.tar.gz"), data)
                data.seek(0)
                run("docker", "run", "-i", "--rm", "--network", "none", "-v", f"{volume}:/data",
                    "--entrypoint", "python", image("web"), "-c", extractor, stdin=data)
            save_config({**cfg, "SECRET_KEY": meta["key"], "DATA_VOLUME": volume})
        except BaseException:
            if settings().get("DATA_VOLUME") != volume:
                run("docker", "volume", "rm", volume, capture=True)
            raise
    return cfg


def latest():
    git("fetch", "--tags", "origin", "main")
    tags = git("tag", "--merged", "FETCH_HEAD", "--list", "v*").splitlines()
    versions = [(tuple(map(int, tag[1:].split("."))), tag) for tag in tags if re.fullmatch(r"v\d+\.\d+\.\d+", tag)]
    if not versions:
        raise ValueError("В основной ветке пока нет релизного тега.")
    return max(versions)[1]


def recover_version():
    pending = STATE / "pending.json"
    journal = json.loads(pending.read_text())
    old = journal["old"]
    # A new service may already have migrated SQLite. Keep its volume and restore the snapshot separately.
    compose("stop")
    if git("rev-parse", "HEAD") != old:
        git("switch", "--detach", old)
    if journal.get("starting"):
        restore_archive(STATE / "backups" / journal["snapshot"])
    start()
    pending.unlink()


def change_version(target, *, rollback=False):
    if git("status", "--porcelain"):
        raise ValueError("В рабочей копии есть незакоммиченные правки.")
    old = git("rev-parse", "HEAD")
    new = git("rev-parse", "--verify", target + "^{commit}")
    if new == old:
        return "Уже установлена актуальная версия."
    if rollback and settings().get("ACCESS_MODE", "https") != "https" and not git("ls-tree", "--name-only", new, "app/network.py"):
        raise ValueError("Предыдущий релиз поддерживает только прямой HTTPS. Выполните ./install.sh --access https перед откатом.")
    pending = STATE / "pending.json"
    journal = {"old": old, "new": new}
    replace(pending, json.dumps(journal))
    try:
        compose("stop")
        snapshot = backup()
        git("switch", "--detach", new)
        cached = rollback and all(subprocess.run(
            ["docker", "image", "inspect", image(service)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0 for service in ("web", "worker"))
        if not cached:
            build()
        journal.update(starting=True, snapshot=snapshot.name)
        replace(pending, json.dumps(journal))
        start()
    except BaseException:
        recover_version()
        raise
    replace(STATE / "previous", old)
    pending.unlink()
    return f"Установлена {new[:12]}. Копия {snapshot.name}."


def operate(action, archive=None):
    if action == "install":
        build()
        start()
        # fd is inherited from the local installer. Web workers never log the password.
        compose("exec", "-T", "web", "flask", "--app", "app", "admin-password", "--if-missing")
        return "Установка завершена."
    if action == "check":
        return "Последний релиз " + latest() + ". Установлена версия " + (ROOT / "VERSION").read_text().strip() + "."
    if action == "update":
        return change_version(latest())
    if action == "rollback":
        if not (STATE / "previous").exists():
            raise ValueError("Предыдущая установленная версия отсутствует.")
        return change_version((STATE / "previous").read_text().strip(), rollback=True)
    if action == "backup":
        compose("stop")
        try:
            path = backup()
        finally:
            start()
        return "Копия сохранена: " + str(path)
    if action == "restore":
        if not archive:
            raise ValueError("Укажите путь к архиву.")
        old_cfg = settings()
        compose("stop")
        try:
            backup()
            restore_archive(archive)
            start()
        except BaseException:
            save_config(old_cfg)
            start()
            raise
        return "Данные восстановлены. Прежний том сохранён: " + old_cfg["DATA_VOLUME"]
    if action == "start":
        start()
    if action == "status":
        compose("ps")
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("install", "start", "check", "update", "rollback", "backup", "restore", "status", "recover"))
    parser.add_argument("archive", nargs="?")
    args = parser.parse_args()
    os.umask(0o077)
    with (STATE / "operation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = STATE / "control" / "maintenance"
        if (STATE / "pending.json").exists():
            recover_version()
            marker.unlink(missing_ok=True)
        if args.command == "recover":
            if marker.exists():
                start()
                marker.unlink()
            return
        changing = args.command in {"update", "rollback", "backup", "restore", "start", "install"}
        if changing:
            replace(marker, "maintenance", 0o644)
        try:
            print(operate(args.command, args.archive))
        finally:
            if changing and not (STATE / "pending.json").exists():
                marker.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError, KeyError) as err:
        print(f"Операция не завершена: {err}", file=sys.stderr)
        sys.exit(1)
