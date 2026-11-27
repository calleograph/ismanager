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
from threading import Event, Thread
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".runtime"
ENV = ROOT / ".env"
GIT = ["git", "-C", str(ROOT)]


class OperationReport(TypedDict, total=False):
    id: str
    action: str
    message: str
    state: str
    events: list[dict[str, str | int]]


operation: OperationReport = {}


def progress(message, *, state="running"):
    if operation:
        operation.update({"message": message, "state": state})
        operation["events"].append({"time": int(time.time()), "message": message})
        replace(STATE / "control/operation.json", json.dumps(operation, ensure_ascii=False), 0o644)


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


def image(service, tag=None):
    return f"{settings()['COMPOSE_PROJECT_NAME']}-{service}:{tag or revision()}"


def compose(*args, **kwargs):
    return run("docker", "compose", "--project-name", settings()["COMPOSE_PROJECT_NAME"], *args,
               env={**os.environ, **settings(), "APP_REVISION": revision()}, **kwargs)


def build(source=ROOT, tag=None):
    buildx = subprocess.run(["docker", "buildx", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if buildx:
        builder = ["docker", "buildx", "build", "--load", "--progress=plain"]
        env = dict(os.environ)
    else:
        print("Buildx недоступен. Собираем через прежний docker build. Если Docker отключил этот сборщик, установите плагин Buildx.", flush=True)
        builder = ["docker", "build"]
        env = {**os.environ, "DOCKER_BUILDKIT": "0"}
    for service, file in (("worker", "Dockerfile.worker"), ("web", "Dockerfile")):
        stage = "Сборка обработчика GigaAM" if service == "worker" else "Сборка веб-приложения и обезличивателя"
        print(stage, flush=True)
        progress(stage)
        torch_index = settings().get("TORCH_INDEX_URL") if service == "worker" else None
        args = ["--build-arg", "TORCH_INDEX_URL=" + torch_index] if torch_index else []
        run(*builder, *args, "-f", str(source / file), "-t", image(service, tag), str(source), env=env)


def report_model_preparation(finished, started):
    last = None
    while not finished.wait(5):
        try:
            raw = compose("exec", "-T", "web", "head", "-c", "1024", "/data/asr-status.json",
                          capture=True, stderr=subprocess.DEVNULL, timeout=4)
            state = json.loads(raw)
            label = state["label"]
            if state["time"] >= started and isinstance(label, str) and label != last:
                print(label, flush=True)
                last = label
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            continue  # The web container and status file appear during this same startup.


def start():
    progress("Запуск контейнеров и проверка готовности")
    cfg = settings()
    if cfg.get("APP_REVISION") != revision():
        save_config({**cfg, "APP_REVISION": revision()})
    print("Подготовка моделей GigaAM. При первой установке worker скачивает веса. Ожидаем готовность сервисов.", flush=True)
    finished = Event()
    reporter = Thread(target=report_model_preparation, args=(finished, time.time()), daemon=True)
    reporter.start()
    try:
        compose("up", "--no-build", "--pull", "never", "-d", "--wait", "--wait-timeout", "1800")
        print("Сервисы готовы.", flush=True)
    finally:
        finished.set()
        reporter.join()


def backup():
    progress("Создание резервной копии")
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
        manifest = full.extractfile(info)
        if manifest is None:
            raise ValueError("В архиве отсутствует манифест.")
        meta = json.load(manifest)
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
                data_info = full.getmember("data.tar.gz")
                if not data_info.isfile():
                    raise ValueError("В архиве отсутствует файл данных.")
                source = full.extractfile(data_info)
                if source is None:
                    raise ValueError("Не удалось прочитать данные из копии.")
                shutil.copyfileobj(source, data)
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
    progress("Проверка опубликованных версий в GitHub")
    git("fetch", "--tags", "origin", "main")
    tags = git("tag", "--merged", "FETCH_HEAD", "--list", "v*").splitlines()
    versions = [(tuple(map(int, tag[1:].split("."))), tag) for tag in tags if re.fullmatch(r"v\d+\.\d+\.\d+", tag)]
    if not versions:
        raise ValueError("В основной ветке пока нет релизного тега.")
    tag = max(versions)[1]
    replace(STATE / "control/release.json", json.dumps({"version": tag, "checked": int(time.time())}), 0o644)
    return tag


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
    tag = git("rev-parse", "--short=12", new)
    cached = rollback and all(subprocess.run(
        ["docker", "image", "inspect", image(service, tag)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0 for service in ("web", "worker"))
    if not cached:
        # Build the target in isolation. The live checkout, volume and containers still serve the current release.
        with tempfile.TemporaryDirectory(prefix="build-", dir=STATE) as work:
            source = Path(work) / "source"
            git("worktree", "add", "--detach", str(source), new)
            try:
                build(source, tag)
            except (OSError, subprocess.SubprocessError) as err:
                raise ValueError("Сборка остановилась до переключения. Прежняя версия продолжает работу. Проверьте вывод сборки в журнале помощника или терминале.") from err
            finally:
                git("worktree", "remove", str(source))

    pending = STATE / "pending.json"
    journal = {"old": old, "new": new}
    replace(pending, json.dumps(journal))
    try:
        progress("Приостановка сервисов для переключения версии")
        replace(STATE / "control/maintenance", "maintenance", 0o644)
        compose("stop")
        snapshot = backup()
        progress("Переключение на подготовленную версию")
        git("switch", "--detach", new)
        journal.update(starting=True, snapshot=snapshot.name)
        replace(pending, json.dumps(journal))
        start()
    except BaseException:
        progress("Ошибка переключения. Возвращаем предыдущую версию")
        recover_version()
        progress("Предыдущая версия снова работает")
        raise
    replace(STATE / "previous", old)
    pending.unlink()
    return f"Установлена версия {(ROOT / 'VERSION').read_text().strip()}. Проверка готовности пройдена. Копия {snapshot.name}."


def operate(action, archive=None):
    if action == "install":
        build()
        start()
        # fd is inherited from the local installer. Web workers never log the password.
        compose("exec", "-T", "web", "flask", "--app", "app", "admin-password", "--if-missing")
        return "Установка завершена."
    if action == "check":
        tag = latest()
        installed = (ROOT / "VERSION").read_text().strip()
        return (f"Установлена актуальная версия {tag}." if tag == "v" + installed
                else f"Последний релиз {tag}. Установлена версия {installed}.")
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
        if args.command in {"check", "update", "rollback", "backup"}:
            operation.update({"id": secrets.token_hex(8), "action": args.command, "events": []})
            progress("Команда принята")
        if changing and args.command not in {"update", "rollback"}:
            replace(marker, "maintenance", 0o644)
        try:
            result = operate(args.command, args.archive)
            progress(result, state="done")
            print(result)
        except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, KeyError) as err:
            # Subprocess arguments and stdout can contain installation secrets. Only controlled messages enter the web UI.
            detail = str(err) if type(err) is ValueError else "Проверьте журнал .runtime/operator.log или вывод команды на сервере."
            recovered = "Предыдущая версия снова работает. " if operation.get("message") == "Предыдущая версия снова работает" else ""
            progress("Операция не завершена. " + recovered + detail, state="error")
            raise
        finally:
            if changing and not (STATE / "pending.json").exists():
                marker.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError, KeyError) as err:
        print(f"Операция не завершена: {err}", file=sys.stderr)
        sys.exit(1)
