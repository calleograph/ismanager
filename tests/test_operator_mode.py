import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from app import create_app
from test_platform import first_login, token


ROOT = Path(__file__).resolve().parents[1]


def test_running_v04_helper_survives_web_upgrade(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROL_DIR", str(tmp_path))
    secret = secrets.token_hex(32)
    signature = hashlib.sha256((secret + ":operator").encode()).hexdigest()
    app = create_app(dict(DATA_DIR=tmp_path / "data", SECRET_KEY=secret, TESTING=True))
    client, _ = first_login(app)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(tmp_path / "operator.sock"))
        server.listen(2)
        server.settimeout(5)

        def v04():
            for expected, response in (("ping", b"no\n"), ("check", b"ok\n")):
                connection, _ = server.accept()
                with connection:
                    assert connection.makefile("rb").readline(128).decode().strip() == f"{signature} {expected}"
                    connection.sendall(response)

        with ThreadPoolExecutor(max_workers=1) as pool:
            calls = pool.submit(v04)
            page = client.get("/admin/")
            assert "помощник предыдущей версии" in page.get_data(as_text=True)
            assert 'name="operation"' in page.get_data(as_text=True)
            assert client.post("/admin/maintenance", data={"csrf_token": token(page), "operation": "check"}).status_code == 302
            calls.result()


def test_operator_only_skips_docker_buildx_and_apt(tmp_path):
    target = tmp_path / "instance"
    (target / "scripts").mkdir(parents=True)
    (target / ".env").touch()
    (target / "scripts/install_operator.py").write_text("print('operator only')")
    result = subprocess.run(["bash", str(ROOT / "install.sh"), "--dir", str(target), "--operator"],
                            capture_output=True, text=True, check=True, env={**os.environ, "PATH": "/usr/bin:/bin"})
    assert result.stdout.strip() == "operator only"


def test_operator_cli_and_live_socket_lifecycle(tmp_path, monkeypatch):
    instance = tmp_path / "server"
    shutil.copytree(ROOT / "scripts", instance / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    control = instance / ".runtime/control"
    control.mkdir(parents=True)
    monkeypatch.setenv("CONTROL_DIR", str(control))
    secret = secrets.token_hex(32)
    (instance / ".env").write_text(f"SECRET_KEY={secret}\nCOMPOSE_PROJECT_NAME=sample\n")
    (instance / "VERSION").write_text("1.0.0")
    def git(*args):
        subprocess.run(["git", "-C", str(instance), *args], check=True, capture_output=True)
    git("init", "-b", "main")
    git("add", "VERSION")
    git("-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture")
    git("tag", "v1.0.0")
    git("remote", "add", "origin", str(instance))
    path = instance / "scripts/manage.py"
    checked = subprocess.run([sys.executable, str(path), "check"], text=True, check=True, capture_output=True)
    assert "v1.0.0" in checked.stdout
    app = create_app(dict(DATA_DIR=tmp_path / "data", SECRET_KEY=secret, TESTING=True))
    guest = app.test_client()
    assert guest.get("/admin/system-metrics").location == "/login"
    client, _ = first_login(app)
    assert set(client.get("/admin/system-metrics").json) == {"cpu", "cores", "total", "available", "worker"}
    admin = client.get("/admin/")
    assert 'name="operation"' not in admin.get_data(as_text=True)
    assert "python3 scripts/manage.py update" in admin.get_data(as_text=True)
    (control / "operator-disabled").touch()
    assert "отключено при установке" in client.get("/admin/").get_data(as_text=True)
    (control / "operator-disabled").unlink()
    helper = subprocess.Popen([sys.executable, str(instance / "scripts/host_helper.py")], cwd=instance)
    try:
        until = time.monotonic() + 10
        while not (control / "operator.sock").is_socket() and time.monotonic() < until:
            time.sleep(.05)
        assert (control / "operator.sock").is_socket()
        admin = client.get("/admin/")
        assert 'name="operation"' in admin.get_data(as_text=True)
        client.post("/admin/maintenance", data={"csrf_token": token(admin), "operation": "check"})
        until = time.monotonic() + 10
        while time.monotonic() < until:
            state = control / "status.json"
            if state.exists() and "v1.0.0" in json.loads(state.read_text())["message"]:
                break
            time.sleep(.1)
        assert "v1.0.0" in json.loads(state.read_text())["message"]
        (control / "operator-disabled").touch()
        # An explicitly disabled installation also refuses signed commands on the socket.
        with socket.socket(socket.AF_UNIX) as conn:
            conn.connect(str(control / "operator.sock"))
            signed = hashlib.sha256((secret + ":operator").encode()).hexdigest()
            conn.sendall((signed + " check\n").encode())
            assert conn.recv(32) == b"disabled\n"
    finally:
        helper.terminate()
        helper.wait(timeout=10)
