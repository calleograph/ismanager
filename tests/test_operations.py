import json
from unittest.mock import Mock

from scripts import manage


def test_interrupted_release_restores_earlier_checkout(tmp_path, monkeypatch):
    monkeypatch.setattr(manage, "STATE", tmp_path)
    previous = "1" * 40
    pending = tmp_path / "pending.json"
    pending.write_text(json.dumps({"old": previous, "new": "2"*40, "starting": True, "snapshot": "before.tar"}))
    git = Mock(return_value="2"*40)
    start, restore = Mock(), Mock()
    monkeypatch.setattr(manage, "git", git)
    monkeypatch.setattr(manage, "compose", Mock())
    monkeypatch.setattr(manage, "start", start)
    monkeypatch.setattr(manage, "restore_archive", restore)
    manage.recover_version()
    git.assert_any_call("switch", "--detach", previous)
    restore.assert_called_once_with(tmp_path / "backups/before.tar")
    start.assert_called_once()
    assert not pending.exists()


def test_marker_blocks_writes_during_update(tmp_path, monkeypatch):
    from app import create_app
    import secrets
    app = create_app(dict(DATA_DIR=tmp_path, SECRET_KEY=secrets.token_hex(32), TESTING=True))
    monkeypatch.setenv("CONTROL_DIR", str(tmp_path))
    (tmp_path / "maintenance").touch()
    client = app.test_client()
    assert client.get("/healthz").status_code == 200
    assert client.get("/login").status_code == 503
    assert client.post("/passwords/generate").status_code == 503


def test_backup_stream_is_forwarded(tmp_path):
    import sys
    from scripts.manage import run
    output = tmp_path / "stream"
    with output.open("wb") as fd:
        run(sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'archive')", stdout=fd)
    assert output.read_bytes() == b"archive"


def test_rollback_from_http_to_tls_only_release_keeps_running_instance(monkeypatch):
    import pytest
    monkeypatch.setattr(manage, "git", Mock(side_effect=["", "current", "previous", ""]))
    monkeypatch.setattr(manage, "settings", lambda: {"ACCESS_MODE": "http"})
    compose = Mock()
    monkeypatch.setattr(manage, "compose", compose)
    with pytest.raises(ValueError, match="--access https"):
        manage.change_version("v0.1.3", rollback=True)
    compose.assert_not_called()


def test_startup_reports_changed_model_download_progress(monkeypatch, capsys):
    event = Mock()
    event.wait.side_effect = [False, False, False, True]
    readings = [(2, "Старая запись"), (9, "Загружается GigaAM · 16 МиБ"), (12, "Загружается GigaAM · 16 МиБ")]
    monkeypatch.setattr(manage, "compose", Mock(side_effect=[json.dumps(dict(time=t,label=label)) for t,label in readings]))
    manage.report_model_preparation(event, started=5)
    assert capsys.readouterr().out.splitlines() == ["Загружается GigaAM · 16 МиБ"]


def test_failed_staged_build_never_stops_live_release(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setattr(manage, "STATE", tmp_path)
    git = Mock(side_effect=["", "old", "new", "aabbcc", "", ""])
    monkeypatch.setattr(manage, "git", git)
    monkeypatch.setattr(manage, "build", Mock(side_effect=OSError("build unavailable")))
    stop = Mock()
    monkeypatch.setattr(manage, "compose", stop)
    with pytest.raises(ValueError, match="Прежняя версия продолжает работу"):
        manage.change_version("v1.0.0")
    stop.assert_not_called()
    assert not any(call.args[:1] == ("switch",) for call in git.call_args_list)
    assert not (tmp_path / "pending.json").exists() and not (tmp_path / "control/maintenance").exists()


def test_progress_requires_admin_through_maintenance(tmp_path, monkeypatch):
    import secrets
    from app import create_app
    from test_platform import first_login

    app = create_app(dict(DATA_DIR=tmp_path / "data", SECRET_KEY=secrets.token_hex(32), TESTING=True))
    monkeypatch.setenv("CONTROL_DIR", str(tmp_path))
    client, _ = first_login(app)
    (tmp_path / "maintenance").touch()
    (tmp_path / "operation.json").write_text(json.dumps(dict(id="one", state="running", message="Сборка образа", events=[])))
    route = "/admin/maintenance/status"
    assert app.test_client().get(route).location == "/login"
    assert client.get(route).json["report"]["message"] == "Сборка образа"
    response = client.get("/admin/")
    assert response.status_code == 503 and 'http-equiv="refresh"' not in response.get_data(as_text=True)
    assert client.post("/admin/maintenance", data={"operation":"check"}).status_code == 503


def test_build_uses_staged_files_and_target_tags(tmp_path, monkeypatch):
    run = Mock()
    monkeypatch.setattr(manage, "run", run)
    monkeypatch.setattr(manage, "settings", lambda: {"COMPOSE_PROJECT_NAME":"fixture","TORCH_INDEX_URL":"https://example.invalid/torch"})
    monkeypatch.setattr(manage.subprocess, "run", Mock(return_value=Mock(returncode=0)))
    manage.build(tmp_path, "1234")
    assert len(run.call_args_list) == 2
    for call, service, file in zip(run.call_args_list, ["worker","web"], ["Dockerfile.worker","Dockerfile"]):
        assert call.args[-5:] == ("-f", str(tmp_path / file), "-t", "fixture-" + service + ":1234", str(tmp_path))
