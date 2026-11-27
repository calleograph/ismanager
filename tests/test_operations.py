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
