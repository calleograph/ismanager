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
