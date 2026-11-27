import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import time

import pytest
from flask import Flask

from app.auth import protected
from app import watch_storage as ws


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("path", ["../x", "x/../../file", "C:/Windows", "\\\\server\\share", "a:b",
                                  "a/../x", "test/.", "NUL.txt", "a\nname", "dir/ab."])
def test_relative_paths(path):
    with pytest.raises(ValueError):
        ws.relative_folder(path)


def test_base_folder_and_symlink_boundaries(tmp_path):
    base = tmp_path / "mount"
    other = tmp_path / "other"
    base.mkdir()
    other.mkdir()
    (other / "private.wav").write_bytes(b"private")
    (base / "external").symlink_to(other, target_is_directory=True)
    (base / "audio.wav").symlink_to(other / "private.wav")
    (base / "result.txt").symlink_to(other / "private.wav")
    os.mkfifo(base / "feed.wav")
    with pytest.raises(ValueError):
        ws.validate_resource({"kind":"local", "path":str(other)}, base)
    with pytest.raises(OSError), ws.open_storage({"kind":"local","path":"external"}, "", base):
        pass
    with ws.open_storage({"kind":"local", "path":str(base)}, "", base) as directory:
        directory.probe()
        assert not list(directory.list_media())
        with pytest.raises(ValueError):
            directory.read_text("result.txt")
        with pytest.raises((OSError, ValueError)):
            directory.publish_text("result.txt", "new")
        assert (other / "private.wav").read_bytes() == b"private"
    with ws.open_storage({"kind":"local","path":"audio"}, "", base, folder="save/new", create=True) as nested:
        nested.publish_text("выход.txt", "готово")
    assert (base / "audio/save/new/выход.txt").read_text() == "готово"


def test_copy_delete_and_restore_after_change(tmp_path, monkeypatch):
    root = tmp_path / "dir"
    root.mkdir()
    source = root / "вход.wav"
    source.write_bytes(b"original")
    dest = tmp_path / "copy"
    with ws.open_storage({"kind":"local","path":""}, "", root) as store:
        snap, = store.list_media()
        assert store.copy_source(snap, dest) == digest(b"original")
        with pytest.raises(FileExistsError):
            store.copy_source(snap, dest)
        with pytest.raises(ValueError):
            store.copy_source(snap, tmp_path / "large", max_bytes=3)
        assert not (tmp_path / "large").exists()
        with pytest.raises(ws.SourceChangedError):
            store.delete_source(snap, "0" * 64)
        assert source.read_bytes() == b"original"
        snap = store.stat(source.name)
        move = ws._move
        def replace_before_claim(src_fd, src, dst_fd, dst):
            if src == source.name:
                newcomer = root / "newcomer"
                newcomer.write_bytes(b"new data")
                os.replace(newcomer, source)
            return move(src_fd, src, dst_fd, dst)
        with monkeypatch.context() as active:
            active.setattr(ws, "_move", replace_before_claim)
            with pytest.raises(ws.SourceChangedError):
                store.delete_source(snap, digest(b"original"))
        assert source.read_bytes() == b"new data"
        with pytest.raises(ws.SourceChangedError):
            store.copy_source(snap, tmp_path / "changed")
        snap = store.stat(source.name)
        assert store.delete_source(snap, digest(b"new data"))
        assert not store.delete_source(snap, digest(b"new data"))
        assert not source.exists()


def test_publication_and_concurrent_arrival(tmp_path, monkeypatch):
    with ws.open_storage({"kind":"local","path":""}, "", tmp_path) as store:
        store.publish_text("отчёт.txt", "первая версия")
        first = store.stat("отчёт.txt")
        store.publish_text("отчёт.txt", "первая версия")
        assert first == store.stat("отчёт.txt")
        before = digest("первая версия".encode())
        with pytest.raises(FileExistsError):
            store.publish_text("отчёт.txt", "чужая версия")
        store.publish_text("отчёт.txt", "вторая версия", previous_sha256=before)
        assert store.read_text("отчёт.txt") == "вторая версия"
        backup, = tmp_path.glob("*.previous-*.txt")
        assert backup.read_text() == "первая версия"
        old_move = ws._Local.move
        def concurrent_writer(self, old, new):
            old_move(self, old, new)
            if old == "отчёт.txt":
                (tmp_path / "отчёт.txt").write_text("пользователь")
        monkeypatch.setattr(ws._Local, "move", concurrent_writer)
        with pytest.raises(FileExistsError):
            store.publish_text("отчёт.txt", "третья версия", previous_sha256=digest("вторая версия".encode()))
        assert store.read_text("отчёт.txt") == "пользователь"
        assert {path.read_text() for path in tmp_path.glob("*.previous-*.txt")} == {"первая версия", "вторая версия"}
        assert not list(tmp_path.glob("*.part"))


@pytest.mark.skipif(os.getenv("ISMANAGER_LIVE_SMB") != "1", reason="requires a local Docker daemon")
def test_live_samba(tmp_path):
    """ISMANAGER_LIVE_SMB=1 python -m pytest -q tests/test_watch_storage.py"""
    name = "ismanager-smb-" + secrets.token_hex(8)
    password = secrets.token_hex(24)
    def docker(*args, **kwargs):
        return subprocess.run(["docker", *args], check=True, stdout=subprocess.PIPE, text=True, **kwargs).stdout.strip()
    docker("network", "create", name)
    try:
        docker("run", "-d", "--name", name, "--network", name, "-p", "127.0.0.1::445", "--tmpfs",
               "/data:rw,mode=0777,size=32m", "-e", "USER1", "-e", "SHARE1=media;/data;yes;no;no;analyst",
               "-e", "WORKGROUP=EXAMPLE", "dperson/samba:latest", env={**os.environ, "USER1":"analyst;" + password})
        port = int(docker("port", name, "445/tcp").rsplit(":", 1)[1])
        app = Flask(__name__)
        app.secret_key = secrets.token_hex(32)
        with app.app_context():
            cfg = dict(kind="smb", server="127.0.0.1", share="media", port=port, username="analyst",
                       domain="EXAMPLE", password=protected(password))
            invalid = dict(cfg, password=protected("incorrect"))
        for attempt in range(60):
            try:
                with ws.open_storage(cfg, app.secret_key) as store:
                    store.probe()
                break
            except OSError:
                if attempt == 59:
                    raise
                time.sleep(1)
        docker("exec",name,"sh","-c","printf 'sample' > /data/test.wav && chmod 666 /data/test.wav")
        with ws.open_storage(cfg, app.secret_key) as store:
            with pytest.raises(OSError), ws.open_storage(invalid, app.secret_key) as wrong:
                wrong.probe()
            snap, = store.list_media()
            assert store.copy_source(snap, tmp_path / "input") == digest(b"sample")
            assert (tmp_path / "input").read_bytes() == b"sample"
            with pytest.raises(ws.SourceChangedError):
                store.delete_source(snap, digest(b"wrong"))
            assert store.delete_source(snap, digest(b"sample"))
            assert not store.delete_source(snap, digest(b"sample"))
        with ws.open_storage(cfg, app.secret_key, folder="архив/готово", create=True) as out:
            out.publish_text("текст.txt", "первая")
            out.publish_text("текст.txt", "первая")
            with pytest.raises(FileExistsError):
                out.publish_text("текст.txt", "посторонняя")
            out.publish_text("текст.txt", "вторая", previous_sha256=digest("первая".encode()))
            assert out.read_text("текст.txt") == "вторая"
        with ws.open_storage(cfg, app.secret_key, folder="архив/готово", create=True) as again:
            assert again.read_text("текст.txt") == "вторая"
    finally:
        subprocess.run(["docker", "rm", "-fv", name], capture_output=True)
        subprocess.run(["docker", "network", "rm", name], capture_output=True)


def test_open_writer_prevents_copy_and_removal(tmp_path):
    source = tmp_path / "held.wav"
    source.write_bytes(b"before")
    with ws.open_storage({"kind":"local","path":""}, "", tmp_path) as store:
        initial = store.stat(source.name)
        with source.open("ab") as recorder:
            with pytest.raises(ws.SourceChangedError):
                store.copy_source(initial, tmp_path / "partial")
            assert not (tmp_path / "partial").exists()
            with pytest.raises(ws.SourceChangedError):
                store.delete_source(initial, digest(b"before"))
            assert store.stat(source.name) == initial
            recorder.write(b" after")
        later = store.stat(source.name)
        assert store.copy_source(later, tmp_path / "complete") == digest(b"before after")
        assert store.delete_source(later, digest(b"before after"))


def test_unsupported_lease_retains_source(tmp_path, monkeypatch):
    source = tmp_path / "foreign.wav"
    source.write_bytes(b"bytes")
    real = ws.fcntl.fcntl
    def unsupported(fd, cmd, arg=0):
        if cmd == ws.fcntl.F_SETLEASE:
            raise PermissionError(ws.errno.EPERM, "not the owning uid")
        return real(fd, cmd, arg)
    monkeypatch.setattr(ws.fcntl, "fcntl", unsupported)
    with ws.open_storage({"kind":"local","path":""}, "", tmp_path) as store:
        snap = store.stat(source.name)
        sha = store.copy_source(snap, tmp_path / "copied")
        with pytest.raises(ws.SourceRetainedError):
            store.delete_source(snap, sha)
        assert source.read_bytes() == b"bytes" and store.stat(source.name) == snap


def test_busy_text_is_preserved(tmp_path):
    with ws.open_storage({"kind":"local","path":""}, "", tmp_path) as store:
        store.publish_text("note.txt", "original")
        with (tmp_path / "note.txt").open("ab") as editor:
            with pytest.raises(FileExistsError):
                store.publish_text("note.txt", "new", previous_sha256=digest(b"original"))
            editor.write(b" edited")
        assert store.read_text("note.txt") == "original edited"
        assert not list(tmp_path.glob("*.previous-*.txt"))


def test_endpoint_restriction_applies_before_smb_connect(monkeypatch):
    import smbclient
    from smbprotocol.connection import Connection
    monkeypatch.setattr(Connection, "connect", lambda *args, **kwargs: pytest.fail("unexpected connection"))
    with pytest.raises(PermissionError):
        smbclient.register_session("other.test", username="user", password="test",
                                   connection_cache=ws._ServerConnections("allowed.test", 445))


def test_public_recovery_directory_retains_source(tmp_path):
    (tmp_path / "t.wav").write_bytes(b"x")
    quarantine = tmp_path / "IS Manager - recovery"
    quarantine.mkdir()
    quarantine.chmod(0o777)
    with ws.open_storage({"kind":"local","path":""}, "", tmp_path) as store:
        snap = store.stat("t.wav")
        with pytest.raises(ws.SourceRetainedError):
            store.delete_source(snap, digest(b"x"))
        assert store.stat("t.wav") == snap
