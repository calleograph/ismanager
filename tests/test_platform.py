import re
import secrets

import pytest

from app import create_app
from app.db import get_db


@pytest.fixture
def app(tmp_path):
    return create_app(dict(TESTING=True, DATA_DIR=str(tmp_path), SECRET_KEY=secrets.token_hex(32)))


def token(resp):
    return re.search(rb'name="csrf_token" value="([^"]+)"', resp.data).group(1).decode()


def first_login(app):
    runner = app.test_cli_runner()
    bootstrap = runner.invoke(args=["admin-password", "--if-missing"])
    assert bootstrap.exit_code == 0
    assert not runner.invoke(args=["admin-password", "--if-missing"]).output.strip()
    c = app.test_client()
    pw = bootstrap.output.strip()
    resp = c.post("/login", data=dict(username="admin", password=pw, csrf_token=token(c.get("/login"))))
    assert resp.location.endswith("/account")
    assert c.get("/passwords/").location.endswith("/account")
    new = secrets.token_urlsafe(30) + "aa1"
    c.post("/account", data=dict(action="password", current=pw, new=new, repeat=new, csrf_token=token(c.get("/account"))))
    return c, new


def test_platform_and_revocation(app):
    c, _ = first_login(app)
    for path in ("/", "/account", "/transcription/", "/redaction/", "/passwords/", "/threats/", "/admin/", "/admin/directory/"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert r.headers["Cache-Control"] == "no-store"
    assert c.post("/logout").status_code == 400
    with c.session_transaction() as s:
        assert "sid" in s
    c.post("/logout", data={"csrf_token":token(c.get("/account"))})
    assert c.get("/admin/").status_code == 302
    with app.app_context():
        assert get_db().execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_login_rate_limit(app):
    c = app.test_client()
    for i in range(13):
        response = c.post("/login", data=dict(username="missing", password="incorrect", csrf_token=token(c.get("/login"))))
    assert response.status_code == 429


def test_totp_and_reset(app, monkeypatch):
    import pyotp
    from app import auth
    c, pw = first_login(app)
    c.post("/account", data=dict(action="prepare", csrf_token=token(c.get("/account"))))
    page = c.get("/account")
    seed = re.search(rb"<code>([A-Z2-7]+)</code>", page.data).group(1).decode()
    clock = int(auth.time.time() // 30) * 30
    code = pyotp.TOTP(seed).at(clock)
    c.post("/account", data=dict(action="enable", code=code, csrf_token=token(page)))
    c.post("/logout", data=dict(csrf_token=token(c.get("/account"))))
    def login(otp):
        return c.post("/login", data=dict(username="admin", password=pw, code=otp, csrf_token=token(c.get("/login"))))
    assert login(code).status_code == 401
    monkeypatch.setattr(auth.time, "time", lambda: clock + 35)
    assert login(pyotp.TOTP(seed).at(clock + 35)).status_code == 302
    assert c.get("/admin/").status_code == 200
    app.test_cli_runner().invoke(args=["admin-password"])
    assert c.get("/admin/").status_code == 302
