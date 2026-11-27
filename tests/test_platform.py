import json
import re
import secrets

import pytest

from app import create_app
from app.db import get_db


@pytest.fixture
def app(tmp_path):
    return create_app(dict(TESTING=True, DATA_DIR=str(tmp_path), SECRET_KEY=secrets.token_hex(32)))


def token(resp):
    return re.search(rb'name="csrf-token" content="([^"]+)"', resp.data).group(1).decode()


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


def test_form_errors_for_browser_and_json(app):
    client = app.test_client()
    client.get("/passwords/")
    headers = {"Accept": "application/json"}
    expired = client.post("/passwords/generate", headers=headers)
    assert expired.status_code == 400 and "Форма устарела" in expired.json["error"]
    oversized = client.post("/passwords/generate", data={"phrase": "a" * 13000}, headers=headers)
    assert oversized.status_code == 413 and "пяти слов" in oversized.json["error"]
    html = client.post("/passwords/generate", headers={"Accept": "*/*"})
    assert html.status_code == 400 and "К генератору паролей" in html.get_data(as_text=True)
    method = client.get("/passwords/generate", headers=headers)
    assert method.status_code == 405 and "POST" in method.headers["Allow"]


def test_password_change_shows_which_field_to_correct(app):
    client, password = first_login(app)
    proposed = secrets.token_urlsafe(20) + "a1"
    for current, new, repeat, field, hint in [
        (password, "short", "short", "new", "от 12 до 1024"),
        (password, "a" * 16, "a" * 16, "new", "второй группы"),
        (password, password, password, "new", "отличается"),
        (password, proposed, "different", "repeat", "различаются"),
        ("wrong", proposed, proposed, "current", "действующий пароль"),
    ]:
        response = client.post("/account", data=dict(action="password", current=current, new=new,
                               repeat=repeat, csrf_token=token(client.get("/account"))))
        html = response.get_data(as_text=True)
        assert response.status_code == 422 and hint in html
        assert f'name="{field}" aria-invalid="true"' in html
        assert password not in html and proposed not in html
    assert client.get("/admin/").status_code == 200


def test_admin_recording_queue_and_worker_heartbeat(app, tmp_path):
    from app.worker import status

    client, _ = first_login(app)
    assert "Нет связи с обработчиком" in client.get("/admin/").get_data(as_text=True)
    with app.app_context():
        db = get_db()
        owner = db.execute("INSERT INTO users(identity,username,display_name,admin) VALUES ('source','u','u',0)").lastrowid
        db.executemany("INSERT INTO transcripts(id,owner,filename,status) VALUES (?,?,?,?)",
                       [(str(i), owner, "private.wav", state)
                        for i, state in enumerate(("queued", "queued", "running", "done", "failed"))])
        db.commit()
    label = "GigaAM v3 E2E RNNT готова к работе"
    status(tmp_path, label, True)
    page = client.get("/admin/").get_data(as_text=True)
    assert label in page
    assert "Записей в очереди — 2." in page
    assert "private.wav" not in page
    path = tmp_path / "asr-status.json"
    state = json.loads(path.read_text())
    state["time"] -= 181
    path.write_text(json.dumps(state))
    page = client.get("/admin/").get_data(as_text=True)
    assert "Нет связи с обработчиком" in page and label not in page


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


def test_configurable_access_policy(app):
    c, _ = first_login(app)
    data = dict(hours=1, attempts_user=4, attempts_ip=10, minutes=2, admin_totp="on")
    c.post("/admin/access", data={**data, "csrf_token": token(c.get("/admin/"))})
    assert c.get("/admin/").location.endswith("/account")
    assert "обязателен второй фактор" in c.get("/account").get_data(as_text=True)
    guest = app.test_client()
    for i in range(5):
        res = guest.post("/login", data=dict(username="missing", password="bad", csrf_token=token(guest.get("/login"))))
    assert res.status_code == 429 and "2 мин" in res.get_data(as_text=True)


def test_concurrent_boot_initializes_all_modules(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    config = dict(TESTING=True, DATA_DIR=str(tmp_path), SECRET_KEY=secrets.token_hex(32))
    def boot(_):
        with create_app(config).app_context():
            return get_db().execute("SELECT COUNT(*) FROM redaction_batch_files").fetchone()[0]
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert list(pool.map(boot, range(6))) == [0] * 6
