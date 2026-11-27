import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from werkzeug.exceptions import Unauthorized

from app import auth, create_app, directory
from app.db import get_db
from test_platform import first_login, token


def test_directory_user_access_and_revocation(tmp_path, monkeypatch):
    app = create_app(dict(TESTING=True, DATA_DIR=tmp_path, SECRET_KEY=secrets.token_hex(32)))
    admin, _ = first_login(app)
    cfg = dict(kind="ad", host="dc.example.test", port=636, protocol="ldaps", ca="", timeout=3,
               bind_dn="CN=svc,DC=example,DC=test", base_dn="DC=example,DC=test", login_attr="",
               name_attr="", domain="EXAMPLE", suffix="example.test", admin_groups=[], user_groups=[])
    person = SimpleNamespace(external_id="stable-id", login="reader", display_name="Анна Петрова", groups=[])
    monkeypatch.setattr(directory, "authenticate", lambda *args: person)
    monkeypatch.setattr(directory, "diagnose", lambda *args: [{"ok": True, "step": "bind", "detail": "OK"}])
    monkeypatch.setattr(directory, "lookup", lambda *args: person)
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO directories(name,config,password,enabled) VALUES(?,?,?,1)",
                   ("Учебный каталог", json.dumps(cfg), auth.protected("example-secret")))
        db.commit()

    def signin(client):
        return client.post("/login", data=dict(username=person.login, password="synthetic",
                                               csrf_token=token(client.get("/login"))))

    one, two = app.test_client(), app.test_client()
    assert signin(one).status_code == signin(two).status_code == 302
    assert one.get("/admin/users/").status_code == 403
    with app.app_context():
        reader = get_db().execute("SELECT id FROM users WHERE username=?", (person.login,)).fetchone()[0]
        local = get_db().execute("SELECT id FROM users WHERE identity='local:admin'").fetchone()[0]
    path = f"/admin/users/{reader}/access"
    filtered = admin.get("/admin/users/?q=ПЕТРОВА")
    assert person.display_name in filtered.get_data(as_text=True)
    assert "Учебный каталог" in filtered.get_data(as_text=True)
    assert "Локальная учётная запись" not in filtered.get_data(as_text=True)
    assert one.post(path, data={"action": "disable", "csrf_token": token(one.get("/"))}).status_code == 403
    assert admin.post(path, data={"action": "disable"}).status_code == 400

    def access(action):
        return admin.post(path, data={"action": action, "csrf_token": token(admin.get("/admin/users/"))})

    assert access("disable").status_code == 302
    assert access("disable").status_code == 302
    assert one.get("/").location.endswith("/login") and two.get("/").location.endswith("/login")
    assert signin(one).status_code == 401
    assert person.display_name not in admin.get("/admin/users/?active=1").get_data(as_text=True)
    assert person.display_name in admin.get("/admin/users/").get_data(as_text=True)
    with app.test_request_context():
        # A successful directory bind already in progress cannot recreate a revoked session.
        with pytest.raises(Unauthorized):
            auth.begin(reader)
        assert get_db().execute("SELECT COUNT(*) FROM sessions WHERE user_id=?", (reader,)).fetchone()[0] == 0
        assert get_db().execute("SELECT COUNT(*) FROM audit WHERE event='user.disabled' AND target_user=?",
                                (reader,)).fetchone()[0] == 1
    profile = "/admin/directory/1"
    checked = admin.post(profile, data={"action": "test", "test_user": person.login,
                                        "csrf_token": token(admin.get(profile))})
    assert "Учётная запись отключена в IS Manager" in checked.get_data(as_text=True)
    assert access("enable").status_code == 302
    assert one.get("/").location.endswith("/login")
    assert signin(one).status_code == 302
    assert admin.post(f"/admin/users/{local}/access", data={"action": "disable",
                      "csrf_token": token(admin.get("/admin/users/"))}).status_code == 400
    assert admin.get("/admin/").status_code == 200


def test_user_directory_pagination_and_upgrade(tmp_path):
    config = dict(DATA_DIR=tmp_path, TESTING=True, SECRET_KEY=secrets.token_hex(32))
    app = create_app(config)
    admin, _ = first_login(app)
    with app.app_context():
        db = get_db()
        db.executemany("INSERT INTO users(identity,username,display_name,admin) VALUES (?,?,?,0)",
                       ((f"ldap:1:{i}", f"reader-{i}", f"Читатель {i}",) for i in range(52)))
        db.commit()
        first_id = db.execute("SELECT id FROM users WHERE username='reader-2'").fetchone()[0]
        db.execute("ALTER TABLE users DROP COLUMN disabled")
        db.execute("ALTER TABLE audit DROP COLUMN target_user")
    with ThreadPoolExecutor(max_workers=2) as workers:
        list(workers.map(create_app, [config, config]))
    page = admin.get("/admin/users/", query_string={"q": "ЧИТАТЕЛЬ"}).get_data(as_text=True)
    assert "reader-51" in page and "Следующие 50" in page
    more = admin.get("/admin/users/", query_string={"q": "ЧИТАТЕЛЬ", "before": first_id}).get_data(as_text=True)
    assert "reader-0" in more and "reader-51" not in more
    assert admin.get("/admin/users/?before=9999999999999999999999").status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM users WHERE disabled=0").fetchone()[0] == 53
        assert get_db().execute("SELECT COUNT(*) FROM audit WHERE target_user IS NULL").fetchone()[0] > 0


def test_shared_ip_counts_failed_logins_only(tmp_path):
    app = create_app(dict(TESTING=True, DATA_DIR=tmp_path, SECRET_KEY=secrets.token_hex(32)))
    _, password = first_login(app)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE auth_settings SET attempts_ip=3,attempts_user=3")
        db.commit()

    def login(name, supplied):
        client = app.test_client()
        return client.post("/login", data=dict(username=name, password=supplied,
                                               csrf_token=token(client.get("/login")))).status_code

    assert login("admin", "incorrect") == 401
    for _ in range(5):
        assert login("admin", password) == 302
    with app.app_context():
        assert sorted(row[0] for row in get_db().execute("SELECT count FROM attempts")) == [1, 1]
    assert login("unknown-one", "incorrect") == 401
    assert login("unknown-two", "incorrect") == 401
    assert login("admin", password) == 429


def test_slow_success_cannot_clear_a_new_window(tmp_path, monkeypatch):
    app = create_app(dict(TESTING=True, DATA_DIR=tmp_path, SECRET_KEY=secrets.token_hex(32)))
    first_login(app)
    with app.test_request_context(environ_base={"REMOTE_ADDR": "192.0.2.5"}):
        db = get_db()
        db.execute("UPDATE auth_settings SET minutes=1")
        db.commit()
        old_reservations = auth.reserve_login("admin")
        later = old_reservations[0][1] + 1
        monkeypatch.setattr(auth.time, "time", lambda: later)
        new_reservations = auth.reserve_login("admin")
        actor = db.execute("SELECT id FROM users WHERE identity='local:admin'").fetchone()[0]
        auth.begin(actor, old_reservations)
        actual = {tuple(row) for row in db.execute("SELECT key,until,count FROM attempts")}
        assert actual == {(key, until, 1) for key, until in new_reservations}


def test_concurrent_requests_respect_shared_ip_limit(tmp_path):
    app = create_app(dict(TESTING=True, DATA_DIR=tmp_path, SECRET_KEY=secrets.token_hex(32)))
    with app.app_context():
        get_db().execute("UPDATE auth_settings SET attempts_ip=3")
        get_db().commit()

    def reserve(index):
        with app.test_request_context(environ_base={"REMOTE_ADDR": "192.0.2.10"}):
            return auth.reserve_login(f"user-{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(12)))
    assert sum(ticket is not None for ticket in results) == 3
    with app.app_context():
        count = get_db().execute("SELECT count FROM attempts WHERE key=?", (auth.digest("ip:192.0.2.10"),)).fetchone()
        assert count[0] == 3
