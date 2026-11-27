"""Run through tests/ldap/run.sh with an isolated TLS-enabled OpenLDAP."""
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from app import create_app
from app.db import get_db

ENV = "ISMANAGER_TEST_LDAP_"


def csrf(page):
    return re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()


@pytest.mark.parametrize("protocol", ["ldaps", "starttls"])
def test_real_directory(tmp_path, protocol):
    app = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "SECRET_KEY": secrets.token_hex(32)})
    c = app.test_client()
    pw = app.test_cli_runner().invoke(args=["admin-password"]).output.strip()
    c.post("/login", data=dict(username="admin", password=pw, csrf_token=csrf(c.get("/login"))))
    c.post("/account", data=dict(action="password", current=pw, new=pw+"yes", repeat=pw+"yes", csrf_token=csrf(c.get("/account"))))
    port = os.environ["ISMANAGER_TEST_LDAPS_PORT"] if protocol == "ldaps" else urlsplit(os.environ[ENV+"URL"]).port
    form = dict(name="Учебный каталог", kind="openldap", protocol=protocol, host="127.0.0.1", port=port, timeout=4,
                bind_dn=os.environ[ENV+"BIND_DN"], password=os.environ[ENV+"BIND_PASSWORD"], base_dn=os.environ[ENV+"BASE_DN"],
                ca=Path(os.environ[ENV+"CA"]).read_text(), enabled="on", action="save",
                user_groups="cn=vpn-users,ou=groups,dc=example,dc=org")
    resp = c.post("/admin/directory/", data={**form, "csrf_token":csrf(c.get("/admin/directory/"))})
    assert resp.status_code == 302, resp.get_data(as_text=True)
    test = dict(action="test", test_user="alice", test_password=os.environ[ENV+"USER_PASSWORD"])
    result = c.post("/admin/directory/1", data={**test, "csrf_token":csrf(c.get("/admin/directory/1"))})
    page_text = result.get_data(as_text=True)
    assert "Администрирование не назначено" in page_text, re.findall(r"<li>(.*?)</li>|role=\"alert\">(.*?)</p>", page_text)
    def signin(name, password):
        other = app.test_client()
        page = other.post("/login", data=dict(username=name, password=password, csrf_token=csrf(other.get("/login"))))
        return other, page.status_code
    member, status = signin("alice", test["test_password"])
    assert status == 401 and member.get("/").status_code == 200 and member.get("/admin/").status_code == 302
    assert signin("bob", test["test_password"])[1] == 401
    assert signin("alice", secrets.token_hex(8))[1] == 401
    search = "/admin/directory/1/principals"
    assert member.get(search).location == "/login"
    assert c.get(search, query_string={"q": "*()"}).json == {"items": []}
    records = c.get(search).json["items"]
    alice = next(p for p in records if p["kind"] == "user" and p["login"] == "alice")
    assert any(p["kind"] == "group" and p["label"] == "vpn-users" for p in records)
    c.post("/admin/directory/1", data={**form, "admin_user": alice["id"] + "|" + alice["label"],
                                     "csrf_token": csrf(c.get("/admin/directory/1"))})
    individual, status = signin("alice", test["test_password"])
    assert status == 302 and individual.get("/admin/").status_code == 200
    form.update(role_flags="1", use_for_admins="on", admin_groups="cn=vpn-users,ou=groups,dc=example,dc=org")
    c.post("/admin/directory/1", data={**form, "csrf_token":csrf(c.get("/admin/directory/1"))})
    assert signin("alice", test["test_password"])[0].get("/admin/").status_code == 200
    form.pop("use_for_admins")
    c.post("/admin/directory/1", data={**form, "csrf_token":csrf(c.get("/admin/directory/1"))})
    assert signin("alice", test["test_password"])[1] == 401
    form["use_for_users"] = "on"
    form["ca"] = Path(os.environ[ENV+"WRONG_CA"]).read_text()
    c.post("/admin/directory/1", data={**form, "csrf_token":csrf(c.get("/admin/directory/1"))})
    assert signin("alice", test["test_password"])[1] == 401
    assert individual.get("/admin/").location == "/login" and member.get("/").status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT password FROM directories").fetchone()[0] != form["password"]
