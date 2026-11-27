"""Integration test invoked by run.sh against an isolated Samba AD domain controller."""
import os
import secrets
from pathlib import Path
from uuid import UUID

import pytest
from app import create_app
from app.db import get_db
from test_platform import first_login, token


@pytest.mark.parametrize("protocol,port", [("ldaps", 636), ("starttls", 389)])
def test_ad_login(tmp_path, protocol, port):
    app = create_app(dict(DATA_DIR=str(tmp_path), SECRET_KEY=secrets.token_hex(32), TESTING=True))
    admin, _ = first_login(app)
    base = "DC=example,DC=test"
    form = dict(name="Учебный домен", kind="ad", domain="EXAMPLE", suffix="example.test",
                host=os.environ["TEST_DC"], port=str(port), protocol=protocol, timeout="5",
                bind_dn="CN=service,CN=Users," + base, password=os.environ["SERVICE_PASS"],
                base_dn=base, enabled="on", ca=Path(os.environ["TEST_CA"]).read_text(),
                admin_groups="CN=Readers,CN=Users," + base, action="save")
    directory = "/admin/directory/"
    saved = admin.post(directory, data={**form, "csrf_token": token(admin.get(directory))})
    assert saved.status_code == 302
    page = directory + "1"
    groups = admin.get(page + "/principals", query_string={"q": "Reade"}).json["items"]
    assert any(g["kind"] == "group" and g["id"].casefold() == form["admin_groups"].casefold() for g in groups)
    people = admin.get(page + "/principals", query_string={"q": "outsid"}).json["items"]
    direct = next(p for p in people if p["kind"] == "user" and p["login"] == "outsider")
    assert UUID(direct["id"])
    diagnosed = admin.post(page, data=dict(action="test", test_user="analyst", test_password=os.environ["USER_PASS"],
                                           csrf_token=token(admin.get(page))))
    assert "Администратор" in diagnosed.get_data(as_text=True)

    def sign_in(name, password):
        client = app.test_client()
        response = client.post("/login", data=dict(username=name, password=password,
                                                   csrf_token=token(client.get("/login"))))
        return client, response.status_code

    for login in ("analyst", "EXAMPLE\\analyst", "analyst@example.test"):
        client, status = sign_in(login, os.environ["USER_PASS"])
        assert status == 302
        assert client.get("/").status_code == 200
        assert client.get("/admin/").status_code == 200
    assert sign_in("outsider", os.environ["USER_PASS"])[1] == 401
    assert sign_in("analyst", secrets.token_urlsafe(20))[1] == 401
    with app.app_context():
        users = get_db().execute("SELECT id, identity FROM users WHERE username='analyst'").fetchall()
        assert len(users) == 1
        assert UUID(users[0]["identity"].split(":")[-1])
        user_id = users[0]["id"]
    access_path = f"/admin/users/{user_id}/access"
    for action in ("disable", "enable"):
        assert admin.post(access_path, data={"action": action, "csrf_token": token(admin.get("/admin/users/"))}).status_code == 302
        assert client.get("/admin/").status_code == 302
        client, status = sign_in("EXAMPLE\\analyst", os.environ["USER_PASS"])
        assert status == (401 if action == "disable" else 302)
    direct_form = {**form, "admin_groups": "", "admin_user": direct["id"] + "|" + direct["label"]}
    assert admin.post(page, data={**direct_form, "csrf_token": token(admin.get(page))}).status_code == 302
    assert sign_in("analyst", os.environ["USER_PASS"])[1] == 401
    client, status = sign_in("outsider", os.environ["USER_PASS"])
    assert status == 302 and client.get("/admin/").status_code == 200
    # Removing the fixture CA must revoke the session and reject the untrusted certificate.
    changed = admin.post(page, data={**form, "ca": "", "csrf_token": token(admin.get(page))})
    assert changed.status_code == 302
    assert client.get("/admin/").status_code == 302
    assert sign_in("analyst", os.environ["USER_PASS"])[1] == 401
