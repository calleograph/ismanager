import secrets

import pytest

from app import create_app
from app.auth import reveal
from app.db import get_db
from test_platform import first_login, token


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / "folders"
    root.mkdir()
    (root / "Встречи").mkdir()
    monkeypatch.setenv("WATCH_ROOT", str(root))
    app = create_app(dict(DATA_DIR=tmp_path / "data", TESTING=True, SECRET_KEY=secrets.token_hex(32)))
    client, _ = first_login(app)
    csrf = token(client.get("/admin/"))

    def post(route, **data):
        return client.post(route, data={**data, "csrf_token": csrf})

    return app, client, post


def test_resources_auth_secrets_and_connection_check(setup):
    app, client, post = setup
    assert "Ресурсы хранения" in client.get("/admin/").get_data(as_text=True)
    path = "/admin/storage/new"
    assert app.test_client().get("/admin/storage/").location == "/login"
    assert client.post(path, data={"kind": "local", "name": "Папка"}).status_code == 400
    invalid = post(path, kind="local", name="Папка", path="../private")
    assert invalid.status_code == 400
    saved = post(path, kind="local", name="Записи", path="Встречи")
    assert saved.status_code == 302
    assert post(saved.location, action="test").location == saved.location
    assert "Папка доступна для чтения" in client.get(saved.location).get_data(as_text=True)
    assert post(path, kind="local", name="Записи", path="Встречи").status_code == 400

    password = secrets.token_urlsafe(24)
    smb = dict(kind="smb", name="Архив", server="store.example", share="Archive", path="",
               domain="EXAMPLE", username="recorder", port="445")
    remote = post(path, **smb, password=password)
    assert remote.status_code == 302
    with app.app_context():
        secret = get_db().execute("SELECT password FROM watch_resources WHERE name='Архив'").fetchone()[0]
        assert secret != password and reveal(secret) == password
    assert password not in client.get(remote.location).get_data(as_text=True)
    assert secret not in client.get(remote.location).get_data(as_text=True)
    assert post(remote.location, **(smb | {"name": "Отдел"}), password="").status_code == 302
    wrong_target = post(remote.location, **(smb | {"server": "another.example"}), password="")
    assert wrong_target.status_code == 400
    assert password not in wrong_target.get_data(as_text=True)
    with app.app_context():
        assert get_db().execute("SELECT password FROM watch_resources WHERE name='Отдел'").fetchone()[0] == secret
    assert post(remote.location, action="delete").location == "/admin/storage/"


def test_rules_routes_defaults_and_resource_protection(setup):
    app, client, post = setup
    assert "Сначала добавьте" in client.get("/admin/watches/new").get_data(as_text=True)
    create = "/admin/storage/new"
    source = post(create, kind="local", name="Вход", path="Встречи").location
    target = post(create, kind="local", name="Выход", path="Тексты").location
    source_id, target_id = int(source.rsplit("/", 1)[1]), int(target.rsplit("/", 1)[1])
    form = dict(name="Совещания", input_resource=source_id, input_folder="", output_resource="", output_folder="")
    new = post("/admin/watches/new", **form, enabled="on")
    assert new.status_code == 302
    assert "Папка «Тексты IS Manager»" in client.get(new.location).get_data(as_text=True)
    assert "Совещания" in client.get("/admin/watches/").get_data(as_text=True)
    assert post("/admin/watches/new", **(form | {"name": "Дубликат"})).status_code == 400
    assert post(source, action="delete").status_code == 400
    assert post(source, kind="local", name="Вход", path="Другая").status_code == 400
    assert post(new.location, **(form | {"input_folder": "../x"})).status_code == 400
    assert post(new.location, **(form | {"output_folder": "Другой"})).status_code == 400
    assert post(new.location, **(form | {"input_resource": 999})).status_code == 400
    with app.app_context():
        rule = get_db().execute("SELECT * FROM watch_rules").fetchone()
        assert rule["output_resource"] is None and not rule["delete_source"] and rule["enabled"]
    form.update(output_resource=target_id, output_folder="Итоги")
    assert post(new.location, **form, delete_source="on").status_code == 302
    with app.app_context():
        rule = get_db().execute("SELECT * FROM watch_rules").fetchone()
        assert rule["output_resource"] == target_id and rule["output_folder"] == "Итоги"
        assert rule["delete_source"] and not rule["enabled"]
    assert post(new.location, action="scan").status_code == 400
    assert post(target, action="delete").status_code == 400
    assert post(new.location, action="delete").location == "/admin/watches/"
    assert post(target, action="delete").location == "/admin/storage/"


def test_processing_state_retry_and_edit_guards(setup):
    app, client, post = setup
    storage = post("/admin/storage/new", kind="local", name="Фонотека", path="Встречи").location
    resource_id = int(storage.rsplit("/", 1)[1])
    form = dict(name="Архивные встречи", input_resource=resource_id, enabled="on")
    route = post("/admin/watches/new", **form).location
    rule_id = int(route.rsplit("/", 1)[1])
    with app.app_context():
        db = get_db()
        db.execute("UPDATE watch_rules SET last_scan=unixepoch() WHERE id=?", (rule_id,))
        file_id = db.execute("""INSERT INTO watch_files(rule_id,name,stamp,state,seen_since,updated,output_name,output_key,error)
            VALUES (?, 'meeting.wav', 'sample', 'failed', unixepoch(),unixepoch(),'meeting.txt','key','Проверьте запись')""",
                             (rule_id,)).lastrowid
        db.commit()
    assert "Проверьте запись" in client.get(route).get_data(as_text=True)
    assert post(route, **form, input_folder="Другая").status_code == 400
    assert post(route, action="scan").status_code == 302
    assert post(route, action="retry", file_id=file_id).status_code == 302
    assert post(route, action="retry", file_id=file_id).status_code == 400
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT last_scan FROM watch_rules WHERE id=?", (rule_id,)).fetchone()[0] == 0
        assert db.execute("SELECT state FROM watch_files WHERE id=?", (file_id,)).fetchone()[0] == "queued"
        db.execute("UPDATE watch_files SET state='running' WHERE id=?", (file_id,))
        db.commit()
    assert post(route, action="delete").status_code == 400
    assert "Распознаётся" in client.get(route).get_data(as_text=True)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE users SET admin=0 WHERE identity='local:admin'")
        db.commit()
    for path in ("/admin/storage/", storage, "/admin/watches/", route):
        assert client.get(path).status_code == 403
    for path in (storage, route):
        assert post(path, action="delete").status_code == 403


@pytest.mark.parametrize("kind", ["local", "smb"])
def test_rules_cannot_share_physical_input_via_other_resources(setup, kind):
    _, _, post = setup
    if kind == "smb":
        common = dict(kind=kind, server="files.example", port="445", domain="EXAMPLE",
                      share="Archive", username="one", password="test-only-credential")
        other = common | {"share": "ARCHIVE", "username": "two"}
    else:
        common = other = {"kind": kind}
    first = post("/admin/storage/new", **common, name="Вся папка", path="").location
    second = post("/admin/storage/new", **other, name="Подпапка", path="Записи").location
    first_id, second_id = (int(url.rsplit("/", 1)[1]) for url in (first, second))
    folder = "записи" if kind == "smb" else "Записи"
    one = post("/admin/watches/new", name="Обработка А", input_resource=first_id, input_folder=folder, enabled="on")
    assert one.status_code == 302
    duplicate = post("/admin/watches/new", name="Обработка Б", input_resource=second_id, input_folder="", enabled="on")
    assert duplicate.status_code == 400
    assert "Эта входная папка уже используется" in duplicate.get_data(as_text=True)
    other_folder = post("/admin/watches/new", name="Обработка Б", input_resource=second_id, input_folder="Резерв")
    assert other_folder.status_code == 302
