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
    assert "Записей в очереди — 1" in client.get("/admin/").get_data(as_text=True)
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


@pytest.mark.parametrize("storage_kind", ["local", "smb"])
def test_redaction_destinations_and_physical_cycles(setup, storage_kind):
    app, client, post = setup
    common = {"kind": storage_kind}
    if storage_kind == "smb":
        common.update(server="file.test", username="watch", password="sample", share="Общая")
    root = post("/admin/storage/new", **common, name="Общий ресурс", path="").location
    sub = post("/admin/storage/new", **common, name="Выход", path="Готовые").location
    root_id, sub_id = (int(url.rsplit("/", 1)[1]) for url in (root, sub))
    form = dict(name="Архив заявок", kind="redaction", input_resource=root_id, input_folder="Заявки",
                output_resource=sub_id, enabled="on")
    new = "/admin/watches/new"
    chosen = client.get(new + "?kind=redaction").get_data(as_text=True)
    assert 'name="kind" value="redaction"' in chosen and 'Обезличено IS Manager' in chosen
    assert 'name="delete_source"' not in chosen
    one = post(new, **form, delete_source="on")
    assert one.status_code == 302
    assert post(new, **(form | {"name": "Лишнее"})).status_code == 400
    assert post(one.location, **(form | {"kind": "transcription"})).status_code == 400
    asr = post(new, **(form | {"kind": "transcription", "name": "Встречи"}))
    assert asr.status_code == 302
    assert "Встречи" not in client.get("/admin/watches/?kind=redaction").get_data(as_text=True)
    other_source = dict(input_resource=root_id, input_folder="Отдел", output_resource=root_id)
    for route in (
        {"input_resource": root_id, "input_folder": "Готовые", "output_resource": root_id, "output_folder": "Готовые"},
        {"input_resource": root_id, "input_folder": "Готовые"},
        {**other_source, "output_folder": "Заявки"},
        {**other_source, "output_folder": "Отдел"},
    ):
        assert post(new, name="Конфликт", kind="redaction", **route).status_code == 400
    assert post(new + "?kind=redaction", name="Отдельно", kind="redaction", input_resource=root_id,
                input_folder="Архив отдела").status_code == 302
    with app.app_context():
        db = get_db()
        saved = db.execute("SELECT * FROM watch_rules WHERE name=?", (form["name"],)).fetchone()
        assert saved["delete_source"] == 0 and saved["kind"] == "redaction"
        row = db.execute("""INSERT INTO watch_files(rule_id,name,stamp,state,seen_since,updated,output_key,output_name,recoveries)
                            VALUES (?,'большой.pdf','v','failed',1,1,'путь','результат.txt',2)""", (saved["id"],))
        file_id = row.lastrowid
        db.commit()
    assert post(one.location, action="retry", file_id=file_id).status_code == 302
    with app.app_context():
        assert tuple(get_db().execute("SELECT state,recoveries FROM watch_files WHERE id=?", (file_id,)).fetchone()) == ("queued", 0)


def test_large_resource_lists_and_saved_selections(setup):
    app, client, post = setup
    with app.app_context():
        db = get_db()
        db.executemany("INSERT INTO watch_resources(kind,name,path) VALUES('local',?,?)",
                       ((f"Папка {n:03}", f"folder/{n}") for n in range(124)))
        pick = db.execute("SELECT id FROM watch_resources WHERE name='Папка 123'").fetchone()[0]
        db.commit()
    assert len(client.get("/admin/storage/options").json["items"]) == 50
    assert client.get("/admin/storage/options?q=ПАПКА+123").json["items"] == [{"id":pick, "name":"Папка 123"}]
    page = client.get("/admin/storage/?page=3").text
    assert "Папка 123" in page and "Папка 000" not in page
    rule = post("/admin/watches/new", name="Выбор удалённого по списку ресурса", input_resource=pick)
    assert rule.status_code == 302 and "Папка 123" in client.get(rule.location).text


def test_old_watch_failure_can_be_found_and_retried(setup):
    app, client, post = setup
    res = post("/admin/storage/new", name="Источник", kind="local", path="incoming")
    route = post("/admin/watches/new", name="Правило", input_resource=res.location.rsplit("/",1)[1], enabled="on").location
    rule_id = int(route.rsplit("/",1)[1])
    with app.app_context():
        db = get_db()
        db.executemany("""INSERT INTO watch_files(rule_id,name,stamp,state,seen_since,updated,output_name,output_key)
                       VALUES(?,?,'snapshot',?,1,?,?,?)""",
                       ((rule_id, f"audio{n:03}.wav", "failed" if n==0 else "done", n+1, f"result{n}.txt", str(n)) for n in range(103)))
        failed = db.execute("SELECT id FROM watch_files WHERE state='failed'").fetchone()[0]
        db.commit()
    assert "audio000.wav" not in client.get(route).text
    filtered = route + "?file_q=AUDIO000&file_state=failed"
    assert "audio000.wav" in client.get(filtered).text
    retried = post(filtered, action="retry", file_id=failed)
    assert retried.status_code == 302 and "file_state=failed" in retried.location
    assert "Файлы не найдены" in client.get(retried.location).text
