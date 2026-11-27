import io
import re
import secrets
from concurrent.futures import ThreadPoolExecutor

from app import create_app
from app.db import get_db
from test_platform import token


def test_public_modules_keep_independent_owners(tmp_path):
    app = create_app(dict(TESTING=True, DATA_DIR=str(tmp_path), SECRET_KEY=secrets.token_hex(32)))
    alice, bob = app.test_client(), app.test_client()
    for client in (alice, bob):
        for route in ("/", "/redaction/", "/transcription/", "/threats/", "/passwords/"):
            assert client.get(route).status_code == 200
        for route in ("/account", "/admin/", "/admin/directory/1/principals", "/admin/storage/"):
            assert client.get(route).location == "/login"
        assert "Expires=" in client.get("/").headers["Set-Cookie"]
    with app.app_context():
        assert get_db().execute("SELECT count(*) FROM users").fetchone()[0] == 0
    page = alice.get("/redaction/")
    csrf = token(page)
    nonce = re.search(rb'name="nonce" value="([a-f0-9]+)"', page.data)[1].decode()
    assert alice.post("/redaction/batches", data={"nonce": nonce}).status_code == 400
    batch = alice.post("/redaction/batches", data=dict(nonce=nonce, csrf_token=csrf)).location
    job = alice.post("/transcription/", data=dict(media=(io.BytesIO(b"fixture"), "sample.ogg"), csrf_token=csrf)).location
    assert alice.get(batch).status_code == alice.get(job).status_code == 200
    assert bob.get(batch).status_code == bob.get(job).status_code == bob.get(job + "/status").status_code == 404
    assert bob.get(batch + "/archive.zip").status_code == 404
    assert bob.post("/redaction/batches", data=dict(nonce=nonce, csrf_token=csrf)).status_code == 400
    assert "sample.ogg" not in bob.get("/").get_data(as_text=True)
    assert alice.get("/login").status_code == 200
    pw = app.test_cli_runner().invoke(args=["admin-password"]).output.strip()
    assert alice.post("/login", data=dict(username="admin", password=pw, csrf_token=csrf)).location == "/account"
    alice.post("/account", data=dict(action="password", current=pw, new=pw+"yes", repeat=pw+"yes", csrf_token=token(alice.get("/account"))))
    assert alice.get(job).status_code == 404
    assert alice.get("/admin/").status_code == 200
    alice.post("/logout", data=dict(csrf_token=token(alice.get("/account"))))
    assert alice.get(job).status_code == 200 and alice.get("/admin/").location == "/login"


def test_concurrent_first_submissions_share_one_guest_owner(tmp_path):
    app = create_app(dict(TESTING=True, DATA_DIR=str(tmp_path), SECRET_KEY=secrets.token_hex(32)))
    guest = app.test_client()
    csrf = token(guest.get("/redaction/"))
    with guest.session_transaction() as state:
        initial = dict(state)

    def submit(_):
        client = app.test_client()
        with client.session_transaction() as state:
            state.update(initial)
        return client.post("/redaction/batches", data=dict(nonce=secrets.token_hex(16), csrf_token=csrf)).status_code

    with ThreadPoolExecutor(max_workers=4) as workers:
        assert list(workers.map(submit, range(4))) == [303] * 4
    with app.app_context():
        counts = get_db().execute("SELECT count(*),count(distinct owner) FROM redaction_batches").fetchone()
        assert tuple(counts) == (4, 1)
