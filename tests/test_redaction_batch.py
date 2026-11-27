from concurrent.futures import ThreadPoolExecutor
import io
import re
import secrets
import time
from threading import Barrier, Event
import zipfile

import pytest

from app import create_app, redaction_batch as jobs
from app.auth import digest
from app.db import get_db
from test_platform import first_login, token


@pytest.fixture
def setup(tmp_path):
    app = create_app(dict(TESTING=True, SECRET_KEY=secrets.token_hex(32), DATA_DIR=str(tmp_path)))
    alice, _ = first_login(app)
    bob = app.test_client()
    sid = secrets.token_hex(24)
    with app.app_context(), get_db() as db:
        owner = db.execute("INSERT INTO users(identity,username,display_name,admin) VALUES('other','reader','Читатель',0)").lastrowid
        db.execute("INSERT INTO sessions VALUES(?,?,?)",(digest(sid),owner,int(time.time())+300))
    with bob.session_transaction() as session:
        session["sid"] = sid
    return app,alice,bob,tmp_path


def create(client):
    page = client.get("/redaction/")
    csrf = token(page)
    nonce = re.search(rb'id="batch-upload".*?name="nonce" value="([a-f0-9]+)"',page.data,re.S)[1].decode()
    data = dict(csrf_token=csrf,nonce=nonce)
    where = client.post("/redaction/batches",data=data).location
    assert client.post("/redaction/batches",data=data).location == where
    return where,csrf


def upload(client, where, csrf, content, *, key=None, ext="txt"):
    return client.post(where+"/files?ext="+ext, data=content,content_type="application/octet-stream",
                       headers={"X-CSRF-Token":csrf,"X-Upload-Key":key or secrets.token_hex(16)})


def test_batch_routes_results_errors_and_privacy(setup,monkeypatch,caplog):
    app,alice,bob,root = setup
    where,csrf = create(alice)
    assert "Настроить правило для папок" in alice.get("/redaction/").get_data(as_text=True)
    assert "Настроить правило для папок" not in bob.get("/redaction/").get_data(as_text=True)
    assert bob.get(where).status_code == bob.get(where+"/archive.zip").status_code == 404
    assert upload(bob,where,token(bob.get("/redaction/")),b"other").status_code == 404
    assert upload(alice,where,"bogus",b"denied").status_code == 400
    for body in (b"private original",b"invalid private input",b"another private original"):
        assert upload(alice,where,csrf,body).status_code == 200
    bad = alice.post(where+"/files",json=dict(size=jobs.BATCH_MAX_BYTES+1,ext="docx",name="private-name.docx"),
                     headers={"X-CSRF-Token":csrf,"X-Upload-Key":secrets.token_hex(16)})
    assert bad.json["ordinal"] == 4 and "64" in bad.json["error"]
    assert alice.get(where+"/archive.zip").status_code == alice.get(where+"/files/1/download").status_code == 404
    def redact(path,ext):
        assert ext=="txt" and (path.stat().st_mode & 0o777)==0o600
        if path.read_bytes().startswith(b"invalid"):
            raise ValueError("SECRET-TRACE private parser input")
        return "Проверено",{"email":1},["Использован OCR.","Изображения внутри офисного документа опущены.","SECRET-TRACE"]
    monkeypatch.setattr(jobs,"redact_file",redact)
    with app.app_context():
        db = get_db()
        assert all(jobs.work(db,root) for _ in range(3)) and not jobs.work(db,root)
    visible = alice.get(where).get_data(as_text=True)
    for word in ("Готово 2","Ошибок 2","Использован OCR","Вложенные изображения Office","64 МиБ"):
        assert word in visible
    assert all(word not in visible+caplog.text for word in ("private","SECRET-TRACE"))
    assert alice.get(where+"/files/1/download").get_data(as_text=True) == "Проверено"
    assert alice.get(where+"/files/2/download").status_code == bob.get(where+"/files/1/download").status_code == 404
    with zipfile.ZipFile(io.BytesIO(alice.get(where+"/archive.zip").data)) as archive:
        assert archive.namelist() == ["redacted-000001.txt","redacted-000003.txt"]
        assert archive.read("redacted-000001.txt").decode() == "Проверено"
    assert {path.name for path in (root/"redaction-batch").iterdir()} == {".lock",".locks"}
    with app.app_context():
        objects = get_db().execute("SELECT ext,state,error,result FROM redaction_batch_files").fetchall()
        assert "private" not in repr([tuple(row) for row in objects])


def test_upload_retries_conflicts_and_restored_queue(setup,monkeypatch):
    app,alice,_,root = setup
    where,csrf = create(alice)
    key = secrets.token_hex(16)
    assert upload(alice,where,csrf,b"one",key=key).json["ordinal"] == 1
    assert upload(alice,where,csrf,b"one",key=key).json["ordinal"] == 1
    assert upload(alice,where,csrf,b"one").json["ordinal"] == 1
    assert upload(alice,where,csrf,b"two",key=key).status_code == 409
    multipart = dict(csrf_token=csrf,nonce=secrets.token_hex(16),file=(io.BytesIO(b"two"),"private surname.txt"))
    assert alice.post(where+"/files",data=multipart).status_code == 303
    monkeypatch.setattr(jobs,"redact_file",lambda p,e: ("результат",{},[]))
    with app.app_context():
        db = get_db()
        source1,source2 = [r["source"] for r in db.execute("SELECT source FROM redaction_batch_files ORDER BY ordinal")]
        orphan = root/"redaction-batch"/secrets.token_hex(16)
        orphan.write_bytes(b"interrupted upload")
        (root/"redaction-batch"/source1).unlink()
        with db:
            db.execute("UPDATE redaction_batch_files SET state='running',attempts=1 WHERE ordinal=2")
        jobs.recover(db,root)
        assert not orphan.exists()
        assert [tuple(r) for r in db.execute("SELECT state,error FROM redaction_batch_files ORDER BY ordinal")] == [
            ("failed","missing"),("queued","")]
        assert jobs.work(db,root)
    assert upload(alice,where,csrf,b"one",key=key).json["ordinal"] == 1
    with app.app_context():
        db = get_db()
        assert jobs.work(db,root) and not jobs.work(db,root)
        assert db.execute("SELECT count(*) FROM redaction_batch_files WHERE state='done'").fetchone()[0] == 2
    assert "private surname" not in alice.get(where).get_data(as_text=True)


def test_concurrent_reuploads_claim_once(setup,monkeypatch):
    app,alice,_,root = setup
    where,csrf = create(alice)
    with alice.session_transaction() as session:
        state = dict(session)
    barrier = Barrier(4)
    def send(_):
        client = app.test_client()
        with client.session_transaction() as target:
            target.update(state)
        barrier.wait(timeout=10)
        return upload(client,where,csrf,b"same document").json["ordinal"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(send,range(4))) == [1]*4
    called=[]
    def redact(path,ext):
        called.append(path)
        time.sleep(0.05)
        return "проверено",{},[]
    monkeypatch.setattr(jobs,"redact_file",redact)
    def worker(_):
        with app.app_context():
            barrier.wait(timeout=10)
            return jobs.work(get_db(),root)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(worker,range(4))).count(True)==1
    assert len(called)==1


def test_pagination_without_a_batch_file_cap(setup):
    app,alice,_,root = setup
    where,csrf = create(alice)
    for i in range(45):
        assert upload(alice,where,csrf,f"document {i}".encode()).status_code == 200
    page = alice.get(where+"?page=2").get_data(as_text=True)
    assert "№ 45" in page and "<td>№ 1 ·" not in page and "Всего 45" in page


def test_recovery_during_upload_waits_for_receipt(setup,monkeypatch):
    app,alice,_,root = setup
    where,csrf = create(alice)
    with alice.session_transaction() as session:
        state = dict(session)
    writing, release, recovering, finished = Event(), Event(), Event(), Event()
    original = jobs.record
    def pause(*args,**kwargs):
        writing.set()
        assert release.wait(10)
        return original(*args,**kwargs)
    monkeypatch.setattr(jobs,"record",pause)
    def submit():
        client = app.test_client()
        with client.session_transaction() as session:
            session.update(state)
        return upload(client,where,csrf,b"original").status_code
    def restart():
        with app.app_context():
            recovering.set()
            jobs.recover(get_db(),root)
            finished.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        sending = pool.submit(submit)
        assert writing.wait(10)
        recovery = pool.submit(restart)
        try:
            assert alice.post(where+"/delete",headers={"X-CSRF-Token":csrf}).status_code == 409
            assert recovering.wait(10) and not finished.wait(0.05)
        finally:
            release.set()
        assert sending.result(timeout=10) == 200
        recovery.result(timeout=10)
    with app.app_context():
        row = get_db().execute("SELECT state,source FROM redaction_batch_files").fetchone()
        assert row["state"] == "queued" and (root/"redaction-batch"/row["source"]).read_bytes() == b"original"


def test_completed_batch_deletion_and_active_transfer(setup,monkeypatch):
    app,alice,bob,root = setup
    where,csrf = create(alice)
    assert upload(alice,where,csrf,b"file").status_code == 200
    url = where+"/delete"
    assert bob.post(url,headers={"X-CSRF-Token":token(bob.get("/redaction/"))}).status_code == 404
    assert alice.post(url,headers={"X-CSRF-Token":csrf}).status_code == 409
    monkeypatch.setattr(jobs,"redact_file",lambda path,ext:("result",{},[]))
    with app.app_context():
        assert jobs.work(get_db(),root)
    transfer = alice.get(where+"/archive.zip",buffered=False)
    assert transfer.status_code == 200
    assert alice.post(url,headers={"X-CSRF-Token":csrf}).status_code == 409
    transfer.close()
    assert alice.post(url,headers={"X-CSRF-Token":csrf}).status_code == 303
    for suffix in ("","/archive.zip","/files/1/download"):
        assert alice.get(where+suffix).status_code == 404
    with app.app_context():
        assert all(get_db().execute("SELECT count(*) FROM "+table).fetchone()[0]==0 for table in
                   ("redaction_batches","redaction_batch_files","redaction_batch_receipts"))
    other,_ = create(alice)
    assert other!=where
