import csv
import io
import re
import secrets
from html import unescape

from app import auth, create_app, journal
from app.db import get_db
from test_platform import first_login


def test_audit_filters_cursor_export_and_access(tmp_path):
    app = create_app(dict(TESTING=True, DATA_DIR=tmp_path, SECRET_KEY=secrets.token_hex(32)))
    admin, _ = first_login(app)
    member = app.test_client()
    sid = secrets.token_urlsafe(32)
    with app.app_context():
        db = get_db()
        actor = db.execute("INSERT INTO users(identity,username,display_name,admin) VALUES('ldap:1:a',?,?,0)",
                           ("=actor", "Оператор")).lastrowid
        target = db.execute("INSERT INTO users(identity,username,display_name,admin) VALUES('ldap:1:b',?,?,0)",
                            ('user;"2"', "Марина Петрова")).lastrowid
        unrelated = db.execute("INSERT INTO users(identity,username,display_name,admin) VALUES('ldap:1:c','other','Other',0)").lastrowid
        db.execute("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,unixepoch()+300)", (auth.digest(sid), target))
        db.executemany("INSERT INTO audit(time,actor,event,target_user) VALUES(datetime('2026-01-01',?),?,'user.disabled',?)",
                       ((f"+{i} seconds", actor, target) for i in range(516)))
        db.execute("INSERT INTO audit(actor,event,target_user) VALUES(?,'user.disabled',?)", (target, actor))
        db.execute("INSERT INTO audit(actor,event,target_user) VALUES(?,'user.enabled',?)", (actor, target))
        db.execute("INSERT INTO audit(actor,event,target_user) VALUES(?,'user.disabled',?)", (unrelated, None))
        db.commit()
    with member.session_transaction() as sess:
        sess["sid"] = sid
    for path in ("/admin/journal/", "/admin/journal/export.csv"):
        assert app.test_client().get(path).status_code == 302
        assert member.get(path).status_code == 403

    assert "Открыть журнал" in admin.get("/admin/").get_data(as_text=True)
    args = {"event": "user.disabled", "user": "ПЕТРОВА"}
    first = admin.get("/admin/journal/", query_string=args).get_data(as_text=True)
    assert first.count('<tr>') == 51 and 'rel="prev"' not in first
    assert "2026-01-01 00:08:35" in first and "Доступ отключён" in first
    older = unescape(re.search(r'rel="next" href="([^"]+)', first).group(1))
    second = admin.get(older).get_data(as_text=True)
    assert "2026-01-01 00:08:35" not in second
    newer = unescape(re.search(r'rel="prev" href="([^"]+)', second).group(1))
    assert "2026-01-01 00:08:35" in admin.get(newer).get_data(as_text=True)
    assert admin.get("/admin/journal/?before=1&after=2").status_code == 400
    assert "Событий не найдено" in admin.get("/admin/journal/", query_string={"user": "no-such-person"}).get_data(as_text=True)

    response = admin.get("/admin/journal/export.csv", query_string=args)
    assert response.mimetype == "text/csv" and response.headers["Content-Disposition"].startswith("attachment")
    contents = response.get_data()
    assert contents.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(contents.decode("utf-8-sig")), delimiter=";"))
    assert len(rows) == 518
    assert all(len(row) == 6 and row[3] == "user.disabled" for row in rows[1:])
    assert rows[1][4:] == ['user;"2"', "'=actor"] and rows[2][4:] == ["'=actor", 'user;"2"']
    ids = [int(row[0]) for row in rows[1:]]
    assert ids == sorted(set(ids), reverse=True)
    for value in ("  +sample", "\ttext", "\ntext", "@name", "＝sample", "-x"):
        assert journal.excel_cell(value) == "'" + value
