"""Read and export the administrator's audit journal."""
import csv
import io
import re
import unicodedata
from collections.abc import Iterator

from flask import Response, abort, render_template, request, stream_with_context

from .db import get_db

EVENTS = {
    "access.saved": "Политика входа изменена",
    "directory.saved": "Подключение каталога сохранено",
    "directory.deleted": "Подключение каталога удалено",
    "local_admin.reset": "Установлен пароль локального администратора",
    "login.denied": "Вход отклонён",
    "login.ok": "Вход выполнен",
    "maintenance.backup": "Запрошена резервная копия",
    "maintenance.check": "Запрошена проверка обновлений",
    "maintenance.rollback": "Запрошен откат версии",
    "maintenance.update": "Запрошено обновление",
    "password.changed": "Пароль изменён",
    "sessions.revoked": "Сеансы завершены",
    "storage.saved": "Ресурс хранения сохранён",
    "storage.deleted": "Ресурс хранения удалён",
    "totp.disabled": "Двухфакторная защита отключена",
    "totp.enabled": "Двухфакторная защита включена",
    "user.disabled": "Доступ отключён",
    "user.enabled": "Доступ включён",
    "watch.save": "Правило наблюдения сохранено",
    "watch.delete": "Правило наблюдения удалено",
    "watch.scan": "Запрошен обход наблюдаемой папки",
    "watch.retry": "Запрошена повторная обработка записи",
}


def title(event):
    return EVENTS.get(event, event)


def filters():
    return request.args.get("event", "").strip()[:160], request.args.get("user", "").strip()[:256]


def cursor(name):
    value = request.args.get(name, type=int)
    if name in request.args and (value is None or not 0 < value < 2**63):
        abort(400)
    return value


def entries(event, user, limit, before=None, after=None, account=None):
    query = ""
    conditions = []
    values: list[str | int] = []
    if user and not account:
        query = "WITH matches AS (SELECT id FROM users WHERE instr(casefold(username || ' ' || display_name), ?) > 0) "
        values.append(user.casefold())
        conditions.append("(a.actor IN matches OR a.target_user IN matches)")
    if event:
        conditions.append("a.event=?")
        values.append(event)
    if before:
        conditions.append("a.id < ?")
        values.append(before)
    if after:
        conditions.append("a.id > ?")
        values.append(after)
    order = "ASC" if after else "DESC"
    if account:
        # Keep the seek and LIMIT on both exact-account indexes before merging.
        predicates = "".join(" AND " + item for item in conditions)
        query = f"""WITH actor_matches AS (
                SELECT id FROM audit a WHERE actor=?{predicates} ORDER BY id {order} LIMIT ?
            ), target_matches AS (
                SELECT id FROM audit a WHERE target_user=?{predicates} ORDER BY id {order} LIMIT ?
            ), matches AS (SELECT id FROM actor_matches UNION SELECT id FROM target_matches) """
        values = [account, *values, limit] * 2
    query += """SELECT a.id,a.time,a.event,actor.username AS actor,target.username AS target
        FROM audit a LEFT JOIN users actor ON a.actor=actor.id LEFT JOIN users target ON a.target_user=target.id"""
    if account:
        query += " JOIN matches m ON m.id=a.id"
    elif conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += f" ORDER BY a.id {order} LIMIT ?"
    return get_db().execute(query, (*values, limit)).fetchall()


def index():
    event, user = filters()
    before, after = cursor("before"), cursor("after")
    if before and after:
        abort(400)
    account = cursor("account")
    selected = get_db().execute("SELECT username FROM users WHERE id=?", (account,)).fetchone() if account else None
    if account and not selected:
        abort(404)
    records = entries(event, user, 51, before, after, account)
    rows = records[:50]
    if after:
        rows.reverse()
    # Seek to each next code in audit_event instead of reading every repeated code.
    choices = [r[0] for r in get_db().execute("""WITH RECURSIVE codes(event) AS (
        SELECT min(event) FROM audit
        UNION ALL
        SELECT (SELECT event FROM audit WHERE event>codes.event ORDER BY event LIMIT 1)
        FROM codes WHERE event IS NOT NULL
    ) SELECT event FROM codes WHERE event IS NOT NULL""")]
    if event and event not in choices:
        choices.append(event)
    return render_template("journal.html", entries=rows, event=event, user=user, account=account, selected=selected,
                           choices=sorted(choices, key=title), filtered_page=bool(before or after),
                           newer=(len(records) > 50 if after else bool(before)),
                           older=(bool(after) or len(records) > 50))


def excel_cell(value):
    value = str(value) if value is not None else ""
    # Spreadsheet readers can interpret a quoted CSV cell as a formula.
    if value.startswith(("\t", "\r", "\n")) or re.match(r"^[\s\ufeff]*[=+@-]", unicodedata.normalize("NFKC", value)):
        return "'" + value
    return value


def export():
    event, user = filters()
    account = cursor("account")

    def chunks() -> Iterator[str]:
        output = io.StringIO(newline="")
        output.write("\ufeff")
        writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_ALL)
        writer.writerow(("ID", "Время UTC", "Событие", "Код события", "Инициатор", "Учётная запись"))
        yield output.getvalue()
        before = None
        while rows := entries(event, user, 500, before=before, account=account):
            output.seek(0)
            output.truncate(0)
            for row in rows:
                cells = (row["id"], row["time"], title(row["event"]), row["event"], row["actor"], row["target"])
                writer.writerow(excel_cell(value) for value in cells)
            yield output.getvalue()
            before = rows[-1]["id"]
            if len(rows) < 500:
                break

    return Response(stream_with_context(chunks()), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="ismanager-audit.csv"'})
