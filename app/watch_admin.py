"""Administrator screens for transcription resources and folder watches."""
import sqlite3

from flask import abort, current_app, flash, g, redirect, render_template, request, url_for

from . import watch_storage
from .auth import protected
from .db import audit, get_db
from .folder_watch import storage_location

RESOURCE_FIELDS = ("kind", "path", "server", "share", "domain", "username", "port")
ROUTE_FIELDS = ("input_resource", "input_folder", "output_resource", "output_folder")
STATES = {
    "settling": "Ожидается завершение записи", "queued": "В очереди", "running": "Распознаётся",
    "publishing": "Сохраняется текст", "done": "Готово", "existing": "Текст уже существует",
    "conflict": "Конфликт выходного файла", "failed": "Ошибка", "missing": "Источник недоступен",
}


def register(bp):
    bp.add_url_rule("/storage/", "storage", resources)
    bp.add_url_rule("/storage/new", "storage_edit", resource_edit, methods=["GET", "POST"])
    bp.add_url_rule("/storage/<int:resource_id>", "storage_edit", resource_edit, methods=["GET", "POST"])
    bp.add_url_rule("/watches/", "watches", watches)
    bp.add_url_rule("/watches/new", "watch_edit", rule_edit, methods=["GET", "POST"])
    bp.add_url_rule("/watches/<int:rule_id>", "watch_edit", rule_edit, methods=["GET", "POST"])


def record(db, table, number):
    if number >= 2**63:
        abort(404)
    row = db.execute(f"SELECT * FROM {table} WHERE id=?", (number,)).fetchone()
    if row is None:
        abort(404)
    return dict(row)


def display_name():
    value = request.form.get("name", "").strip()
    if not 1 <= len(value) <= 120 or not value.isprintable():
        raise ValueError("Введите название длиной от 1 до 120 символов.")
    return value


def resources():
    rows = get_db().execute("SELECT id,name,kind,path,server,share FROM watch_resources ORDER BY name").fetchall()
    return render_template("watch/storage.html", resources=rows)


def save_resource(db, row, form):
    payload = {key: form[key] for key in RESOURCE_FIELDS}
    password = request.form.get("password", "")
    if len(password) > 2048:
        raise ValueError("Пароль SMB не должен превышать 2048 символов.")
    payload["password"] = protected(password) if payload["kind"] == "smb" and password else (row or {}).get("password", "")
    if payload["kind"] == "smb" and not payload["password"]:
        raise ValueError("Укажите пароль для подключения к ресурсу SMB.")
    value = watch_storage.validate_resource(payload)
    name = display_name()
    if row:
        location_changed = any(value[key] != row[key] for key in RESOURCE_FIELDS)
        if location_changed and db.execute(
            "SELECT 1 FROM watch_rules WHERE input_resource=? OR output_resource=? LIMIT 1", (row["id"], row["id"])
        ).fetchone():
            raise ValueError("Ресурс используется в правилах. Для другой папки или учётной записи создайте отдельный ресурс.")
        if row["kind"] == "smb" and not password and any(
            value[key] != row[key] for key in ("server", "port", "domain", "username")
        ):
            raise ValueError("Введите пароль SMB для нового сервера или учётной записи.")
    params = (name, *(value[key] for key in RESOURCE_FIELDS), value["password"])
    if row:
        db.execute("""UPDATE watch_resources SET name=?,kind=?,path=?,server=?,share=?,domain=?,username=?,port=?,password=?
                      WHERE id=?""", (*params, row["id"]))
        return row["id"]
    return db.execute("""INSERT INTO watch_resources(name,kind,path,server,share,domain,username,port,password)
                         VALUES (?,?,?,?,?,?,?,?,?)""", params).lastrowid


def resource_edit(resource_id=None):
    db = get_db()
    action = request.form.get("action", "save") if request.method == "POST" else None
    if action in ("save", "delete"):
        db.execute("BEGIN IMMEDIATE")
    row = record(db, "watch_resources", resource_id) if resource_id is not None else None
    kind = row["kind"] if row else request.values.get("kind", "local")
    if kind not in ("local", "smb"):
        abort(400)
    form = {key: (row or {}).get(key, "") for key in (*RESOURCE_FIELDS, "name")}
    form.update(kind=kind, port=form["port"] or 445)
    error = ""
    if action == "save":
        form.update({key: request.form.get(key, "").strip() for key in ("name", "path", "server", "share", "domain", "username")})
        form["port"] = request.form.get("port", "445")
        try:
            with db:
                resource_id = save_resource(db, row, form)
                audit("storage.saved", g.user["id"])
            flash("Ресурс сохранён.")
            return redirect(url_for("admin.storage_edit", resource_id=resource_id))
        except ValueError as exc:
            error = str(exc)
        except sqlite3.IntegrityError:
            error = "Ресурс с таким названием уже существует."
    elif action == "test" and row:
        try:
            with watch_storage.open_storage(row, current_app.secret_key) as store:
                store.probe()
            flash("Папка доступна для чтения.")
        except (OSError, ValueError):
            flash("Не удалось открыть папку. Проверьте адрес, учётные данные и права на чтение.", "error")
        return redirect(url_for("admin.storage_edit", resource_id=resource_id))
    elif action == "delete" and row:
        try:
            with db:
                db.execute("DELETE FROM watch_resources WHERE id=?", (resource_id,))
                audit("storage.deleted", g.user["id"])
        except sqlite3.IntegrityError:
            error = "Ресурс используется в правилах наблюдения. Сначала удалите или перенастройте эти правила."
        else:
            flash("Ресурс удалён.")
            return redirect(url_for("admin.storage"))
    elif action is not None:
        abort(400)
    return render_template("watch/resource.html", data=form, resource_id=resource_id, error=error), 400 if error else 200


def watches():
    db = get_db()
    rows = db.execute("""
        SELECT r.*,i.name AS input_name,
               datetime(nullif(r.last_scan,0),'unixepoch') AS scan_time,
               COUNT(f.id) FILTER (WHERE f.state IN ('settling','queued','running','publishing')) AS pending,
               COUNT(f.id) FILTER (WHERE f.state IN ('failed','conflict','missing')
                                   OR (f.state IN ('queued','publishing') AND f.error!='')) AS errors
        FROM watch_rules r JOIN watch_resources i ON i.id=r.input_resource
        LEFT JOIN watch_files f ON f.rule_id=r.id
        GROUP BY r.id ORDER BY r.name""").fetchall()
    return render_template("watch/rules.html", rules=rows)


def chosen_resource(db, key, *, optional=False):
    value = request.form.get(key, "")
    if optional and not value:
        return None
    if not value.isascii() or not value.isdigit() or len(value) > 19:
        raise ValueError("Выберите ресурс хранения из списка.")
    number = int(value)
    if number >= 2**63 or not db.execute("SELECT 1 FROM watch_resources WHERE id=?", (number,)).fetchone():
        raise ValueError("Выбранный ресурс хранения не найден.")
    return number


def save_rule(db, row):
    name = display_name()
    source = chosen_resource(db, "input_resource")
    target = chosen_resource(db, "output_resource", optional=True)
    input_folder = watch_storage.relative_folder(request.form.get("input_folder", ""))
    output_folder = watch_storage.relative_folder(request.form.get("output_folder", ""))
    if target is None and output_folder:
        raise ValueError("Для выбранной выходной подпапки укажите ресурс хранения.")
    source_changed = not row or (source, input_folder) != (row["input_resource"], row["input_folder"])
    if source_changed or "enabled" in request.form:
        location = storage_location(record(db, "watch_resources", source), input_folder)
        others = db.execute("""SELECT i.kind,i.path,i.server,i.port,i.share,r.input_folder
                               FROM watch_rules r JOIN watch_resources i ON i.id=r.input_resource
                               WHERE r.id!=?""", (row["id"] if row else 0,))
        if any(storage_location(other, other["input_folder"]) == location for other in others):
            raise ValueError("Эта входная папка уже используется в другом правиле наблюдения. Выберите другую папку.")
    route = (source, input_folder, target, output_folder)
    if row and route != tuple(row[k] for k in ROUTE_FIELDS) and db.execute(
        "SELECT 1 FROM watch_files WHERE rule_id=? LIMIT 1", (row["id"],)
    ).fetchone():
        raise ValueError("Для изменения папок правила с историей обработки создайте новое правило.")
    params = (name, *route, int("delete_source" in request.form), int("enabled" in request.form))
    if row:
        db.execute("""UPDATE watch_rules SET name=?,input_resource=?,input_folder=?,output_resource=?,output_folder=?,
                      delete_source=?,enabled=?,last_scan=0 WHERE id=?""", (*params, row["id"]))
        return row["id"]
    return db.execute("""INSERT INTO watch_rules(name,input_resource,input_folder,output_resource,output_folder,
                         delete_source,enabled) VALUES (?,?,?,?,?,?,?)""", params).lastrowid


def rule_edit(rule_id=None):
    db = get_db()
    action = request.form.get("action", "save") if request.method == "POST" else None
    if action is not None:
        db.execute("BEGIN IMMEDIATE")
    row = record(db, "watch_rules", rule_id) if rule_id is not None else None
    form = dict(row or {"name": "", "input_resource": None, "input_folder": "", "output_resource": None,
                        "output_folder": "", "enabled": True, "delete_source": False})
    error = ""
    if action is not None:
        try:
            with db:
                if action == "save":
                    form.update({key: request.form.get(key, "") for key in ("name", *ROUTE_FIELDS)})
                    form.update(enabled="enabled" in request.form, delete_source="delete_source" in request.form)
                    rule_id = save_rule(db, row)
                    message = "Правило сохранено."
                elif action == "delete" and row:
                    if row["enabled"] and db.execute("""SELECT 1 FROM watch_files WHERE rule_id=? AND state IN ('running','publishing')
                                  LIMIT 1""", (rule_id,)).fetchone():
                        raise ValueError("Идёт обработка. Дождитесь её завершения или выключите наблюдение перед удалением правила.")
                    db.execute("DELETE FROM watch_rules WHERE id=?", (rule_id,))
                    message = "Правило и его журнал удалены."
                elif action == "scan" and row and row["enabled"]:
                    db.execute("UPDATE watch_rules SET last_scan=0 WHERE id=?", (rule_id,))
                    message = "Обработчик проверит папку при следующем обходе."
                elif action == "retry" and row:
                    file_id = request.form.get("file_id", type=int)
                    if not file_id or not 0 < file_id < 2**63 or not db.execute(
                        """UPDATE watch_files SET state='queued',retry_at=0,error=''
                           WHERE id=? AND rule_id=? AND state='failed'""", (file_id, rule_id)
                    ).rowcount:
                        raise ValueError("В этом правиле нет такой записи для повтора.")
                    message = "Запись возвращена в очередь."
                else:
                    abort(400)
                audit("watch." + action, g.user["id"])
            flash(message)
            if action == "delete":
                return redirect(url_for("admin.watches"))
            return redirect(url_for("admin.watch_edit", rule_id=rule_id))
        except ValueError as exc:
            error = str(exc)
        except sqlite3.IntegrityError:
            error = "Название правила или входная папка уже используется. Проверьте настройки правила."
    files = []
    if row:
        files = db.execute("""SELECT id,name,output_name,state,error,datetime(updated,'unixepoch') AS changed
                              FROM watch_files WHERE rule_id=? ORDER BY updated DESC,id DESC LIMIT 50""", (rule_id,)).fetchall()
    choices = db.execute("SELECT id,name FROM watch_resources ORDER BY name").fetchall()
    return render_template("watch/rule.html", rule_id=rule_id, row=row, data=form, choices=choices,
                           files=files, states=STATES, error=error), 400 if error else 200
