"""Administrator screens for transcription resources and folder watches."""
import sqlite3

from flask import abort, current_app, flash, g, redirect, render_template, request, url_for

from . import watch_storage
from .auth import protected
from .db import audit, get_db
from .folder_watch import output_location, storage_location

RESOURCE_FIELDS = ("kind", "path", "server", "share", "domain", "username", "port")
KINDS = {"transcription": "Транскрибация", "redaction": "Обезличивание"}
ROUTE_FIELDS = ("input_resource", "input_folder", "output_resource", "output_folder")
STATES = {
    "settling": "Ожидается завершение записи", "queued": "В очереди", "running": "Распознаётся",
    "publishing": "Сохраняется текст", "done": "Готово", "existing": "Текст уже существует",
    "conflict": "Конфликт выходного файла", "failed": "Ошибка", "missing": "Источник недоступен",
}


def register(bp):
    bp.add_url_rule("/storage/", "storage", resources)
    bp.add_url_rule("/storage/options", "storage_options", storage_options)
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


def page_number(key="page"):
    page = request.args.get(key, 1, type=int)
    if not 1 <= page <= 10_000_000:
        abort(400)
    return page


def list_position():
    query = request.args.get("q", "").strip()[:256]
    page = page_number()
    return {"q": query or None, "page": page if page>1 else None}


def resource_rows(query, offset=0):
    return get_db().execute("""
        SELECT id,name,kind,path,server,share FROM watch_resources
        WHERE instr(casefold(name || ' ' || path || ' ' || server || ' ' || share), ?) > 0
        ORDER BY name,id LIMIT 51 OFFSET ?
    """, (query.casefold(), offset)).fetchall()


def storage_options():
    rows = resource_rows(request.args.get("q", "").strip()[:256])
    return {"items": [{"id": row["id"], "name": row["name"]} for row in rows[:50]], "more": len(rows)>50}


def resources():
    query = request.args.get("q", "").strip()[:256]
    page = page_number()
    rows = resource_rows(query, (page-1)*50)
    return render_template("watch/storage.html", resources=rows[:50],query=query,page=page,more=len(rows)>50)


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
            return redirect(url_for("admin.storage_edit", resource_id=resource_id, **list_position()))
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
        return redirect(url_for("admin.storage_edit", resource_id=resource_id, **list_position()))
    elif action == "delete" and row:
        try:
            with db:
                db.execute("DELETE FROM watch_resources WHERE id=?", (resource_id,))
                audit("storage.deleted", g.user["id"])
        except sqlite3.IntegrityError:
            error = "Ресурс используется в правилах наблюдения. Сначала удалите или перенастройте эти правила."
        else:
            flash("Ресурс удалён.")
            return redirect(url_for("admin.storage", **list_position()))
    elif action is not None:
        abort(400)
    return render_template("watch/resource.html", data=form, resource_id=resource_id, error=error, position=list_position()), 400 if error else 200


def watches():
    db = get_db()
    kind = request.args.get("kind", "")
    if kind and kind not in KINDS:
        abort(400)
    query = request.args.get("q", "").strip()[:256]
    page = page_number()
    rows = db.execute("""
        WITH selected AS (
            SELECT r.*,i.name AS input_name FROM watch_rules r JOIN watch_resources i ON i.id=r.input_resource
            WHERE (?='' OR r.kind=?) AND instr(casefold(r.name || ' ' || i.name || ' ' || r.input_folder),?)>0
            ORDER BY r.name,r.id LIMIT 51 OFFSET ?
        )
        SELECT r.*,
               datetime(nullif(r.last_scan,0),'unixepoch') AS scan_time,
               COUNT(f.id) FILTER (WHERE f.state IN ('settling','queued','running','publishing')) AS pending,
               COUNT(f.id) FILTER (WHERE f.state IN ('failed','conflict','missing')
                                   OR (f.state IN ('queued','publishing') AND f.error!='')) AS errors
        FROM selected r LEFT JOIN watch_files f ON f.rule_id=r.id
            AND f.state IN ('settling','queued','running','publishing','failed','conflict','missing')
        GROUP BY r.id ORDER BY r.name,r.id""", (kind, kind, query.casefold(), (page-1)*50)).fetchall()
    return render_template("watch/rules.html", rules=rows[:50], kinds=KINDS, kind=kind,
                           query=query, page=page, more=len(rows)>50)


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


def validate_rule_folders(db, proposed, rule_id):
    resources = {r["id"]: r for r in db.execute("SELECT id,kind,path,server,port,share FROM watch_resources")}

    def folders(rule):
        output, folder = output_location(rule)
        return (storage_location(resources[rule["input_resource"]], rule["input_folder"]),
                storage_location(resources[output], folder))

    source, target = folders(proposed)
    redact = proposed["kind"] == "redaction"
    if redact and source == target:
        raise ValueError("Для обезличенного текста выберите другую выходную папку.")
    for other in db.execute("SELECT * FROM watch_rules WHERE id!=? AND kind=?", (rule_id, proposed["kind"])):
        other_source, other_target = folders(other)
        if source == other_source:
            raise ValueError("Эта входная папка уже используется в другом правиле того же назначения.")
        if redact and (source == other_target or target == other_source):
            raise ValueError("Вход одного правила обезличивания не может быть выходом другого.")


def save_rule(db, row):
    name = display_name()
    kind = request.form.get("kind", row["kind"] if row else request.args.get("kind", "transcription"))
    if kind not in KINDS or (row and kind != row["kind"]):
        raise ValueError("Выберите назначение при создании нового правила.")
    source = chosen_resource(db, "input_resource")
    target = chosen_resource(db, "output_resource", optional=True)
    input_folder = watch_storage.relative_folder(request.form.get("input_folder", ""))
    output_folder = watch_storage.relative_folder(request.form.get("output_folder", ""))
    if target is None and output_folder:
        raise ValueError("Для выбранной выходной подпапки укажите ресурс хранения.")
    route = (source, input_folder, target, output_folder)
    if not row or route != tuple(row[k] for k in ROUTE_FIELDS) or "enabled" in request.form:
        validate_rule_folders(db, dict(kind=kind, **dict(zip(ROUTE_FIELDS, route))), row["id"] if row else 0)
    if row and route != tuple(row[k] for k in ROUTE_FIELDS) and db.execute(
        "SELECT 1 FROM watch_files WHERE rule_id=? LIMIT 1", (row["id"],)
    ).fetchone():
        raise ValueError("Для изменения папок правила с историей обработки создайте новое правило.")
    params = (name, *route, int(kind == "transcription" and "delete_source" in request.form), int("enabled" in request.form))
    if row:
        db.execute("""UPDATE watch_rules SET name=?,input_resource=?,input_folder=?,output_resource=?,output_folder=?,
                      delete_source=?,enabled=?,last_scan=0 WHERE id=?""", (*params, row["id"]))
        return row["id"]
    return db.execute("""INSERT INTO watch_rules(name,input_resource,input_folder,output_resource,output_folder,
                         delete_source,enabled,kind) VALUES (?,?,?,?,?,?,?,?)""", (*params, kind)).lastrowid


def rule_edit(rule_id=None):
    db = get_db()
    action = request.form.get("action", "save") if request.method == "POST" else None
    file_query = request.args.get("file_q", "").strip()[:256]
    file_state = request.args.get("file_state", "").strip()
    file_page = page_number("file_page")
    if file_state and file_state not in STATES:
        abort(400)
    if action is not None:
        db.execute("BEGIN IMMEDIATE")
    row = record(db, "watch_rules", rule_id) if rule_id is not None else None
    kind = request.args.get("kind", "transcription")
    if kind not in KINDS:
        abort(400)
    form = dict(row or {"name": "", "kind": kind, "input_resource": None, "input_folder": "", "output_resource": None,
                        "output_folder": "", "enabled": True, "delete_source": False})
    error = ""
    if action is not None:
        try:
            with db:
                if action == "save":
                    form.update({key: request.form.get(key, "") for key in ("name", *ROUTE_FIELDS)})
                    form["kind"] = request.form.get("kind", form["kind"])
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
                        """UPDATE watch_files SET state='queued',retry_at=0,recoveries=0,error=''
                           WHERE id=? AND rule_id=? AND state='failed'""", (file_id, rule_id)
                    ).rowcount:
                        raise ValueError("В этом правиле нет такой записи для повтора.")
                    message = "Запись возвращена в очередь."
                else:
                    abort(400)
                audit("watch." + action, g.user["id"])
            flash(message)
            if action == "delete":
                return redirect(url_for("admin.watches", **list_position(), kind=request.args.get("kind") or None))
            return redirect(url_for("admin.watch_edit", rule_id=rule_id, **list_position(), kind=request.args.get("kind") or None, file_q=file_query or None,
                                    file_state=file_state or None, file_page=file_page if file_page>1 else None,
                                    _anchor="files" if action in ("scan", "retry") else None))
        except ValueError as exc:
            error = str(exc)
        except sqlite3.IntegrityError:
            error = "Название правила или входная папка уже используется. Проверьте настройки правила."
    files = []
    if row:
        files = db.execute("""SELECT id,name,output_name,state,error,processing_note,datetime(updated,'unixepoch') AS changed
                              FROM watch_files WHERE rule_id=? AND (?='' OR state=?)
                              AND instr(casefold(name || ' ' || output_name),?)>0
                              ORDER BY updated DESC,id DESC LIMIT 51 OFFSET ?""",
                           (rule_id,file_state,file_state,file_query.casefold(),(file_page-1)*50)).fetchall()
    choice_query = request.args.get("resource_q", "").strip()[:256]
    rows = resource_rows(choice_query)
    choices = list(rows[:50])
    selected = {form.get("input_resource"), form.get("output_resource")}
    visible = {str(option["id"]) for option in choices}
    for number in selected:
        if number and str(number) not in visible:
            saved = db.execute("SELECT id,name FROM watch_resources WHERE id=?", (str(number),)).fetchone()
            if saved:
                choices.append(saved)
    has_resources = bool(choices) or bool(db.execute("SELECT 1 FROM watch_resources LIMIT 1").fetchone())
    states = STATES | {"running": "Обезличивается"} if form["kind"] == "redaction" else STATES
    return render_template("watch/rule.html", rule_id=rule_id, row=row, data=form, choices=choices,
                           files=files[:50], file_more=len(files)>50, file_page=file_page, file_query=file_query,
                           file_state=file_state, position=list_position(), states=states, kinds=KINDS, error=error, choice_query=choice_query,
                           large=len(rows)>50 or bool(choice_query), has_resources=has_resources), 400 if error else 200
