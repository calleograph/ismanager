import json
import os
import re
import socket
import sqlite3
import ssl
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for
from ldap3.utils.dn import parse_dn

from . import directory
from .auth import digest, protected, reveal
from .db import audit, get_db

bp = Blueprint("admin", __name__, url_prefix="/admin")


def profile_config(row):
    data = json.loads(row["config"])
    ad = data["kind"] == "ad"
    return directory.DirectoryConfig(
        id=str(row["id"]), kind=data["kind"], hosts=(data["host"],),
        port=data["port"], encryption=data["protocol"], ca_cert=data["ca"], timeout=data["timeout"],
        bind_dn=data["bind_dn"], bind_password=reveal(row["password"]), base_dn=data["base_dn"],
        user_filter="(&(objectCategory=person)(objectClass=user))" if ad else "(objectClass=inetOrgPerson)",
        login_attr=data["login_attr"] or ("sAMAccountName" if ad else "uid"),
        id_attr="objectGUID" if ad else "entryUUID", name_attr=data["name_attr"] or "displayName",
    )


def roles(config, groups):
    is_admin = bool(config["admin_groups"]) and directory.group_allowed(groups, config["admin_groups"])
    return is_admin or directory.group_allowed(groups, config["user_groups"]), is_admin


def directory_login(login, password):
    db = get_db()
    if not re.fullmatch(r"[\w.\-]+(?:[@\\][\w.\-]+)?", login):
        return None
    for row in db.execute("SELECT * FROM directories WHERE enabled=1 ORDER BY id").fetchall():
        cfg = json.loads(row["config"])
        if "\\" in login and cfg["domain"].casefold() != login.split("\\", 1)[0].casefold():
            continue
        if "@" in login and cfg["suffix"] and cfg["suffix"].casefold() != login.rsplit("@", 1)[1].casefold():
            continue
        try:
            user = directory.authenticate(profile_config(row), login, password)
        except directory.LdapError as exc:
            if exc.code in {"not_found", "unavailable", "tls_error", "config_error"}:
                continue
            return None
        allowed, admin = roles(cfg, user.groups)
        if not allowed:
            return None
        key = f"ldap:{row['id']}:{user.external_id}"
        with db:
            db.execute("""INSERT INTO users(identity,username,display_name,admin) VALUES (?,?,?,?)
                ON CONFLICT(identity) DO UPDATE SET username=excluded.username,
                display_name=excluded.display_name,admin=excluded.admin""", (key, user.login, user.display_name, admin))
        return db.execute("SELECT * FROM users WHERE identity=?", (key,)).fetchone()
    return None


@bp.get("/")
def index():
    db = get_db()
    profiles = db.execute("SELECT id,name,enabled FROM directories ORDER BY id").fetchall()
    sessions = db.execute("""SELECT u.id,u.display_name,COUNT(*) AS n FROM sessions s JOIN users u
        ON u.id=s.user_id WHERE s.expires>unixepoch() GROUP BY u.id ORDER BY u.display_name""").fetchall()
    events = db.execute("""SELECT a.time,a.event,u.username FROM audit a LEFT JOIN users u ON u.id=a.actor
        ORDER BY a.id DESC LIMIT 25""").fetchall()
    status = {}
    try:
        status = json.loads((Path(os.getenv("CONTROL_DIR", "/control")) / "status.json").read_text())
    except (OSError, ValueError):
        pass
    return render_template("admin.html", profiles=profiles, sessions=sessions, events=events, status=status)


@bp.post("/users/<int:user_id>/revoke")
def revoke(user_id):
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit("sessions.revoked", g.user["id"])
    flash("Сеансы пользователя завершены.")
    return redirect(url_for("admin.index"))


@bp.post("/maintenance")
def maintenance():
    op = request.form.get("operation", "")
    if op not in {"check", "update", "rollback", "backup"}:
        abort(400)
    try:
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(4)
            sock.connect(os.getenv("CONTROL_DIR", "/control") + "/operator.sock")
            sock.sendall((digest(current_app.secret_key + ":operator") + " " + op + "\n").encode())
            reply = sock.makefile("rb").readline(32)
        if reply == b"ok\n":
            with get_db():
                audit("maintenance." + op, g.user["id"])
            flash("Задача принята. Обновите страницу для просмотра результата.")
        else:
            flash("Помощник занят или запрос отклонён.", "error")
    except OSError:
        flash("Помощник обновлений недоступен. На сервере выполните ./install.sh --operator.", "error")
    return redirect(url_for("admin.index"))


def validate(data):
    if data["kind"] not in {"ad", "openldap"} or data["protocol"] not in {"ldaps", "starttls"}:
        raise ValueError("Выберите протокол и тип каталога.")
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", data["host"]):
        raise ValueError("Укажите имя узла или IPv4-адрес.")
    if not 1 <= data["port"] <= 65535 or not 1 <= data["timeout"] <= 60:
        raise ValueError("Проверьте порт и таймаут (1–60 секунд).")
    if not data["bind_dn"] or not data["base_dn"]:
        raise ValueError("Укажите сервисную запись и Base DN.")
    for attr in (data["login_attr"], data["name_attr"]):
        if attr and not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]{0,63}", attr):
            raise ValueError("Некорректное имя атрибута.")
    for dn in [data["base_dn"], *data["admin_groups"], *data["user_groups"]]:
        try:
            parse_dn(dn)
        except Exception as exc:
            raise ValueError("Проверьте DN базы и групп. Каждая группа занимает отдельную строку.") from exc
    if data["ca"]:
        if not re.fullmatch(r"(?:\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+", data["ca"]):
            raise ValueError("Загрузите только публичный сертификат CA в PEM.")
        ssl.create_default_context(cadata=data["ca"])


@bp.route("/directory/", defaults={"profile_id": None}, methods=["GET", "POST"])
@bp.route("/directory/<int:profile_id>", methods=["GET", "POST"])
def profile(profile_id):
    db = get_db()
    row = db.execute("SELECT * FROM directories WHERE id=?", (profile_id,)).fetchone()
    if profile_id and row is None:
        abort(404)
    data = json.loads(row["config"]) if row else {}
    steps = []
    error = ""
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "save":
                data = {key: request.form.get(key, "").strip() for key in
                        ("host", "protocol", "kind", "domain", "suffix", "ca", "base_dn", "bind_dn", "login_attr", "name_attr")}
                data.update(port=int(request.form.get("port", 636)), timeout=int(request.form.get("timeout", 5)))
                for key in ("user_groups", "admin_groups"):
                    data[key] = [line.strip() for line in request.form.get(key, "").splitlines() if line.strip()]
                validate(data)
                name = request.form.get("name", "").strip()
                pwd = request.form.get("password", "")
                if not 1 <= len(name) <= 120 or (not pwd and not row):
                    raise ValueError("Укажите название подключения и пароль сервисной записи.")
                values = (name, json.dumps(data, ensure_ascii=False), protected(pwd) if pwd else row["password"], int("enabled" in request.form))
                with db:
                    if row:
                        db.execute("UPDATE directories SET name=?,config=?,password=?,enabled=? WHERE id=?", (*values, profile_id))
                        revoke_profile(db, profile_id)
                    else:
                        db.execute("INSERT INTO directories(name,config,password,enabled) VALUES (?,?,?,?)", values)
                    audit("directory.saved", g.user["id"])
                flash("Подключение сохранено.")
                return redirect(url_for("admin.index"))
            if row is None:
                abort(400)
            if action == "delete":
                with db:
                    revoke_profile(db, profile_id)
                    db.execute("DELETE FROM directories WHERE id=?", (profile_id,))
                    audit("directory.deleted", g.user["id"])
                return redirect(url_for("admin.index"))
            if action == "test":
                user = request.form.get("test_user", "").strip() or None
                steps = directory.diagnose(profile_config(row), user, request.form.get("test_password") or None)
                if user and all(step["ok"] for step in steps):
                    person = directory.lookup(profile_config(row), user, True)
                    if person:
                        allowed, admin = roles(data, person.groups)
                        steps.append(dict(step="access", ok=allowed, detail="Администратор" if admin else "Допуск разрешён" if allowed else "Доступ закрыт"))
            else:
                abort(400)
        except (ValueError, ssl.SSLError, directory.LdapError, sqlite3.IntegrityError) as exc:
            error = "Название подключения уже используется." if isinstance(exc, sqlite3.IntegrityError) else str(exc)
    return render_template("directory.html", row=row, data=data, steps=steps, error=error)


def revoke_profile(db, profile_id):
    db.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE identity LIKE ?)",
               (f"ldap:{profile_id}:%",))
