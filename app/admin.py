import json
import os
import re
import socket
import sqlite3
import ssl
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for
from ldap3.utils.dn import parse_dn

from . import directory, journal, telemetry, watch_admin
from .asr_store import model_status
from .auth import digest, protected, reveal
from .db import audit, auth_settings, get_db

bp = Blueprint("admin", __name__, url_prefix="/admin")
watch_admin.register(bp)
bp.add_url_rule("/journal/", "journal", journal.index)
bp.add_url_rule("/journal/export.csv", "journal_csv", journal.export)
bp.add_app_template_filter(journal.title, "audit_event")


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


def directory_admin(config, person):
    groups = config.get("admin_groups", [])
    return config.get("use_for_admins", True) and (
        person.external_id in config.get("admin_users", {}) or
        bool(groups) and directory.group_allowed(person.groups, groups))


def directory_login(login, password):
    db = get_db()
    if not re.fullmatch(r"[\w.\-]+(?:[@\\][\w.\-]+)?", login):
        return None
    for row in db.execute("SELECT * FROM directories WHERE enabled=1 ORDER BY coalesce(json_extract(config,'$.priority'),100),id").fetchall():
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
        key = f"ldap:{row['id']}:{user.external_id}"
        with db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM directories WHERE id=? AND enabled=1 AND config=? AND password=?",
                              (row["id"], row["config"], row["password"])).fetchone():
                return None
            if not directory_admin(cfg, user):
                db.execute("UPDATE users SET admin=0 WHERE identity=?", (key,))
                db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE identity=?)", (key,))
                return None
            db.execute("""INSERT INTO users(identity,username,display_name,admin) VALUES (?,?,?,?)
                ON CONFLICT(identity) DO UPDATE SET username=excluded.username,
                display_name=excluded.display_name,admin=excluded.admin""", (key, user.login, user.display_name, 1))
        return db.execute("SELECT * FROM users WHERE identity=? AND disabled=0", (key,)).fetchone()
    return None


@bp.get("/")
def index():
    db = get_db()
    profiles = db.execute("SELECT id,name,enabled FROM directories ORDER BY coalesce(json_extract(config,'$.priority'),100),id").fetchall()
    counts = db.execute("""SELECT (SELECT COUNT(*) FROM users WHERE identity NOT LIKE 'guest:%') AS users,
        (SELECT COUNT(*) FROM sessions WHERE expires>unixepoch()) AS sessions,
        (SELECT COUNT(*) FROM transcripts WHERE status='queued') +
        (SELECT COUNT(*) FROM watch_files f JOIN watch_rules r ON r.id=f.rule_id
         WHERE r.enabled AND r.kind='transcription' AND f.state='queued') AS queued""").fetchone()
    events = db.execute("""SELECT a.time,a.event,u.username,t.username AS target FROM audit a
        LEFT JOIN users u ON u.id=a.actor LEFT JOIN users t ON t.id=a.target_user
        ORDER BY a.id DESC LIMIT 25""").fetchall()
    status = {}
    try:
        status = json.loads((Path(os.getenv("CONTROL_DIR", "/control")) / "status.json").read_text())
    except (OSError, ValueError):
        pass
    data = current_app.config["DATA_DIR"]
    return render_template("admin.html", profiles=profiles, counts=counts, events=events, status=status,
                           policy=auth_settings(), model_status=model_status(data), system=telemetry.system_info(data),
                           operator=operator_state())


@bp.get("/system-metrics")
def system_metrics():
    return telemetry.admin_counters(current_app.config["DATA_DIR"])


@bp.post("/access")
def access():
    limits = (("hours", 1, 168), ("attempts_user", 3, 100), ("attempts_ip", 3, 500), ("minutes", 1, 60))
    values = [request.form.get(key, type=int) for key, _, _ in limits]
    if any(value is None or not low <= value <= high for value, (_, low, high) in zip(values, limits)):
        abort(400, description="Проверьте срок сеанса, пороги и длительность блокировки.")
    with get_db() as db:
        db.execute("UPDATE auth_settings SET hours=?,attempts_user=?,attempts_ip=?,minutes=?,admin_totp=? WHERE id=1",
                   (*values, int("admin_totp" in request.form)))
        audit("access.saved", g.user["id"])
    flash("Политика входа сохранена.")
    return redirect(url_for("admin.index"))


@bp.get("/users/")
def users():
    db = get_db()
    query = request.args.get("q", "").strip()[:256]
    before = request.args.get("before", type=int)
    active = request.args.get("active") == "1"
    if before is not None and not 0 < before < 2**63:
        abort(400)
    rows = db.execute("""
        SELECT u.id,u.username,u.display_name,u.admin,u.disabled,u.identity='local:admin' AS local,
               u.totp IS NOT NULL AS has_totp,d.name AS directory,d.enabled AS directory_enabled,
               (SELECT COUNT(*) FROM sessions WHERE user_id=u.id AND expires>unixepoch()) AS sessions
        FROM users u LEFT JOIN directories d ON u.identity LIKE 'ldap:' || d.id || ':%'
        WHERE u.identity NOT LIKE 'guest:%' AND (? IS NULL OR u.id<?) AND instr(casefold(u.username || ' ' || u.display_name), ?) > 0
        AND (NOT ? OR EXISTS(SELECT 1 FROM sessions WHERE user_id=u.id AND expires>unixepoch()))
        ORDER BY u.id DESC LIMIT 51
    """, (before, before, query.casefold(), active)).fetchall()
    return render_template("users.html", users=rows[:50], more=len(rows) > 50, query=query, before=before, active=active)


@bp.post("/users/<int:user_id>/access")
def user_access(user_id):
    if user_id >= 2**63:
        abort(404)
    action = request.form.get("action")
    if action not in {"disable", "enable"}:
        abort(400)
    disabled = int(action == "disable")
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT identity,disabled FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None or user["identity"].startswith("guest:"):
            abort(404)
        if user["identity"] == "local:admin" or user_id == g.user["id"]:
            abort(400, description="Для этой учётной записи изменение доступа недоступно.")
        if user["disabled"] != disabled:
            db.execute("UPDATE users SET disabled=? WHERE id=?", (disabled, user_id))
            if disabled:
                db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            audit("user.disabled" if disabled else "user.enabled", g.user["id"], target=user_id)
    flash("Доступ отключён. Сеансы завершены." if disabled else "Доступ включён.")
    return redirect(url_for("admin.users", q=request.args.get("q"), before=request.args.get("before", type=int),
                            active="1" if request.args.get("active") == "1" else None))


@bp.post("/users/<int:user_id>/revoke")
def revoke(user_id):
    if user_id >= 2**63:
        abort(404)
    with get_db() as db:
        if not db.execute("SELECT 1 FROM users WHERE id=? AND identity NOT LIKE 'guest:%'", (user_id,)).fetchone():
            abort(404)
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit("sessions.revoked", g.user["id"], target=user_id)
    flash("Сеансы пользователя завершены.")
    return redirect(url_for("admin.users", q=request.args.get("q"), before=request.args.get("before", type=int),
                            active="1" if request.args.get("active") == "1" else None))


def operator_request(operation):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(1)
        sock.connect(os.getenv("CONTROL_DIR", "/control") + "/operator.sock")
        sock.sendall((digest(current_app.secret_key + ":operator") + " " + operation + "\n").encode())
        return sock.makefile("rb").readline(32).strip()


def operator_state():
    if (Path(os.getenv("CONTROL_DIR", "/control")) / "operator-disabled").is_file():
        return "disabled"
    try:
        reply = operator_request("ping")
        # Helpers predating the ping command reply "no" but still accept signed operations.
        return {b"ready": "ready", b"no": "legacy", b"busy": "busy", b"disabled": "disabled"}.get(reply, "unavailable")
    except OSError:
        return "unavailable"


@bp.post("/maintenance")
def maintenance():
    op = request.form.get("operation", "")
    if op not in {"check", "update", "rollback", "backup"}:
        abort(400)
    if (Path(os.getenv("CONTROL_DIR", "/control")) / "operator-disabled").is_file():
        flash("Веб-управление отключено при установке. Команды для сервера приведены ниже.")
        return redirect(url_for("admin.index"))
    try:
        if operator_request(op) == b"ok":
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
                previous = json.loads(row["config"]) if row else {}
                data["user_groups"] = previous.get("user_groups", [])
                data["use_for_users"] = previous.get("use_for_users", bool(row))
                data["admin_groups"] = list(dict.fromkeys(line.strip() for line in request.form.get("admin_groups", "").splitlines() if line.strip()))
                selected = request.form.getlist("admin_user")
                if len(selected) + len(data["admin_groups"]) > 256:
                    raise ValueError("В одном подключении можно выбрать до 256 назначений.")
                data["admin_users"] = {}
                for value in selected:
                    uid, _, label = value.partition("|")
                    data["admin_users"][str(UUID(uid))] = label[:256] or uid
                data["priority"] = int(request.form.get("priority", 100))
                if not 1 <= data["priority"] <= 9999:
                    raise ValueError("Порядок проверки должен быть от 1 до 9999.")
                data["use_for_admins"] = "use_for_admins" in request.form or "role_flags" not in request.form
                certificate = request.files.get("certificate")
                if certificate and certificate.filename:
                    raw = certificate.stream.read(65537)
                    if len(raw) > 65536:
                        raise ValueError("Файл сертификата больше 64 КиБ.")
                    try:
                        data["ca"] = (raw.decode("ascii") if raw.lstrip().startswith(b"-----") else
                                      x509.load_der_x509_certificate(raw).public_bytes(Encoding.PEM).decode("ascii"))
                    except ValueError:
                        raise ValueError("Требуется сертификат в формате PEM или DER.") from None
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
                        profile_id = db.execute("INSERT INTO directories(name,config,password,enabled) VALUES (?,?,?,?)", values).lastrowid
                    audit("directory.saved", g.user["id"])
                flash("Подключение сохранено.")
                return redirect(url_for("admin.profile", profile_id=profile_id))
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
                        allowed = directory_admin(data, person)
                        blocked = db.execute("SELECT 1 FROM users WHERE identity=? AND disabled=1",
                                             (f"ldap:{row['id']}:{person.external_id}",)).fetchone()
                        detail = "Администратор" if allowed else "Администрирование не назначено"
                        if blocked or not row["enabled"]:
                            allowed = False
                            detail = "Учётная запись отключена в IS Manager" if blocked else "Подключение отключено"
                        steps.append(dict(step="access", ok=allowed, detail=detail))
            else:
                abort(400)
        except (ValueError, ssl.SSLError, directory.LdapError, sqlite3.IntegrityError) as exc:
            error = "Название подключения уже используется." if isinstance(exc, sqlite3.IntegrityError) else str(exc)
    return render_template("directory.html", row=row, data=data, steps=steps, error=error)


@bp.get("/directory/<int:profile_id>/principals")
def principals(profile_id):
    row = get_db().execute("SELECT * FROM directories WHERE id=?", (profile_id,)).fetchone()
    if row is None:
        abort(404)
    try:
        return {"items": directory.search_principals(profile_config(row), request.args.get("q", "").strip())}
    except directory.LdapError as exc:
        return {"error": "Каталог недоступен для поиска. Проверьте сохранённое подключение и права сервисной записи.",
                "code": exc.code}, 502
    except ValueError as exc:
        return {"error": str(exc)}, 400


def revoke_profile(db, profile_id):
    db.execute("UPDATE users SET admin=0 WHERE identity LIKE ?", (f"ldap:{profile_id}:%",))
    db.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE identity LIKE ?)",
               (f"ldap:{profile_id}:%",))
