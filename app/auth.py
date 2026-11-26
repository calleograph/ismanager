import base64
import hashlib
import secrets
import time

import click
import pyotp
from cryptography.fernet import Fernet
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from flask.cli import with_appcontext
from werkzeug.security import check_password_hash, generate_password_hash

from .db import audit, get_db

bp = Blueprint("auth", __name__)
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe())


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def cipher():
    key = hashlib.sha256(b"ismanager.credentials.v1:" + current_app.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def protected(text):
    return cipher().encrypt(text.encode()).decode()


def reveal(text):
    return cipher().decrypt(text.encode()).decode()


def limited(login):
    """Reserve an attempt before the slow bind, including concurrent requests."""
    db = get_db()
    now = int(time.time())
    with db:
        db.execute("DELETE FROM attempts WHERE until<=?", (now,))
        for key, maximum in ((digest("ip:" + str(request.remote_addr)), 80), (digest("user:" + login.casefold()), 12)):
            db.execute("INSERT INTO attempts VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1",
                       (key, now + 300))
            if db.execute("SELECT count FROM attempts WHERE key=?", (key,)).fetchone()[0] > maximum:
                return True
    return False


def begin(user_id):
    db = get_db()
    now = int(time.time())
    new_sid = secrets.token_urlsafe(32)
    with db:
        db.execute("DELETE FROM sessions WHERE expires<=? OR token=?", (now, digest(session.get("sid", ""))))
        db.execute("INSERT INTO sessions VALUES (?,?,?)", (digest(new_sid), user_id, now + 43200))
    session.clear()
    session.permanent = True
    session["sid"] = new_sid


def accept_totp(user, code):
    now = int(time.time() // 30)
    otp = pyotp.TOTP(reveal(user["totp"]))
    for step in (now, now - 1, now + 1):
        if secrets.compare_digest(otp.at(step * 30), code) and step > user["last_step"]:
            with get_db() as db:
                return db.execute("UPDATE users SET last_step=? WHERE id=? AND last_step<?",
                                  (step, user["id"], step)).rowcount == 1
    return False


@bp.route("/login", methods=["GET", "POST"])
def login():
    from .admin import directory_login
    if request.method == "GET":
        return redirect(url_for("dashboard")) if g.user else render_template("login.html")
    name = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if limited(name[:256]):
        return render_template("login.html", error="Слишком много попыток. Повторите через пять минут."), 429
    db = get_db()
    user = None
    if name and len(name) <= 256 and password and len(password) <= 4096:
        if name.casefold() == "admin":
            item = db.execute("SELECT * FROM users WHERE identity='local:admin'").fetchone()
            if check_password_hash(item["password"] if item else DUMMY_HASH, password):
                user = item
        else:
            user = directory_login(name, password)
    code = request.form.get("code", "").strip()
    if user is None or (user["totp"] and not (code.isascii() and code.isdigit() and accept_totp(user, code))):
        with db:
            audit("login.denied")
        return render_template("login.html", error="Вход отклонён. Проверьте данные и код, если включена двухфакторная защита."), 401
    with db:
        db.execute("DELETE FROM attempts WHERE key=?", (digest("user:" + name.casefold()),))
        audit("login.ok", user["id"])
    begin(user["id"])
    return redirect(url_for("auth.account" if user["must_change"] else "dashboard"))


@bp.post("/logout")
def logout():
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE token=?", (digest(session.get("sid", "")),))
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/account", methods=["GET", "POST"])
def account():
    user = g.user
    db = get_db()
    pending = session.get("enroll")
    if request.method == "POST":
        action = request.form.get("action")
        if action == "password" and user["identity"] == "local:admin":
            new = request.form.get("new", "")
            if (not check_password_hash(user["password"], request.form.get("current", "")) or
                    not 12 <= len(new) <= 1024 or
                    sum(any(test(c) for c in new) for test in (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum())) < 2 or
                    new == request.form.get("current") or new != request.form.get("repeat")):
                flash("Проверьте текущий пароль и повтор нового пароля длиной от 12 символов.", "error")
            else:
                with db:
                    db.execute("UPDATE users SET password=?,must_change=0 WHERE id=?", (generate_password_hash(new), user["id"]))
                    db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
                    audit("password.changed", user["id"])
                begin(user["id"])
                flash("Пароль изменён.")
                return redirect(url_for("dashboard"))
        elif not user["must_change"]:
            code = request.form.get("code", "").strip()
            if action == "prepare" and not user["totp"]:
                session["enroll"] = pyotp.random_base32()
            elif action == "enable" and pending and not user["totp"] and code.isascii() and pyotp.TOTP(pending).verify(code):
                with db:
                    db.execute("UPDATE users SET totp=?,last_step=? WHERE id=?", (protected(pending), int(time.time() // 30), user["id"]))
                    db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
                    audit("totp.enabled", user["id"])
                begin(user["id"])
            elif action == "disable" and user["totp"] and code.isascii() and code.isdigit() and accept_totp(user, code):
                with db:
                    db.execute("UPDATE users SET totp=NULL,last_step=0 WHERE id=?", (user["id"],))
                    audit("totp.disabled", user["id"])
            else:
                flash("Код не принят.", "error")
        return redirect(url_for("auth.account"))
    return render_template("account.html", pending=pending)


@click.command("admin-password")
@click.option("--if-missing", is_flag=True, help="Создать только при первой установке.")
@with_appcontext
def admin_password(if_missing):
    db = get_db()
    pwd = secrets.token_urlsafe(20)
    with db:
        db.execute("BEGIN IMMEDIATE")
        if if_missing and db.execute("SELECT 1 FROM users WHERE identity='local:admin'").fetchone():
            return
        db.execute("""INSERT INTO users(identity,username,display_name,admin,password,must_change)
            VALUES ('local:admin','admin','Администратор',1,?,1)
            ON CONFLICT(identity) DO UPDATE SET password=excluded.password,must_change=1,totp=NULL,last_step=0""",
                   (generate_password_hash(pwd),))
        db.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE identity='local:admin')")
        db.execute("DELETE FROM attempts WHERE key=?", (digest("user:admin"),))
        audit("local_admin.reset")
    click.echo(pwd)
