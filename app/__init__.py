"""IS Manager application factory. The speech worker has its own dependencies."""


def create_app(config=None):
    import hmac
    import os
    import secrets
    import time
    from datetime import timedelta
    from pathlib import Path

    from flask import Flask, abort, g, redirect, render_template, request, session, url_for
    from werkzeug.exceptions import HTTPException

    from . import admin, auth, db, passwords, redaction, threats, transcription

    app = Flask(__name__)
    app.config.from_mapping(
        DATA_DIR=os.getenv("DATA_DIR", "/data"),
        SECRET_KEY=os.getenv("SECRET_KEY"),
        SESSION_COOKIE_NAME="ismanager_session",
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "1") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=16 * 1024**2,
        MAX_FORM_MEMORY_SIZE=5 * 1024**2,
        MAX_FORM_PARTS=300,
        VERSION=(Path(__file__).resolve().parents[1] / "VERSION").read_text().strip(),
    )
    if config:
        app.config.update(config)
    if not app.secret_key or len(app.secret_key) < 32:
        raise RuntimeError("Задайте SECRET_KEY длиной от 32 символов через install.sh.")
    directory = Path(app.config["DATA_DIR"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    app.config.setdefault("DATABASE", os.getenv("DATABASE") or str(directory / "ismanager.sqlite3"))
    modules = (auth, admin, transcription, redaction, passwords, threats)
    for module in modules:
        app.register_blueprint(module.bp)
    app.teardown_appcontext(db.close_db)
    with app.app_context():
        connection = db.get_db()
        db.init_db(connection)
        for module in modules:
            if hasattr(module, "init_db"):
                module.init_db(connection)
        connection.commit()

    def csrf_token():
        return session.setdefault("csrf", secrets.token_urlsafe(32))

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def authorize():
        limits = {"redaction.index": 12 * 1024**2 + 300000, "passwords.generate": 12000}
        if request.endpoint in limits:
            request.max_content_length = limits[request.endpoint]
        g.user = None
        if request.endpoint in {"static", "health"}:
            return
        if "sid" in session:
            g.user = db.get_db().execute(
                "SELECT users.* FROM users JOIN sessions ON users.id=sessions.user_id "
                "WHERE token=? AND expires>?", (auth.digest(session["sid"]), int(time.time())),
            ).fetchone()
        if request.endpoint != "auth.login":
            if g.user is None:
                return redirect(url_for("auth.login"))
            if g.user["must_change"] and request.endpoint not in {"auth.account", "auth.logout"}:
                return redirect(url_for("auth.account"))
            if request.blueprint == "admin" and not g.user["admin"]:
                abort(403)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not session.get("csrf") or not hmac.compare_digest(
                session["csrf"].encode(), supplied.encode()
            ):
                abort(400, description="Форма устарела. Откройте страницу повторно.")

    @app.after_request
    def headers(response):
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; script-src 'self'"
        )
        return response

    @app.get("/healthz")
    def health():
        db.get_db().execute("SELECT count(*) FROM users").fetchone()
        return {"status": "ok", "version": app.config["VERSION"]}

    @app.get("/")
    def dashboard():
        recent = db.get_db().execute("""
            SELECT 'transcript' AS kind, id, filename AS title, created AS stamp FROM transcripts WHERE owner=?
            UNION ALL SELECT 'redaction', id, 'Обезличивание №' || id, created FROM redactions WHERE user_id=?
            UNION ALL SELECT 'threat', id, name, updated FROM threat_models WHERE owner=?
            ORDER BY stamp DESC LIMIT 6
        """, (g.user["id"],) * 3).fetchall()
        return render_template("home.html", recent=recent)

    @app.errorhandler(HTTPException)
    def error(exc):
        return render_template("error.html", error=exc), exc.code

    app.cli.add_command(auth.admin_password)
    return app
