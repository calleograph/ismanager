"""IS Manager application factory. The speech worker has its own dependencies."""

HTTP_ERRORS = {
    400: ("Проверьте форму", "Откройте форму ещё раз, проверьте заполненные поля и повторите отправку."),
    401: ("Требуется вход", "Откройте страницу входа и войдите с учётной записью администратора."),
    403: ("Доступ ограничен", "Для этого действия нужны права администратора. Обратитесь к администратору IS Manager."),
    404: ("Страница не найдена", "Проверьте адрес. Сохранённые материалы можно открыть из истории в том браузере, где вы с ними работали."),
    405: ("Действие недоступно", "Откройте нужный раздел и повторите действие из его формы."),
    409: ("Состояние изменилось", "Откройте материал из истории, проверьте его текущее состояние и повторите действие."),
    413: ("Слишком большой объём данных", "Уменьшите объём данных и повторите отправку."),
    422: ("Не удалось обработать данные", "Проверьте поля формы и формат выбранного файла. Затем повторите отправку."),
    429: ("Слишком много попыток", "Подождите несколько минут и повторите действие."),
    500: ("Сбой на сервере", "Проверьте, появился ли результат в вашем разделе. Если сбой повторится, сообщите администратору время и действие."),
    503: ("Сервис временно недоступен", "Подождите несколько минут и повторите попытку."),
}


def create_app(config=None):
    import fcntl
    import hmac
    import os
    import secrets
    import time
    from datetime import timedelta
    from pathlib import Path

    from flask import Flask, abort, g, redirect, render_template, request, session, url_for
    from werkzeug.exceptions import HTTPException

    from . import admin, auth, db, network, passwords, redaction, redaction_batch, threats, transcription

    app = Flask(__name__)
    app.config.from_mapping(
        DATA_DIR=os.getenv("DATA_DIR", "/data"),
        SECRET_KEY=os.getenv("SECRET_KEY"),
        SESSION_COOKIE_NAME="ismanager_session",
        SESSION_COOKIE_SAMESITE="Lax",
        ACCESS_MODE=os.getenv("ACCESS_MODE", "https"),
        PUBLIC_HOST=os.getenv("PUBLIC_HOST", "localhost"),
        PUBLIC_URL=os.getenv("PUBLIC_URL", ""),
        TRUSTED_PROXY_IPS=os.getenv("TRUSTED_PROXY_IPS", ""),
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        MAX_CONTENT_LENGTH=16 * 1024**2,
        MAX_FORM_MEMORY_SIZE=5 * 1024**2,
        MAX_FORM_PARTS=300,
        VERSION=(Path(__file__).resolve().parents[1] / "VERSION").read_text().strip(),
    )
    if config:
        app.config.update(config)
    mode = app.config["ACCESS_MODE"]
    app.config.setdefault("PUBLIC_PORT", os.getenv("PUBLIC_PORT", "18443" if mode == "https" else "18084"))
    app.config["PUBLIC_URL"] = network.public_url(mode, app.config["PUBLIC_HOST"], app.config["PUBLIC_PORT"],
                                                 app.config["PUBLIC_URL"])
    if mode not in network.MODES:
        raise ValueError("ACCESS_MODE должен быть https, http или proxy.")
    secure = app.config["PUBLIC_URL"].startswith("https://")
    if not config or "SESSION_COOKIE_SECURE" not in config:
        app.config["SESSION_COOKIE_SECURE"] = secure
    if not secure:
        from flask.sessions import SecureCookieSessionInterface
        app.config["SESSION_COOKIE_NAME"] = "ismanager_http_session"
        app.session_interface = SecureCookieSessionInterface()
        app.session_interface.salt = "ismanager-http-session"
    if mode == "proxy":
        network.install_proxy(app)
    if not app.secret_key or len(app.secret_key) < 32:
        raise RuntimeError("Задайте SECRET_KEY длиной от 32 символов через install.sh.")
    directory = Path(app.config["DATA_DIR"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    app.config.setdefault("DATABASE", os.getenv("DATABASE") or str(directory / "ismanager.sqlite3"))
    modules = (auth, admin, transcription, redaction, passwords, threats)
    for module in modules:
        app.register_blueprint(module.bp)
    app.teardown_appcontext(db.close_db)
    # Gunicorn starts multiple app factories against the same fresh WAL database.
    with app.app_context(), (directory / ".schema.lock").open("a+b") as schema_lock:
        fcntl.flock(schema_lock, fcntl.LOCK_EX)
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
        if request.endpoint == "passwords.generate":
            request.max_content_length = 12000
        elif request.endpoint == "redaction.save_preview":
            request.max_form_memory_size = 9 * 1024**2
        g.user = None
        if request.endpoint in {"static", "health"}:
            return
        if request.endpoint != "admin.maintenance_status" and (Path(os.getenv("CONTROL_DIR", "/control")) / "maintenance").exists():
            abort(503, description="Идёт обслуживание IS Manager. Повторите запрос через несколько минут.")
        if "sid" in session:
            g.user = db.get_db().execute(
                "SELECT users.* FROM users JOIN sessions ON users.id=sessions.user_id "
                "WHERE token=? AND expires>?", (auth.digest(session["sid"]), int(time.time())),
            ).fetchone()
            if g.user is None:
                auth.clear_login()
        public = request.endpoint == "dashboard" or request.blueprint in {"transcription", "redaction", "passwords", "threats"}
        if request.endpoint and not public and request.endpoint != "auth.login" and g.user is None:
            auth.remember_admin_page()
            return redirect(url_for("auth.login"))
        if g.user is not None:
            if request.endpoint not in {"auth.login", "auth.account", "auth.logout"} and (
                g.user["must_change"] or (g.user["admin"] and not g.user["totp"] and db.auth_settings()["admin_totp"])
            ):
                auth.remember_admin_page()
                return redirect(url_for("auth.account"))
            if request.blueprint == "admin" and not g.user["admin"]:
                abort(403)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not session.get("csrf") or not hmac.compare_digest(
                session["csrf"].encode(), supplied.encode()
            ):
                abort(400, description="Форма устарела. Обновите страницу и повторите отправку. Если вы прикрепляли файл, выберите его снова.")
        if public and g.user is None:
            g.user = auth.browser_workspace(create=request.method == "POST" and request.blueprint != "passwords")

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
            SELECT 'transcript' AS kind, id, filename AS title, created AS stamp, NULL AS stage FROM transcripts WHERE owner=?
            UNION ALL SELECT 'redaction', id, 'Обезличивание №' || id, created, NULL FROM redactions WHERE user_id=?
            UNION ALL SELECT 'batch', id, 'Пакет № ' || id, created, NULL FROM redaction_batches WHERE owner=?
            UNION ALL SELECT 'threat', id, name, updated, stage FROM threat_models WHERE owner=?
            ORDER BY stamp DESC, kind, id DESC LIMIT 6
        """, (g.user["id"],) * 4).fetchall()
        return render_template("home.html", recent=recent)

    @app.errorhandler(HTTPException)
    def error(exc):
        title, hint = HTTP_ERRORS.get(exc.code, ("Не удалось выполнить запрос", "Откройте свой раздел и повторите действие."))
        if exc.description != type(exc).description:
            hint = exc.description
        elif exc.code == 413:
            hint = {
                "redaction.index": redaction_batch.FORM_LIMIT_HINT,
                "redaction.upload_file": (redaction_batch.FORM_LIMIT_HINT if request.mimetype == "multipart/form-data"
                                          else "Разделите документ на файлы до 64 МиБ каждый и добавьте их в пакет."),
                "redaction.create_batch": redaction_batch.FORM_LIMIT_HINT,
                "transcription.index": transcription.UPLOAD_ERRORS["large"],
                "passwords.generate": "Сократите введённые параметры генерации. Для своей фразы используйте от трёх до пяти слов.",
                "threats.new": "Уменьшите объём отправляемой анкеты. Для импорта выберите заполненный шаблон XLSX до 2 МБ.",
                "threats.edit": "Уменьшите объём отправляемой анкеты. Для импорта выберите заполненный шаблон XLSX до 2 МБ.",
            }.get(request.endpoint, hint)
        response = exc.get_response()
        if request.accept_mimetypes.best == "application/json":
            response.set_data(app.json.dumps({"error": hint}))
            response.mimetype = "application/json"
        else:
            response.set_data(render_template("error.html", error=exc, title=title, detail=hint))
        if exc.code == 503:
            response.headers["Retry-After"] = "8"
        return response

    app.cli.add_command(auth.admin_password)
    return app
