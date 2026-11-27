"""Browser smoke on a temporary installation. Run: python -m tests.live_web"""
import os
import secrets
import tempfile
import threading
from unittest.mock import patch

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server
from app import create_app


def run(tmp):
    app = create_app(dict(DATA_DIR=tmp, SECRET_KEY=secrets.token_hex(32), SESSION_COOKIE_SECURE=False))
    pw = app.test_cli_runner().invoke(args=["admin-password"]).output.strip()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.getenv("CHROMIUM_PATH") or None)
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda err: errors.append(str(err)))
            page.goto(f"http://127.0.0.1:{server.server_port}")
            page.get_by_role("heading", name="Рабочее пространство").wait_for()
            public_nav = page.get_by_role("navigation", name="Разделы")
            assert public_nav.get_by_role("link", name="Система").count() == 0
            for label in ("Транскрибация", "Обезличивание", "Пароли", "Модели угроз"):
                public_nav.get_by_role("link", name=label).click()
                assert page.locator("main h1").is_visible()
            page.get_by_role("link", name="Вход администратора").click()
            page.get_by_label("Имя пользователя").fill("admin")
            page.get_by_label("Пароль", exact=True).fill(pw)
            page.get_by_role("button", name="Войти").click()
            new = secrets.token_urlsafe(32)
            page.get_by_label("Текущий пароль").fill(pw)
            page.get_by_label("Новый пароль", exact=True).fill(new)
            page.get_by_label("Повторите новый пароль").fill(new)
            page.get_by_role("button", name="Сохранить пароль").click()
            page.get_by_role("heading", name="Администрирование", exact=True).wait_for()
            page.get_by_role("button", name="Сменить тему").click()
            assert page.locator("html").get_attribute("data-theme") == "dark"
            for width, labels in (
                (1366, ("Транскрибация", "Обезличивание", "Пароли", "Модели угроз", "Система", "Обзор")),
                (390, ("Записи", "Обезличить", "Пароли", "Угрозы", "Система", "Обзор")),
            ):
                page.set_viewport_size(dict(width=width, height=820))
                for label in labels:
                    page.get_by_role("navigation", name="Разделы").get_by_role("link", name=label).click()
                    assert page.locator("main h1").is_visible()
                    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), label
            page.goto(f"http://127.0.0.1:{server.server_port}/admin/directory/")
            for field, value in {"name":"Тест", "host":"directory.test", "base_dn":"dc=example,dc=test",
                                 "bind_dn":"cn=reader,dc=example,dc=test", "password":"fixture-only"}.items():
                page.locator(f'[name="{field}"]').fill(value)
            page.get_by_role("button", name="Сохранить подключение").click()
            records = [
                dict(kind="group", id="cn=ops,dc=example,dc=test", dn="cn=ops,dc=example,dc=test", label="Операторы"),
                dict(kind="user", id="f9bc8bc8-9b91-4ae6-bb67-706363c48062", dn="cn=test,dc=example,dc=test",
                     label="Мария", login="maria"),
            ]
            with patch("app.directory.search_principals", return_value=records):
                search = page.get_by_role("searchbox")
                search.click()
                page.get_by_role("button", name="Группа · Операторы").click()
                search.fill("мар")
                page.get_by_role("button", name="Пользователь · Мария").click()
                page.get_by_role("button", name="Сохранить подключение").click()
            assert page.get_by_label("Мария (maria)").is_checked()
            assert page.locator('[name="admin_groups"]').input_value() == records[0]["dn"]
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        run(tmp)
    print("Desktop and mobile smoke passed.")
