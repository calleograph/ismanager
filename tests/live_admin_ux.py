"""Administrative UI checks on a temporary installation: python -m tests.live_admin_ux."""
import json
import os
import secrets
import tempfile
from pathlib import Path
import threading
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from app import create_app
from app.db import get_db


def check_bookmark(page, origin, password):
    page.goto(origin + "/admin/watches/new?kind=redaction&q=private-label")
    expect(page.get_by_role("heading", name="Вход администратора")).to_be_visible()
    page.get_by_label("Имя пользователя").fill("admin")
    page.get_by_label("Пароль", exact=True).fill(password)
    page.get_by_role("button", name="Войти").click()
    new = secrets.token_urlsafe(32) + "Aa1"
    page.get_by_label("Текущий пароль").fill(password)
    page.get_by_label("Новый пароль", exact=True).fill(new)
    page.get_by_label("Повторите новый пароль").fill(new)
    page.get_by_role("button", name="Сохранить пароль").click()
    expect(page).to_have_url(origin + "/admin/watches/new?kind=redaction")


def check_folder_form(page):
    box = page.get_by_role("searchbox", name="Поиск входного ресурса")
    select = page.locator("select[name=input_resource]")
    expect(select.locator("option")).to_have_count(51)
    box.fill("089")
    expect(select.locator("option")).to_have_count(2)
    select.select_option(label="Учебная папка 089")
    chosen = select.input_value()
    page.route("**/admin/storage/options*", lambda route: route.abort())
    box.fill("090")
    expect(box.locator("..").locator("..").get_by_role("status")).to_contain_text("Текущий выбор сохранён")
    expect(select).to_have_value(chosen)
    name = page.get_by_label("Название правила")
    name.click()
    name.fill("Проверка сохранности ввода")
    with page.expect_event("dialog") as reload_prompt:
        page.evaluate("setTimeout(() => location.reload(), 0)")
    assert reload_prompt.value.type == "beforeunload"
    reload_prompt.value.dismiss()
    expect(name).to_have_value("Проверка сохранности ввода")
    page.get_by_role("button", name="Сохранить правило").click()
    expect(page.get_by_role("heading", name="Проверка сохранности ввода")).to_be_visible()
    page.reload()
    expect(select).to_have_value(chosen)


def check_maintenance(page, origin, operations):
    # Trigger the real confirmation dialog, Flask authorization and audit event.
    # A stand-in for the host operator accepts the request in this isolated test.
    page.goto(origin + "/admin/")
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.get_by_role("button", name="Откатить версию").click()
    assert "rollback" not in operations
    navigation = []
    page.on("framenavigated", lambda frame: navigation.append(frame.url) if frame == page.main_frame else None)
    page.once("dialog", lambda dialog: dialog.accept())
    with page.expect_response(lambda r: r.url.endswith("/admin/maintenance") and r.status == 202):
        page.get_by_role("button", name="Создать копию").click()
    assert operations.count("backup") == 1
    expect(page.locator("#maintenance [data-message]")).to_contain_text("Команда принята")
    path = Path(os.environ["CONTROL_DIR"]) / "operation.json"
    events = [{"message": "Создание резервной копии"}]
    report = dict(id="fixture", action="backup", state="running", events=events, message=events[0]["message"])
    path.write_text(json.dumps(report))
    expect(page.locator("#maintenance [data-message]")).to_have_text(events[0]["message"])
    expect(page.get_by_role("button", name="Создать копию")).to_be_disabled()
    page.get_by_text("Ход операции", exact=True).click()
    flag = {"offline": True}

    def network(route):
        if flag["offline"]:
            route.fulfill(status=503, body="Service unavailable")
        else:
            route.continue_()
    page.route("**/admin/maintenance/status", network)
    expect(page.locator("[data-connection]")).to_contain_text("Связь с сервисом временно прервана")
    flag["offline"] = False
    path.write_text(json.dumps(dict(report, state="done", message="Копия готова")))
    expect(page.locator("#maintenance [data-message]")).to_have_text("Копия готова", timeout=9000)
    expect(page.get_by_role("button", name="Создать копию")).to_be_enabled()
    assert operations.count("backup") == 1 and not navigation
    assert page.locator("[data-history]").evaluate("el => el.open")
    # The previous release has an admin panel and health endpoint but no progress endpoint.
    page.unroute("**/admin/maintenance/status", network)
    polls = []
    def old_server(route):
        polls.append(True)
        route.fulfill(status=404, body="Not found")
    page.route("**/admin/maintenance/status", old_server)
    page.route("**/healthz", lambda route: route.fulfill(json={"status":"ok","version":"0.5.0"}))
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Откатить версию").click()
    expect(page.get_by_role("link", name="Открыть панель установленной версии")).to_be_visible()
    expect(page.locator("[data-installed]")).to_have_text("0.5.0")
    assert len(polls) == 1 and not navigation


def run(directory):
    app = create_app(dict(DATA_DIR=directory, SECRET_KEY=secrets.token_hex(32), ACCESS_MODE="http"))
    password = app.test_cli_runner().invoke(args=["admin-password"]).output.strip()
    with app.app_context():
        db = get_db()
        db.executemany("INSERT INTO watch_resources(name,kind,path) VALUES(?,'local',?)",
                       ((f"Учебная папка {n:03}", f"folder/{n}") for n in range(120)))
        db.commit()
    operations = []

    def helper(operation):
        operations.append(operation)
        return b"ready" if operation == "ping" else b"ok"

    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch("app.admin.operator_request", side_effect=helper), sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.getenv("CHROMIUM_PATH") or None)
            page = browser.new_page(viewport=dict(width=1280, height=800))
            origin = f"http://127.0.0.1:{server.server_port}"
            check_bookmark(page, origin, password)
            check_folder_form(page)
            check_maintenance(page, origin, operations)
            plain = browser.new_context(java_script_enabled=False, storage_state=page.context.storage_state())
            native = plain.new_page()
            native.goto(origin + "/admin/")
            native.get_by_role("button", name="Создать копию").click()
            assert operations.count("backup") == 1
            native.get_by_role("button", name="Проверить", exact=True).click()
            expect(native).to_have_url(origin + "/admin/#maintenance")
            assert operations.count("check") == 1
            native.get_by_role("checkbox", name="Подтверждаю временную остановку").check()
            native.get_by_role("button", name="Создать копию").click()
            expect(native).to_have_url(origin + "/admin/#maintenance")
            assert operations.count("backup") == 2
            plain.close()
            browser.close()
    finally:
        server.shutdown()
        thread.join()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, CONTROL_DIR=directory):
        run(directory)
    print("Admin bookmark, unsaved choices, interrupted search and maintenance confirmations passed.")
