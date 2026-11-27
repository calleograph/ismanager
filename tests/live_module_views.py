"""Check visible actions, background results and restored workspaces in a disposable browser."""
import os
import re
import secrets
import tempfile
import threading

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from app import create_app
from app.db import get_db


PUBLIC_ACTIONS = {
    "/": ".record-action", "/transcription/": "[data-asr-upload] button[type=submit]",
    "/redaction/": "#redaction-form button[type=submit]", "/passwords/": ".pass-copy",
    "/threats/": ".threat-actions button[value=next]", "/login": "main form button[type=submit]",
}
ADMIN_ACTIONS = {
    "/admin/": ".admin-nav a", "/admin/directories/": ".admin-head .btn",
    "/admin/directory/": ".admin-save button", "/admin/users/": "main form button[type=submit]",
    "/admin/journal/": "main form button", "/admin/storage/": "main .actions .btn",
    "/admin/storage/new?kind=smb": "button[value=save]", "/admin/watches/": "main .actions .btn",
    "/admin/watches/new": "button[value=save]",
}


def first_screen(page, origin, actions):
    for width, height in ((1366, 768), (1280, 800), (390, 844)):
        page.set_viewport_size(dict(width=width, height=height))
        for path, selector in actions.items():
            assert page.goto(origin + path).ok
            control = page.locator(selector).first
            expect(control).to_be_visible()
            page.evaluate("document.fonts.ready.then(() => true)")
            assert control.evaluate("""el => {
                const r=el.getBoundingClientRect();
                return r.top>=0 && r.bottom<=innerHeight+1 && r.left>=0 && r.right<=innerWidth+1;
            }"""), (width, height, path)


def resume_from_cache(page):
    # Explicit lifecycle events also cover browsers that evict no-store responses.
    page.evaluate("""() => {
        dispatchEvent(new PageTransitionEvent('pagehide', {persisted:true}));
        if (!document.querySelector('.shell').inert) throw Error('Restored material was visible');
        dispatchEvent(new PageTransitionEvent('pageshow', {persisted:true}));
    }""")


def check_redaction_upload(browser, origin):
    for javascript in (True, False):
        with browser.new_context(java_script_enabled=javascript) as context:
            page = context.new_page()
            page.goto(origin + "/redaction/")
            form = page.locator("#redaction-form")
            files = form.locator('input[type="file"][name="file"][multiple]')
            expect(page.locator('input[type="file"]')).to_have_count(1)
            submit = form.get_by_role("button", name="Обезличить и сохранить")
            submit.click()
            expect(form.locator("#redaction-error")).to_contain_text("Исходный текст")
            expect(page.locator('main a[href*="/redaction/batches/"]')).to_have_count(0)
            first = {"name": "first.txt", "mimeType": "text/plain", "buffer": b"first sample"}
            second = {"name": "second.txt", "mimeType": "text/plain", "buffer": b"second sample"}
            files.set_input_files(first)
            form.get_by_role("button", name="Предпросмотр без сохранения").click()
            expect(page.get_by_role("heading", name="Предпросмотр")).to_be_visible(timeout=15000)
            expect(page.locator("#redacted-text")).to_have_value("first sample")
            page.goto(origin + "/redaction/")
            files.set_input_files(first)
            submit.click()
            expect(page.locator("#redacted-text")).to_have_value("first sample", timeout=15000)
            page.goto(origin + "/redaction/")
            files.set_input_files([first, second])
            if javascript:
                expect(form.get_by_role("button", name="Предпросмотр без сохранения")).to_be_hidden()
                attempts = []

                def fail_second_upload(route):
                    attempts.append(route.request.post_data_buffer)
                    if len(attempts) == 2:
                        route.abort()
                    else:
                        route.continue_()

                page.route(re.compile(r"/redaction/batches/\d+/files\?ext=txt$"), fail_second_upload)
                submit.click()
                expect(form.locator("#redaction-error")).to_contain_text("Проверьте соединение")
                assert files.evaluate("field => field.files.length") == 2
            submit.click()
            expect(page.get_by_role("heading", name="Пакет №", level=1)).to_be_visible()
            results = page.locator("#batch-results")
            expect(results).to_contain_text("Всего 2")
            if javascript:
                expect(results.locator("[data-local-name]").first).to_contain_text("first.txt")
                assert attempts == [first["buffer"], second["buffer"], second["buffer"]]
            else:
                expect(results).not_to_contain_text("first.txt")
                page.get_by_text("Добавить файлы", exact=True).click()
                page.locator('#batch-upload input[type="file"]').set_input_files([
                    {"name": "third.txt", "mimeType": "text/plain", "buffer": b"third sample"},
                    {"name": "fourth.txt", "mimeType": "text/plain", "buffer": b"fourth sample"},
                ])
                page.get_by_role("button", name="Добавить в пакет").click()
                expect(results).to_contain_text("Всего 4")


def check_results(app, page, origin, batch, record):
    navigations = []
    page.goto(origin + "/transcription/example")
    page.on("framenavigated", lambda frame: navigations.append(frame.url))
    back = page.get_by_role("link", name="← Мои записи")
    back.focus()
    with app.app_context():
        db = get_db()
        db.execute("UPDATE transcripts SET status='done',body='Учебная стенограмма' WHERE id='example'")
        db.commit()
    field = page.get_by_label("Текст записи")
    expect(field).to_have_value("Учебная стенограмма", timeout=10000)
    expect(back).to_be_focused()
    field.fill("Учебная правка")
    expect(page.get_by_role("button", name="Сохранить правки")).to_be_enabled()
    with page.expect_event("dialog") as prompt:
        page.evaluate("setTimeout(() => location.reload(), 0)")
    assert prompt.value.type == "beforeunload"
    prompt.value.dismiss()
    expect(field).to_have_value("Учебная правка")
    assert not navigations
    page.get_by_role("button", name="Сохранить правки").click()

    page.goto(f"{origin}/redaction/batches/{batch}")
    navigations.clear()
    form = page.locator("#batch-upload")
    form.locator("input[type=file]").set_input_files(dict(name="sample.txt", mimeType="text/plain", buffer=b"Test"))
    form.get_by_role("button", name="Добавить в пакет").click()
    expect(page.locator("#batch-results")).to_contain_text("Всего 1")
    with app.app_context():
        db = get_db()
        db.execute("UPDATE redaction_batch_files SET state='done',result='sample' WHERE batch_id=?", (batch,))
        db.commit()
    field = form.locator("input[type=file]")
    field.focus()
    expect(page.get_by_role("link", name="Скачать готовые TXT в ZIP")).to_be_visible(timeout=12000)
    expect(field).to_be_focused()
    assert not navigations

    page.goto(origin + "/redaction/")
    source = page.get_by_label("Исходный текст")
    source.fill("Ввод учебного оператора")
    navigations.clear()
    resume_from_cache(page)
    expect(source).to_be_visible()
    expect(source).to_have_value("Ввод учебного оператора")
    expect(source).to_be_focused()
    assert not navigations
    page.once("dialog", lambda dialog: dialog.accept())
    page.goto(f"{origin}/redaction/{record}")
    with app.app_context():
        db = get_db()
        db.execute("DELETE FROM redactions WHERE id=?", (record,))
        db.commit()
    resume_from_cache(page)
    expect(page.get_by_text("Ошибка 404")).to_be_visible()
    # Complete same-session requests before replacing the visitor's cookie jar.
    page.goto(f"{origin}/redaction/batches/{batch}", wait_until="networkidle")
    page.context.clear_cookies()
    assert not page.context.cookies(origin)
    resume_from_cache(page)
    expect(page.get_by_text("Ошибка 404")).to_be_visible()


def run(directory):
    app = create_app(dict(DATA_DIR=directory, SECRET_KEY=secrets.token_hex(32), ACCESS_MODE="http"))
    password = app.test_cli_runner().invoke(args=["admin-password"]).output.strip()
    with app.app_context():
        db = get_db()
        owner = db.execute("SELECT id FROM users WHERE admin=1").fetchone()[0]
        db.execute("UPDATE users SET must_change=0 WHERE id=?", (owner,))
        db.executemany("INSERT INTO watch_resources(name,kind,path) VALUES(?,'local',?)",
                       ((f"Учебная папка {n}", str(n)) for n in range(80)))
        db.execute("INSERT INTO transcripts(id,owner,filename,status) VALUES('example',?,'Учебная запись','running')", (owner,))
        batch = db.execute("INSERT INTO redaction_batches(owner,nonce) VALUES(?,'example')", (owner,)).lastrowid
        record = db.execute("""INSERT INTO redactions(user_id,profile,result,stats,notes)
                               VALUES(?,'faceless','Учебная выдача','{}','[]')""", (owner,)).lastrowid
        db.commit()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.getenv("CHROMIUM_PATH") or None)
            check_redaction_upload(browser, origin)
            page = browser.new_page()
            first_screen(page, origin, PUBLIC_ACTIONS)
            page.get_by_label("Имя пользователя").fill("admin")
            page.get_by_label("Пароль", exact=True).fill(password)
            page.get_by_role("button", name="Войти").click()
            first_screen(page, origin, ADMIN_ACTIONS)
            check_results(app, page, origin, batch, record)
            browser.close()
    finally:
        server.shutdown()
        thread.join()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        run(directory)
    print("45 first-screen actions, single and batch upload with and without JavaScript, stationary results and access checks passed.")
