"""Chromium checks of the two public generators. Run python -m tests.live_generators."""
import os
from pathlib import Path
import secrets
import tempfile
import threading
from zipfile import ZipFile

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from app import create_app
from app.threat_model.workbook import workbook


def check_passwords(page, origin):
    page.goto(origin + "/passwords/")
    results = page.locator("#pass-results li")
    expect(page.get_by_role("tab", selected=True)).to_have_text("По словарю")
    expect(results).to_have_count(7)
    expect(page.locator(".pass-advice a")).to_contain_text("§ 4.2")
    rotation = page.get_by_role("button", name="Автоматическая смена советов")
    rotation.click()
    expect(rotation).to_have_attribute("aria-pressed", "false")
    initial_tip = page.locator(".pass-advice p").inner_text()
    page.get_by_role("button", name="Другой совет").click()
    expect(page.locator(".pass-advice p")).not_to_have_text(initial_tip)
    first = results.locator("code").all_text_contents()
    page.get_by_role("button", name="Как собран вариант 1", exact=True).click()
    expect(results.first.locator(".pass-breakdown")).to_contain_text("Случайная вставка")
    page.get_by_role("button", name="Ещё", exact=True).click()
    assert results.locator("code").all_text_contents() != first
    page.get_by_role("button", name="Копировать все", exact=True).click()
    assert page.evaluate("navigator.clipboard.readText()").splitlines() == results.locator("code").all_text_contents()

    page.get_by_role("tab", name="Своя фраза").click()
    submit = page.locator("#pass-generate")
    expect(submit).to_be_disabled()
    page.get_by_label("Ваша фраза").fill("маяк,облако—берег")
    expect(page.locator("#pass-preview")).to_have_text("Mayak · Oblako · Bereg")
    page.get_by_text("В конце", exact=True).click()
    submit.click()
    expect(results).to_have_count(7)
    assert all(p.startswith("MayakOblakoBereg") for p in results.locator("code").all_text_contents())
    page.get_by_role("tab", name="История").click()
    expect(results.first.locator("small")).to_contain_text(" · ")
    assert all(len(h.split(" · ")[1].split(" + ")) == 4 for h in results.locator("small").all_text_contents())
    page.get_by_role("tab", name="Случайный").click()
    expect(results).to_have_count(7)
    assert all(len(p) == 16 for p in results.locator("code").all_text_contents())
    page.get_by_role("tab", name="Случайный").press("ArrowLeft")
    expect(page.get_by_role("tab", selected=True)).to_have_text("История")

    fallback = page.context.new_page()
    fallback.add_init_script("Object.defineProperty(window, 'crypto', {value: undefined})")
    fallback.add_init_script("Object.defineProperty(navigator, 'clipboard', {value: undefined})")
    fallback.goto(origin + "/passwords/")
    expect(fallback.locator('[name="processor"]')).to_have_value("server")
    fallback.get_by_role("tab", name="Своя фраза").click()
    fallback.get_by_label("Ваша фраза").fill("маяк,облако—берег")
    with fallback.expect_response(lambda r: r.url.endswith("/passwords/generate")) as generation:
        fallback.locator("#pass-generate").click()
    assert generation.value.ok
    fallback.get_by_role("button", name="Как собран вариант 1", exact=True).click()
    expect(fallback.locator(".pass-breakdown").first).to_contain_text("Mayak")
    fallback.get_by_role("button", name="Скопировать вариант 1", exact=True).click()
    assert fallback.evaluate("getSelection().toString()") == fallback.locator("#pass-results code").first.inner_text()
    fallback.get_by_role("button", name="Копировать все", exact=True).click()
    assert fallback.locator("#pass-manual").input_value().splitlines() == fallback.locator("#pass-results code").all_text_contents()
    fallback.close()


def check_wizard(page, origin):
    page.goto(origin + "/threats/")
    expect(page.get_by_role("heading", name="Профиль системы")).to_be_visible()
    expect(page.locator(".threat-nav li")).to_have_count(11)
    with page.expect_download() as blank:
        page.get_by_role("link", name="Скачать пример шаблона").click()
    assert blank.value.suggested_filename.endswith(".xlsx")
    page.locator("[name=systemType]").select_option("crm")
    page.get_by_label("Загрузить заполненный файл").set_input_files(
        dict(name="other.xls", mimeType="application/vnd.ms-excel", buffer=b"fixture"))
    expect(page.locator("#sheet-error")).to_contain_text("Скачайте пример шаблона")
    expect(page.locator("#threat-sheet")).to_be_focused()
    expect(page.locator("[name=systemType]")).to_have_value("crm")
    page.locator("[name=systemType]").select_option("")
    page.get_by_role("button", name="Далее").click()
    expect(page.get_by_role("alert")).to_contain_text("Заполните")
    expect(page.locator("[name=systemType]")).to_be_focused()
    expect(page.locator("[name=systemType]")).to_have_attribute("aria-invalid", "true")
    page.locator("[name=systemType]").select_option("erp_1c")
    expect(page.locator('[data-option="erp_1c"]')).to_be_visible()
    page.locator("[name=systemNetworkCondition]").select_option("corporate_internet")
    page.get_by_role("button", name="Далее").click()
    expect(page.get_by_role("heading", name="Оператор и ИС")).to_be_visible()
    page.locator("[name=infosystemShortName]").fill("Черновик проверки")
    page.get_by_role("button", name="01 Профиль системы").click()
    expect(page.get_by_role("heading", name="Профиль системы")).to_be_visible()
    page.get_by_role("button", name="02 Оператор и ИС").click()
    expect(page.locator("[name=infosystemShortName]")).to_have_value("Черновик проверки")
    page.get_by_role("button", name="Назад", exact=True).click()
    draft = page.url
    values = dict(systemType="crm", systemNetworkCondition="isolated_no_internet", objectType="ispdn", infosystemShortName="Импорт из Excel")
    values.update(operatorFullName="Учебный оператор", operatorShortName="Оператор", operatorLegalAddress="Учебный адрес",
                  infosystemFullName="Тестовая система", dataCategory_other=True, subjectType="employee")
    for i in range(1, 4):
        values[f"commissionRole_{i}"] = "chairman" if i == 1 else "member"
        values[f"commissionPosition_{i}"] = f"Должность {i}"
        values[f"commissionName_{i}"] = f"Участник {i}"
    with page.expect_response(lambda r: r.request.method == "POST" and r.url == draft) as uploaded:
        page.get_by_label("Загрузить заполненный файл").set_input_files(
            dict(name="anketa.xlsx", mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                 buffer=workbook(values).getvalue()))
    assert uploaded.value.status == 302
    expect(page.locator("[name=systemType]")).to_have_value("crm")
    assert page.url == draft
    page.get_by_role("button", name="Все мои анкеты").click()
    expect(page.get_by_role("link", name="Импорт из Excel")).to_be_visible()
    expect(page.locator(".threat-recent a")).to_have_count(1)
    page.locator(".threat-recent a").click()
    # This saved draft already reached step 2 before importing the workbook.
    for step in range(2, 11):
        if step == 7:
            page.locator("#threat-search").fill("несуществующая-строка")
            expect(page.locator("#threat-matches")).to_contain_text("Совпадений нет")
            page.locator("#threat-search").fill("УБИ.001")
            expect(page.locator(".threat-choice:visible")).to_have_count(1)
        page.get_by_role("button", name="Далее").click()
    with page.expect_download() as package:
        page.get_by_role("button", name="Сформировать и скачать ZIP").click()
    with ZipFile(package.value.path()) as archive:
        assert archive.namelist() and all(name.endswith(".docx") for name in archive.namelist())
    page.goto(origin + "/threats/")
    with page.expect_download() as saved:
        page.get_by_role("link", name="Скачать документы ZIP · Импорт из Excel").click()
    assert saved.value.suggested_filename.endswith(".zip")


def run(tmp):
    app = create_app(dict(DATA_DIR=tmp, SECRET_KEY=secrets.token_hex(32), ACCESS_MODE="http"))
    server = make_server("127.0.0.1", 0, app, threaded=True)
    origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.getenv("CHROMIUM_PATH") or None)
            context = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda err: errors.append(str(err)))
            check_passwords(page, origin)
            check_wizard(page, origin)
            for width in (1366, 390, 320):
                page.set_viewport_size(dict(width=width, height=820))
                for module in ("passwords", "threats"):
                    page.goto(f"{origin}/{module}/")
                    if module == "passwords":
                        expect(page.locator("#pass-results li")).to_have_count(7)
                        settings = page.locator("#pass-settings")
                        assert settings.evaluate("el => el.open") == (width > 820)
                        if width <= 820:
                            settings.locator("summary").click()
                            expect(page.locator("#word-length")).to_be_visible()
                            settings.locator("summary").click()
                    else:
                        assert page.locator(".threat-nav").evaluate("el => el.open") == (width > 760)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (width, module)
                    if os.getenv("GENERATOR_SCREENSHOTS"):
                        masked = [page.locator("#pass-results code, #pass-results small, .pass-breakdown:visible, #pass-manual:visible")] if module == "passwords" else []
                        page.screenshot(path=Path(os.environ["GENERATOR_SCREENSHOTS"]) / f"{module}-{width}.png", mask=masked)
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        run(tmp)
    print("Password modes, copy, fallback, Excel, step navigation and responsive layout passed.")
