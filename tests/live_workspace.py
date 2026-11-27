"""Compare return journeys on disposable instances, using two independent visitors."""
import argparse
import re
import time
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


def run(origin, baseline):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        owner, guest = browser.new_page(), browser.new_page()
        errors = []
        owner.on("pageerror", lambda exc: errors.append(str(exc)))
        owner.goto(origin)
        owner.keyboard.press("Tab")
        expect(owner.get_by_role("link", name="К содержанию")).to_be_focused()
        owner.keyboard.press("Enter")
        expect(owner.locator("main")).to_be_focused()
        owner.get_by_role("navigation", name="Разделы").get_by_role("link", name="Обезличивание").click()
        if not baseline:
            native = browser.new_page(java_script_enabled=False)
            native.goto(origin + "/redaction/")
            native.get_by_role("button", name="Обезличить и сохранить").click()
            expect(native.locator("#redaction-error")).to_contain_text("Исходный текст")
            field = native.locator('#redaction-form input[type="file"]')
            expect(native.locator("main [aria-invalid=true]")).to_be_focused()
            field.set_input_files([
                {"name": "native.txt", "mimeType": "text/plain", "buffer": b"first sample"},
                {"name": "second.txt", "mimeType": "text/plain", "buffer": b"second sample"},
            ])
            native.get_by_role("button", name="Обезличить и сохранить").click()
            expect(native.locator("#batch-results")).to_contain_text("Всего 2")
            native.get_by_text("Добавить файлы", exact=True).click()
            field = native.locator("#batch-upload input[type=file]")
            native.get_by_role("button", name="Добавить в пакет").click()
            expect(native.locator("#batch-upload-error")).to_contain_text("нажмите «Добавить в пакет»")
            expect(field).to_be_focused()
            native.close()
            source = owner.locator('#redaction-form textarea[name="text"]')
            source.fill("Синтетический текст")
            upload = owner.locator('#redaction-form input[type="file"]')
            upload.set_input_files({"name": "sample.txt", "mimeType": "text/plain", "buffer": b"sample"})
            owner.get_by_role("button", name="Предпросмотр без сохранения").click()
            expect(owner.locator("#redaction-error")).to_contain_text("очистите поле «Исходный текст»")
            with owner.expect_event("dialog") as warning:
                owner.evaluate("setTimeout(() => location.reload(), 0)")
            assert warning.value.type == "beforeunload"
            warning.value.dismiss()
            expect(source).to_have_value("Синтетический текст")
            # Discard the synthetic draft before creating an unrelated batch.
            owner.once("dialog", lambda dialog: dialog.accept())
            owner.reload()
        if baseline:
            owner.locator("#batch-upload button").click()
        else:
            batch_field = owner.locator('#redaction-form input[type="file"]')
            batch_field.set_input_files([
                {"name": "sample.txt", "mimeType": "text/plain", "buffer": b"first sample"},
                {"name": "second.txt", "mimeType": "text/plain", "buffer": b"second sample"},
            ])
            owner.get_by_role("button", name="Обезличить и сохранить").click()
        expect(owner.get_by_role("heading", name="Пакет №", level=1)).to_be_visible()
        batch = urlsplit(owner.url).path
        owner.get_by_role("link", name="IS Manager", exact=True).click()
        start = time.perf_counter()
        if baseline:
            owner.get_by_role("navigation", name="Разделы").get_by_role("link", name="Обезличивание").click()
        owner.locator(f'main a[href="{batch}"]').click()
        expect(owner.get_by_role("heading", name="Пакет №", level=1)).to_be_visible()
        print(f"Reopen batch: {2 if baseline else 1} clicks, {time.perf_counter()-start:.3f}s")

        owner.get_by_role("navigation", name="Разделы").get_by_role("link", name="Модели угроз").click()
        owner.locator('[name="systemType"]').select_option("crm")
        owner.locator('[name="systemNetworkCondition"]').select_option("corporate_internet")
        owner.get_by_role("button", name="Далее").click()
        expect(owner.get_by_role("heading", name="Оператор и ИС")).to_be_visible()
        draft = urlsplit(owner.url).path
        if not baseline:
            name = owner.locator('[name="infosystemShortName"]')
            name.fill("Учебная система")
            dialogs = []
            def cancel_leave(dialog):
                dialogs.append(dialog.type)
                dialog.dismiss()
            owner.once("dialog", cancel_leave)
            owner.get_by_role("link", name="IS Manager", exact=True).click(no_wait_after=True)
            expect(name).to_have_value("Учебная система")
            assert dialogs == ["beforeunload"]
            owner.get_by_role("button", name=re.compile("Сохранить")).first.click()
            expect(name).to_have_value("Учебная система")
        owner.get_by_role("link", name="IS Manager", exact=True).click()
        start = time.perf_counter()
        owner.locator('main a[href*="/threats/"]').filter(has=owner.locator("time")).click()
        if baseline:
            owner.get_by_role("button", name="Далее").click()
        expect(owner.get_by_role("heading", name="Оператор и ИС")).to_be_visible()
        print(f"Resume draft: {2 if baseline else 1} clicks, {time.perf_counter()-start:.3f}s")
        guest.goto(origin)
        assert not guest.locator(f'main a[href="{batch}"],main a[href="{draft}"]').count()
        for route in (batch, draft):
            assert guest.goto(origin + route).status == 404
        assert not errors, errors
        browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin", help="Disposable local installation URL")
    parser.add_argument("--baseline", action="store_true", help="Exercise the paths used in v0.5.0")
    args = parser.parse_args()
    run(args.origin.rstrip("/"), args.baseline)
