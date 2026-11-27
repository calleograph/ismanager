"""Run with two IS Manager images and a prepared, read-only GigaAM volume.

The test provisions its own web, worker, Samba domain controller, database and folders.
"""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import tempfile
from io import BytesIO
from zipfile import ZipFile

from playwright.sync_api import sync_playwright

from tests.live_network import SAMPLE, docker, login, published_port, wait_healthy


def eventually(check, seconds=180):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(1)
    raise AssertionError(f"Не выполнено условие {check} за {seconds} секунд")


def run(web_image, worker_image, model_volume):
    prefix = "ism-watch-test-" + secrets.token_hex(5)
    web, worker, dc = (prefix + "-" + part for part in ("web", "worker", "dc"))
    redactor = prefix + "-redactor"
    data, watch = prefix + "-data", prefix + "-watch"
    fixture_image = "ismanager-ad-fixture:test"
    docker("build", "-q", "-t", fixture_image, str(Path(__file__).parent / "active_directory"))
    docker("volume", "inspect", model_volume)
    env = dict(os.environ, SECRET_KEY=secrets.token_hex(32),
               USER_PASS=secrets.token_hex(15) + "Xz!", SERVICE_PASS=secrets.token_hex(15) + "Tt!")

    with ExitStack() as cleanup:
        def remove(*args):
            cleanup.callback(subprocess.run, ["docker", *args], check=False, capture_output=True)
        docker("network", "create", prefix)
        remove("network", "rm", prefix)
        for volume in (data, watch):
            docker("volume", "create", volume)
            remove("volume", "rm", volume)
        docker("run", "-d", "--name", dc, "--hostname", "dc", "--network", prefix, "--network-alias", "dc",
               "-e", "WATCH_SHARE=1", "-e", "USER_PASS", "-e", "SERVICE_PASS", fixture_image, env=env)
        remove("rm", "-f", dc)
        docker("run", "-d", "--name", web, "--network", prefix, "-p", "127.0.0.1::8443",
               "-e", "ACCESS_MODE=http", "-e", "SECRET_KEY", "-v", data + ":/data",
               "-v", watch + ":/watch:ro", web_image, env=env)
        remove("rm", "-f", web)
        wait_healthy(web)
        initial = docker("exec", web, "flask", "--app", "app", "admin-password", "--if-missing")
        docker("run", "-d", "--name", worker, "--network", prefix, "-e", "SECRET_KEY", "-e", "WATCH_POLL_SECONDS=2",
               "-v", data + ":/data", "-v", watch + ":/watch", "-v", model_volume + ":/models:ro",
               worker_image, env=env)
        remove("rm", "-f", worker)
        wait_healthy(worker)
        docker("run", "-d", "--name", redactor, "--network", prefix, "--cap-drop", "ALL", "-e", "SECRET_KEY",
               "-e", "WATCH_POLL_SECONDS=2", "-v", data + ":/data", "-v", watch + ":/watch",
               "--health-cmd", "python -m app.redaction_worker health", "--health-interval", "3s",
               web_image, "python", "-m", "app.redaction_worker", env=env)
        remove("rm", "-f", redactor)
        wait_healthy(redactor)
        docker("exec", worker, "mkdir", "-p", "/watch/incoming")
        docker("cp", str(SAMPLE), worker + ":/tmp/sample.ogg")
        origin = f"http://127.0.0.1:{published_port(web)}"
        driver = cleanup.enter_context(sync_playwright())
        browser = driver.chromium.launch(executable_path=os.getenv("CHROMIUM_PATH") or None)
        cleanup.callback(browser.close)
        page = browser.new_page()
        login(page, origin, initial, secrets.token_urlsafe(30))

        def post(route, **fields):
            assert page.goto(origin + route).ok
            token = page.locator('meta[name="csrf-token"]').get_attribute("content")
            response = page.request.post(origin + route, form={"csrf_token": token, "action": "save", **fields},
                                         max_redirects=0)
            assert response.status in (302, 303), (route, response.status)
            return response.headers["location"]

        def identifier(url):
            return str(int(url.rstrip("/").rsplit("/", 1)[-1]))

        local = identifier(post("/admin/storage/new", kind="local", name="Локальные записи", path="incoming"))
        remote = {"kind": "smb", "server": "dc", "port": "445", "domain": "EXAMPLE",
                  "username": "analyst", "password": env["USER_PASS"], "path": ""}
        incoming = identifier(post("/admin/storage/new", name="Вход SMB", share="watch-input", **remote))
        outgoing = identifier(post("/admin/storage/new", name="Результат SMB", share="watch-output", **remote))
        local_rule = post("/admin/watches/new", name="На сервере", input_resource=local, input_folder="",
                          output_resource="", output_folder="", enabled="on")
        smb_rule = post("/admin/watches/new", name="Доменный ресурс", input_resource=incoming, input_folder="",
                        output_resource=outgoing, output_folder="exports", enabled="on", delete_source="on")
        assert page.goto(origin + local_rule).ok and page.goto(origin + smb_rule).ok
        print("Правила локального и двух доменных ресурсов сохранены через HTTP", flush=True)

        def exists(container, path):
            result = subprocess.run(["docker", "exec", container, "test", "-s", path], capture_output=True)
            return result.returncode == 0

        local_result = "/watch/incoming/Тексты IS Manager/Встреча.txt"
        smb_result = "/srv/watch-output/exports/Разговор.txt"
        docker("exec", worker, "cp", "/tmp/sample.ogg", "/watch/incoming/Встреча.ogg")
        docker("cp", str(SAMPLE), dc + ":/srv/watch-input/Разговор.ogg")
        eventually(lambda: exists(worker, local_result) and exists(dc, smb_result))
        for service, path in ((worker, local_result), (dc, smb_result)):
            content = docker("exec", service, "cat", path)
            assert "текст" in content.lower() and "день" in content.lower(), content
            stamps = re.findall(r"\d{2}:\d{2}:\d{2}(?:[.,]\d+)?", content)
            assert len(stamps) >= 2 and stamps[0] != stamps[1], content
        eventually(lambda: not exists(dc, "/srv/watch-input/Разговор.ogg"))
        assert exists(worker, "/watch/incoming/Встреча.ogg")
        original = docker("exec", worker, "cat", local_result)
        docker("exec", worker, "rm", "--", local_result)
        eventually(lambda: exists(worker, local_result))
        assert docker("exec", worker, "cat", local_result) == original
        print("GigaAM записал оба TXT с тайм-кодами. Удалён только выбранный исходник. Утерянный TXT восстановлен.")

        rule = post("/admin/watches/new", kind="redaction", name="Заявки", input_resource=incoming,
                    input_folder="", output_resource=outgoing, output_folder="safe", enabled="on")
        assert page.goto(origin + rule).ok
        ticket = b"ticket;password;contact\nclosed;synthetic test phrase;demo@sample.invalid\n"
        with tempfile.TemporaryDirectory() as tmp:
            document = Path(tmp) / "private-name.csv"
            document.write_bytes(ticket)
            docker("cp", str(document), dc + ":/srv/watch-input/" + document.name)

        def results():
            return docker("exec", dc, "sh", "-c",
                          "if test -d /srv/watch-output/safe; then ls -1 /srv/watch-output/safe; fi").splitlines()

        eventually(lambda: len(results()) == 1)
        [filename] = results()
        assert re.fullmatch(r"ismanager-redacted-[0-9a-f]{32}\.txt", filename)
        content = docker("exec", dc, "cat", "/srv/watch-output/safe/" + filename)
        assert "closed" in content and "synthetic test phrase" not in content and "demo@" not in content
        assert exists(dc, "/srv/watch-input/private-name.csv")
        print("Доменная папка дала обезличенный TXT с нейтральным именем. Оригинал сохранён.", flush=True)
        check_batch(page, origin, ticket)


def check_batch(page, origin, ticket):
    page.goto(origin + "/redaction/")
    files = page.locator('input[type="file"][multiple]')
    files.set_input_files([
        {"name": "private-person.csv", "mimeType": "text/csv", "buffer": ticket},
        {"name": "second.log", "mimeType": "text/plain", "buffer": "Заявка закрыта. Пароль: blue otter".encode()},
        {"name": "broken.pdf", "mimeType": "application/pdf", "buffer": b"broken document"},
    ])
    files.locator("xpath=ancestor::form").locator('button[type="submit"]').first.click()
    page.wait_for_url(re.compile(r"/redaction/batches/[^/]+/?$"), timeout=60000)
    details = page.url.rstrip("/")
    def archive_ready():
        reply = page.request.get(details + "/archive.zip")
        if reply.status != 200 or not reply.body().startswith(b"PK"):
            return False
        with ZipFile(BytesIO(reply.body())) as archive:
            names = archive.namelist()
            if len(names) != 2:
                return False
            assert all(re.fullmatch(r"[\w.-]+\.txt", name) and "private" not in name for name in names)
            text = "\n".join(archive.read(name).decode("utf-8") for name in names)
            assert "closed" in text and "Заявка" in text and "blue otter" not in text
            assert not any(marker in text for marker in ("demo@", "synthetic test phrase", "broken document"))
        return True
    eventually(archive_ready)
    print("Пакет из трёх файлов принят в Chromium. Два проверенных TXT скачаны в ZIP, повреждённый PDF изолирован.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("web_image")
    parser.add_argument("worker_image")
    parser.add_argument("model_volume")
    args = parser.parse_args()
    run(args.web_image, args.worker_image, args.model_volume)
