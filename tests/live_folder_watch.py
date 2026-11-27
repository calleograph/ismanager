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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("web_image")
    parser.add_argument("worker_image")
    parser.add_argument("model_volume")
    args = parser.parse_args()
    run(args.web_image, args.worker_image, args.model_volume)
