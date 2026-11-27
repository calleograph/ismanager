"""Exercise a host Nginx on :8106 and Docker's loopback upstream on :18086 in Chromium."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

from playwright.sync_api import expect, sync_playwright

from tests.live_network import HOST, SAMPLE, docker, login, wait_healthy


def run(web_image, worker_image, models, nginx_image):
    prefix = "ism-http-front-" + secrets.token_hex(6)
    data, web, worker, nginx = (prefix + part for part in ("-data", "-web", "-worker", "-nginx"))
    env = dict(os.environ, SECRET_KEY=secrets.token_hex(32))
    origin = f"http://{HOST}:8106"
    with ExitStack() as cleanup:
        def remove(*args):
            cleanup.callback(subprocess.run, ["docker", *args], capture_output=True)
        docker("volume", "create", data)
        remove("volume", "rm", data)
        tmp = Path(cleanup.enter_context(tempfile.TemporaryDirectory()))
        tmp.chmod(0o755)
        (tmp / "operator-disabled").write_text("disabled")
        example = (Path(__file__).resolve().parents[1] / "docs/nginx-http.conf.example").read_text()
        front = example.replace("listen 8106;", "listen 127.0.0.1:8106;").replace("ismanager.example.org", HOST)
        (tmp / "test.conf").write_text("events {}\nhttp { access_log off;\n" + front + "\n}")
        docker("run", "-d", "--name", web, "-p", "127.0.0.1:18086:8443", "-v", data + ":/data",
               "-v", str(tmp) + ":/control:ro", "-e", "SECRET_KEY", "-e", "ACCESS_MODE=proxy",
               "-e", "PUBLIC_URL=" + origin, "-e", "TRUSTED_PROXY_IPS=gateway", web_image, env=env)
        remove("rm", "-f", web)
        wait_healthy(web)
        docker("run", "-d", "--name", nginx, "--network", "host", "-v", str(tmp) + ":/test:ro",
               nginx_image, "nginx", "-c", "/test/test.conf", "-g", "daemon off;")
        remove("rm", "-f", nginx)
        driver = cleanup.enter_context(sync_playwright())
        browser = driver.chromium.launch(executable_path=os.getenv("CHROMIUM_PATH") or None, args=[
            "--no-proxy-server", f"--host-resolver-rules=MAP {HOST} 127.0.0.1"])
        cleanup.callback(browser.close)
        context = browser.new_context()
        page = context.new_page()
        first = docker("exec", web, "flask", "--app", "app", "admin-password", "--if-missing")
        login(page, origin, first, secrets.token_urlsafe(24) + "X9")
        assert page.goto(origin + "/admin/").ok
        expect(page.get_by_text(origin + "/", exact=True)).to_be_visible()
        expect(page.locator("#technical summary")).to_have_text("Технические характеристики")
        expect(page.get_by_text("Веб-управление отключено при установке.")).to_be_visible()
        assert not page.locator('button[value="update"]').count()
        assert any(cookie["name"] == "ismanager_http_session" and not cookie["secure"] for cookie in context.cookies())
        page.goto(origin + "/transcription/")
        page.locator('[name=media]').set_input_files(SAMPLE)
        cdp = context.new_cdp_session(page)
        cdp.send("Network.enable")
        cdp.send("Network.emulateNetworkConditions", dict(offline=False, latency=40, downloadThroughput=1048576, uploadThroughput=12000))
        page.get_by_role("button", name="Расшифровать запись").click()
        expect(page.locator("[data-upload-console]")).to_be_visible()
        expect(page.locator("[data-asr-console]")).to_contain_text("Запись принята в очередь", timeout=60000)
        cdp.detach()
        docker("run", "-d", "--name", worker, "--network", "none", "-v", data + ":/data", "-v", models + ":/models:ro",
               "-e", "SECRET_KEY", worker_image, env=env)
        remove("rm", "-f", worker)
        expect(page.locator("[data-asr-resources]")).to_contain_text("CPU GigaAM", timeout=90000)
        expect(page.locator("#asr-text")).to_be_visible(timeout=120000)
        assert "день" in page.locator("#asr-text").input_value().lower()
        expect(page.locator("[data-asr-log]")).to_contain_text("Распознавание русской речи")
        expect(page.locator("[data-asr-log]")).to_contain_text("Готово")
        expect(page.get_by_role("button", name="Сохранить правки")).to_be_disabled()
        page.locator("#asr-text").fill("Учебная расшифровка. Текст проверен.")
        expect(page.locator("[data-pending-edits]")).to_contain_text("Сохраните правки")
        page.get_by_role("button", name="Сохранить правки").click()
        page.get_by_role("link", name="Мои записи").click()
        with page.expect_download() as saved:
            page.get_by_role("link", name="Скачать TXT").click()
        assert Path(saved.value.path()).read_text().strip() == "Учебная расшифровка. Текст проверен."
        page.goto(origin + "/admin/")
        with page.expect_response(lambda r: r.url.endswith("/admin/system-metrics")) as updated:
            page.locator("#technical summary").click()
            expect(page.locator("[data-worker-ram]")).to_contain_text("МиБ")
        metrics = updated.value.json()
        assert 0 <= metrics["cpu"]["percent"] <= 100 and metrics["cores"] > 0
        assert 0 <= metrics["available"] <= metrics["total"]
        assert metrics["worker"]["memory_mib"] > 0 and metrics["worker"]["busy_cores"] >= 0
        expect(page.locator("[data-machine-cpu]")).to_contain_text("%")
        expect(page.locator("[data-machine-ram]")).to_contain_text("Занято")
        print("Nginx :8106 → 127.0.0.1:18086, HTTP cookie, CLI operator mode, GigaAM upload/queue/result and live server/worker counters passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("web_image")
    parser.add_argument("worker_image")
    parser.add_argument("model_volume")
    parser.add_argument("--nginx-image", default="nginx:alpine")
    args = parser.parse_args()
    run(args.web_image, args.worker_image, args.model_volume, args.nginx_image)
