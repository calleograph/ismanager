"""Exercise the three production transports in Chromium and disposable containers.

Run with the web and worker images built from this checkout:
    python -m tests.live_network WEB_IMAGE WORKER_IMAGE

Requires Docker, openssl, Python Playwright with Chromium, and network access for
the initial GigaAM model download. All published ports are loopback-only.
"""
import argparse
from contextlib import ExitStack
import http.client
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time

from playwright.sync_api import expect, sync_playwright


HOST = "ismanager.test"
SAMPLE = Path(__file__).parent / "fixtures" / "speech-ru.ogg"
TLS = ssl._create_unverified_context()  # The two certificates belong to the disposable test.
FORWARDED = {
    "Forwarded": "for=192.0.2.90;proto=http;host=other.test",
    "X-Forwarded-For": "192.0.2.90",
    "X-Forwarded-Host": "other.test",
    "X-Forwarded-Port": "4444",
    "X-Forwarded-Proto": "http",
}


def docker(*args, **options):
    return subprocess.run(["docker", *args], check=True, text=True,
                          stdout=subprocess.PIPE, **options).stdout.strip()


def published_port(container, internal=8443):
    return int(docker("port", container, f"{internal}/tcp").rsplit(":", 1)[1])


def request(port, secure, path, headers=None):
    options = {"context": TLS} if secure else {}
    client = http.client.HTTPSConnection if secure else http.client.HTTPConnection
    conn = client("127.0.0.1", port, timeout=3, **options)
    try:
        conn.request("GET", path, headers={"Host": f"{HOST}:{port}", **(headers or {})})
        reply = conn.getresponse()
        return reply.status, reply.headers
    finally:
        conn.close()


def certificate(port):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        with TLS.wrap_socket(sock, server_hostname=HOST) as secure:
            return secure.getpeercert(binary_form=True)


def wait_healthy(container):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        state = docker("inspect", "-f", "{{.State.Status}} {{.State.Health.Status}}", container)
        if state == "running healthy":
            return
        if state.startswith(("dead ", "exited ")):
            break
        time.sleep(1)
    subprocess.run(["docker", "logs", "--tail", "40", container], check=False)
    raise RuntimeError(f"{container} failed its Docker healthcheck ({state})")


def configure_nginx(tmp):
    subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                    "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}",
                    "-keyout", str(tmp / "tls.key"), "-out", str(tmp / "tls.crt")],
                   check=True, capture_output=True)
    example = (Path(__file__).resolve().parents[1] / "docs" / "nginx.conf.example").read_text()
    server = (example.replace("listen 443 ssl;", "listen 8443 ssl;")
              .replace("ismanager.example.org", HOST)
              .replace("/etc/nginx/tls/ismanager.fullchain.pem", "/test/tls.crt")
              .replace("/etc/nginx/tls/ismanager.key", "/test/tls.key")
              .replace("proxy_pass http://127.0.0.1:18084;",
                       "set $backend web:8443; proxy_pass http://$backend;"))
    # Use Docker DNS for web container replacements. The second listener tests a
    # trusted proxy mistakenly advertising plain HTTP.
    plain = server.replace("listen 8443 ssl;", "listen 8080;").replace(
        "X-Forwarded-Proto https;", "X-Forwarded-Proto http;")
    (tmp / "nginx.conf").write_text(
        "events {}\nhttp { access_log off; resolver 127.0.0.11 ipv6=off valid=1s;\n"
        + server + plain + "}\n", encoding="utf-8")


def login(page, origin, password, replacement=None):
    page.goto(origin + "/login")
    page.get_by_label("Имя пользователя").fill("admin")
    page.get_by_label("Пароль", exact=True).fill(password)
    page.get_by_role("button", name="Войти").click()
    if replacement is not None:
        page.get_by_label("Текущий пароль").fill(password)
        page.get_by_label("Новый пароль", exact=True).fill(replacement)
        page.get_by_label("Повторите новый пароль").fill(replacement)
        page.get_by_role("button", name="Сохранить пароль").click()
    expect(page.get_by_role("heading", name="Рабочее пространство")).to_be_visible()


def check_modules(page, origin, label):
    page.goto(origin + "/passwords/")
    page.get_by_role("tab", name="Случайный").click()
    page.locator("#pass-generate").click()
    expect(page.locator("#pass-results li")).to_have_count(7)
    if not page.evaluate("window.isSecureContext"):
        page.locator("#pass-results button").first.click()
        expect(page.locator("#pass-status")).to_contain_text("выделен")
        assert page.evaluate("window.getSelection().toString().length") == 16
        fallback = page.context.new_page()
        try:
            fallback.add_init_script("Object.defineProperty(window, 'crypto', {value: undefined})")
            fallback.goto(origin + "/passwords/")
            form = fallback.locator("#pass-form")
            expect(form.locator('[name="processor"]')).to_have_value("server")
            expect(form.locator('option[value="browser"]')).to_be_disabled()
            form.get_by_role("tab", name="Случайный").click()
            with fallback.expect_response(lambda r: r.request.method == "POST") as result:
                form.locator("#pass-generate").click()
            assert result.value.ok
            expect(fallback.locator("#pass-results li")).to_have_count(7)
        finally:
            fallback.close()

    page.goto(origin + "/redaction/")
    page.locator('#redaction-form [name="text"]').fill("Связь по почте test@example.org")
    page.get_by_role("button", name="Обезличить и сохранить").click()
    result = page.locator("#redacted-text").input_value()
    assert result.strip() and "example.org" not in result

    page.goto(origin + "/threats/")
    page.get_by_role("button", name="Создать анкету").click()
    for field in ("systemType", "systemNetworkCondition"):
        page.locator(f'select[name="{field}"]').select_option(index=1)
    page.get_by_role("button", name="Далее").click()
    page.locator('[name="infosystemShortName"]').fill(label)
    page.get_by_role("button", name="Сохранить черновик").click()
    page.goto(origin + "/threats/")
    expect(page.get_by_role("link", name=label)).to_be_visible()

    page.goto(origin + "/transcription/")
    page.locator('[name="media"]').set_input_files(SAMPLE)
    page.get_by_role("button", name="Расшифровать запись").click()
    field = page.locator("#asr-text")
    expect(field).to_be_visible(timeout=900000)
    transcript = field.input_value().lower()
    assert "день" in transcript and "текст" in transcript


def run(web_image, worker_image, nginx_image, model_volume=None):
    prefix = "ismanager-nettest-" + secrets.token_hex(6)
    web, worker, proxy = (prefix + "-" + part for part in ("web", "worker", "proxy"))
    data, models = prefix + "-data", prefix + "-models"
    local_env = dict(os.environ, SECRET_KEY=secrets.token_hex(32))
    password = secrets.token_urlsafe(32)
    with ExitStack() as cleanup:
        def remove(*args):
            cleanup.callback(subprocess.run, ["docker", *args], capture_output=True)
        docker("network", "create", prefix)
        remove("network", "rm", prefix)
        if model_volume:
            docker("volume", "inspect", model_volume)
            models = model_volume
        for volume in ((data,) if model_volume else (data, models)):
            docker("volume", "create", volume)
            remove("volume", "rm", volume)
        tmp = Path(cleanup.enter_context(tempfile.TemporaryDirectory()))
        configure_nginx(tmp)
        docker("run", "-d", "--name", proxy, "--network", prefix,
               "-p", "127.0.0.1::8443", "-p", "127.0.0.1::8080", "-v", f"{tmp}:/test:ro",
               nginx_image, "nginx", "-c", "/test/nginx.conf", "-g", "daemon off;")
        remove("rm", "-f", proxy)
        proxy_ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", proxy)
        proxy_port = published_port(proxy)
        browser_api = cleanup.enter_context(sync_playwright())
        chromium = browser_api.chromium.launch(executable_path=os.getenv("CHROMIUM_PATH") or None, args=[
            "--no-proxy-server", f"--host-resolver-rules=MAP {HOST} 127.0.0.1",
        ])
        cleanup.callback(chromium.close)
        previous = None
        initial_cert = None
        insecure_cookie = None
        legacy_cookie = None
        for mode in ("legacy", "http", "proxy", "https"):
            if previous:
                docker("rm", "-f", web)
            env = [] if mode == "legacy" else ["-e", f"ACCESS_MODE={mode}"]
            if mode == "proxy":
                env += ["-e", f"TRUSTED_PROXY_IPS={proxy_ip}"]
            authority = f"{HOST}:{proxy_port}" if mode == "proxy" else HOST
            docker("run", "-d", "--name", web, "--network", prefix, "--network-alias", "web",
                   "-p", "127.0.0.1::8443", "-v", f"{data}:/data", "-e", "SECRET_KEY",
                   "-e", f"PUBLIC_HOST={authority}", *env, web_image, env=local_env)
            if not previous:
                remove("rm", "-f", web)
            wait_healthy(web)
            port = published_port(web)
            secure = mode != "http"
            front_port = proxy_port if mode == "proxy" else port
            origin = f"{'https' if secure else 'http'}://{HOST}:{front_port}"
            if mode == "legacy":
                initial_cert = certificate(port)
                first_password = docker("exec", web, "flask", "--app", "app", "admin-password", "--if-missing")
                assert first_password
                docker("run", "-d", "--name", worker, "--network", prefix, "-v", f"{data}:/data",
                       "-v", f"{models}:/models" + (":ro" if model_volume else ""), worker_image)
                remove("rm", "-f", worker)
            if mode == "https":
                assert certificate(port) == initial_cert
            if mode == "proxy":
                claimed = {**FORWARDED, "X-Forwarded-Proto": "https", "Host": authority}
                denied_requests = (
                    (port, False, claimed, 403),
                    (published_port(proxy, 8080), False, {"Host": authority}, 400),
                    (proxy_port, True, {"Host": "other.test"}, 400),
                )
                for target, tls, headers, expected in denied_requests:
                    status, response = request(target, tls, "/login", headers)
                    assert status == expected and not response.get("Set-Cookie"), status

            context = chromium.new_context(ignore_https_errors=True)
            try:
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda err: errors.append(str(err)))
                login(page, origin, first_password if mode == "legacy" else password,
                      password if mode == "legacy" else None)
                assert page.evaluate("window.isSecureContext") == secure
                name = "ismanager_session" if secure else "ismanager_http_session"
                cookie = next(c for c in context.cookies() if c["name"] == name)
                assert cookie["secure"] == secure and cookie["httpOnly"] and cookie["sameSite"] == "Lax"
                if mode == "legacy":
                    legacy_cookie = f'{name}={cookie["value"]}'
                if mode == "http":
                    insecure_cookie = cookie["value"]
                    status, response = request(front_port, False, "/admin/", {"Cookie": legacy_cookie})
                    assert status == 302 and response["Location"] == "/login"
                if mode in ("proxy", "https"):
                    assert request(front_port, True, "/admin/", {"Cookie": legacy_cookie})[0] == 200
                    status, response = request(front_port, True, "/admin/", {"Cookie": f"{name}={insecure_cookie}"})
                    assert status == 302 and response["Location"] == "/login"
                altered = dict(FORWARDED)
                altered["X-Forwarded-Proto"] = "http" if secure else "https"
                altered["Cookie"] = cookie["name"] + "=" + cookie["value"]
                status, response = request(front_port, secure, "/threats", altered)
                assert status == 308 and response["Location"] == origin + "/threats/", (
                    status, response.get("Location"))
                if mode in ("http", "proxy"):
                    check_modules(page, origin, "Проверка " + mode)
                if mode in ("proxy", "https"):
                    page.goto(origin + "/threats/")
                    expect(page.get_by_role("link", name="Проверка http")).to_be_visible()
                assert not errors, errors
            finally:
                context.close()
            previous = mode
            print(f"{mode} passed", flush=True)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("web_image")
    cli.add_argument("worker_image")
    cli.add_argument("--nginx-image", default="nginx:alpine")
    cli.add_argument("--model-volume", help="Reuse prepared GigaAM weights read-only.")
    args = cli.parse_args()
    run(args.web_image, args.worker_image, args.nginx_image, args.model_volume)
