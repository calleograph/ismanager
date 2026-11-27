import http.client
import ipaddress
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest
from flask import request

from app import create_app
from app.network import gateway_ip, gunicorn_args, proxy_peers, public_authority

ROOT = Path(__file__).resolve().parents[1]
HOST = "portal.example:9443"
PROXY = "192.0.2.12"
CLIENT = "198.51.100.26"


def inspect_request(response):
    response.headers["X-Test-Scheme"] = request.scheme
    response.headers["X-Test-Peer"] = request.remote_addr
    response.headers["X-Test-Host"] = request.host
    return response


def client_config(folder, **settings):
    return dict(DATA_DIR=str(folder), SECRET_KEY=secrets.token_hex(32), TESTING=True, **settings)


def token(response):
    return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()


def test_http_sessions_login_csrf_passwords_and_https_transition(tmp_path):
    cfg = client_config(tmp_path, ACCESS_MODE="http")
    app = create_app(cfg)
    c = app.test_client()
    origin = "http://lan.example"
    pw = app.test_cli_runner().invoke(args=["admin-password"]).output.strip()
    page = c.get("/login", base_url=origin)
    cookie = page.headers["Set-Cookie"]
    assert cookie.startswith("ismanager_http_session=") and "Secure" not in cookie
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert c.post("/login", base_url=origin, data={"username": "admin", "password": pw}).status_code == 400
    login = c.post("/login", base_url=origin, data={"username": "admin", "password": pw, "csrf_token": token(page)})
    assert login.location == "/account"
    new = secrets.token_urlsafe(30) + "!Aa3"
    assert c.post("/account", base_url=origin, data=dict(action="password", current=pw, new=new, repeat=new,
                  csrf_token=token(c.get("/account", base_url=origin)))).location == "/"
    page = c.get("/passwords/", base_url=origin)
    result = c.post("/passwords/generate", base_url=origin, data={"csrf_token": token(page), "mode": "story"})
    assert result.status_code == 200 and len(result.json["results"]) == 7

    other = create_app(cfg | {"ACCESS_MODE": "https"}).test_client()
    copied = c.get_cookie("ismanager_http_session", domain="lan.example")
    other.set_cookie("ismanager_session", copied.value, domain="lan.example")
    assert other.get("/admin/", base_url="https://lan.example").location == "/login"


def test_proxy_peer_scheme_host_and_limiter_address(tmp_path):
    app = create_app(client_config(tmp_path, ACCESS_MODE="proxy", TRUSTED_PROXY_IPS=PROXY, PUBLIC_HOST=HOST))
    app.after_request(inspect_request)
    c = app.test_client()
    headers = {"Host": HOST, "X-Forwarded-Proto": "https", "X-Forwarded-For": CLIENT,
               "X-Forwarded-Host": "elsewhere.example", "Forwarded": "host=elsewhere.example;proto=http"}

    def get(extra=None, peer=PROXY, path="/login"):
        return c.get(path, headers=headers | (extra or {}), environ_overrides={"REMOTE_ADDR": peer})

    page = get()
    assert page.status_code == 200
    assert "Secure" in page.headers["Set-Cookie"]
    assert page.headers["X-Test-Scheme"] == "https" and page.headers["X-Test-Peer"] == CLIENT
    assert page.headers["X-Test-Host"] == HOST
    assert get(peer="192.0.2.90").status_code == 403
    assert get(peer="127.0.0.1").status_code == 403
    assert get(peer="127.0.0.1", path="/healthz").status_code == 200
    for override in (
        {"X-Forwarded-Proto": "http"}, {"X-Forwarded-Proto": "https, http"},
        {"X-Forwarded-For": CLIENT + ", " + PROXY}, {"X-Forwarded-For": "invalid"},
        {"Host": "portal.example:9444"}, {"Host": "elsewhere.example:9443"},
    ):
        assert get(override).status_code == 400
    assert c.get("/login", headers={"Host": HOST, "X-Forwarded-Proto": "https"},
                 environ_overrides={"REMOTE_ADDR": PROXY}).headers["X-Test-Peer"] == PROXY


def test_gateway_and_external_hosts(tmp_path):
    path = tmp_path / "routes"
    rows = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"

    def line(gateway):
        number = int.from_bytes(ipaddress.IPv4Address(gateway).packed, sys.byteorder)
        return f"eth0 00000000 {number:08X} 0003 0 0 0 00000000 0 0 0\n"

    path.write_text(rows)
    with pytest.raises(ValueError):
        gateway_ip(path)
    path.write_text(rows + line("172.16.4.1"))
    assert str(gateway_ip(path)) == "172.16.4.1"
    path.write_text(rows + line("172.16.4.1") + line("172.16.5.1"))
    with pytest.raises(ValueError):
        gateway_ip(path)
    for value in ("*", "192.0.2.0/24", "gateway,127.0.0.1", "", "0.0.0.0", "ff02::5", "fe80::1%eth0"):
        with pytest.raises(ValueError):
            proxy_peers(value)
    assert public_authority("PORTAL.example:443") == "portal.example"
    assert public_authority("[2001:0db8::1]:8443") == "[2001:db8::1]:8443"
    for host in ("user@example", "valid.example.", "host:65536", "host:0", "host:abc", "host,other"):
        with pytest.raises(ValueError):
            public_authority(host)


@pytest.mark.parametrize("mode", ("https", "http", "proxy"))
def test_gunicorn_transport_and_spoofed_headers(mode, tmp_path, monkeypatch):
    # A test-only response header exposes what Flask actually saw behind the Gunicorn parser.
    (tmp_path / "inspect_app.py").write_text(
        "from app import create_app\nfrom tests.test_network import inspect_request\n"
        "app = create_app()\napp.after_request(inspect_request)\n"
    )
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    env = dict(
        os.environ, ACCESS_MODE=mode, SECRET_KEY=secrets.token_hex(32),
        PUBLIC_HOST=HOST if mode == "proxy" else "localhost", TRUSTED_PROXY_IPS="127.0.0.1",
        FORWARDED_ALLOW_IPS="*", PYTHONPATH=os.pathsep.join([str(tmp_path), str(ROOT)]),
    )
    if mode == "https":
        from app.tls import ensure_certificate
        ensure_certificate()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        args = gunicorn_args(mode)
        args[args.index("--bind") + 1] = f"fd://{listener.fileno()}"
        args[args.index("--workers") + 1] = "1"
        args[-1] = "inspect_app:app"
        process = subprocess.Popen(args, cwd=ROOT, env=env, pass_fds=(listener.fileno(),))
        try:
            limit = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    pytest.fail("Gunicorn failed to start")
                if mode == "https":
                    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=2, context=ssl._create_unverified_context())
                else:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request("GET", "/login", headers={
                        "Host": HOST, "X-Forwarded-Proto": "https" if mode != "https" else "http",
                        "X-Forwarded-For": CLIENT, "X-Forwarded-Host": "other.example",
                        "X-Forwarded-Ssl": "off", "X-Forwarded-Protocol": "http",
                    })
                    response = conn.getresponse()
                    response.read()
                    break
                except (ConnectionError, TimeoutError):
                    if time.monotonic() >= limit:
                        raise
                finally:
                    conn.close()
            assert response.status == 200
            assert response.headers["X-Test-Scheme"] == ("http" if mode == "http" else "https")
            assert response.headers["X-Test-Peer"] == (CLIENT if mode == "proxy" else "127.0.0.1")
            assert ("Secure" in response.headers["Set-Cookie"]) == (mode != "http")
        finally:
            process.terminate()
            process.wait(timeout=10)


def test_http_nginx_uses_public_host_port_scheme_and_separate_cookie(tmp_path):
    origin = "http://portal.example:8106/"
    app = create_app(client_config(tmp_path, ACCESS_MODE="proxy", TRUSTED_PROXY_IPS=PROXY,
                                   PUBLIC_URL=origin, PUBLIC_PORT="18086"))
    app.after_request(inspect_request)
    client = app.test_client()
    headers = {"Host": "portal.example:8106", "X-Forwarded-Proto": "http", "X-Forwarded-For": CLIENT}
    sender = {"REMOTE_ADDR": PROXY}
    page = client.get("/login", headers=headers, environ_overrides=sender)
    assert page.headers["X-Test-Scheme"] == "http"
    assert page.headers["X-Test-Host"] == "portal.example:8106"
    assert page.headers["X-Test-Peer"] == CLIENT
    assert page.headers["Set-Cookie"].startswith("ismanager_http_session=") and "Secure" not in page.headers["Set-Cookie"]
    assert client.get("/login", headers=headers | {"X-Forwarded-Proto": "https"}, environ_overrides=sender).status_code == 400
    assert client.get("/login", headers=headers | {"Host": "portal.example:18086"}, environ_overrides=sender).status_code == 400
