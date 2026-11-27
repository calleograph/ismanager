"""HTTP/TLS entry points and the boundary between the reverse proxy and Flask."""
import http.client
import ipaddress
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

MODES = {"https", "http", "proxy"}
DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


def public_authority(host, default_port=443):
    """Validate the external Host without trusting a forwarded address."""
    if not isinstance(host, str) or len(host) > 260:
        raise ValueError("Некорректный внешний адрес.")
    match = re.fullmatch(r"(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?", host, re.ASCII)
    if not match:
        raise ValueError("Укажите имя хоста и при необходимости порт.")
    hostname, port = match.groups()
    if hostname.startswith("["):
        hostname = f"[{ipaddress.IPv6Address(hostname[1:-1])}]"
    else:
        hostname = hostname.lower()
        if len(hostname) > 253 or not re.fullmatch(rf"{DNS_LABEL}(?:\.{DNS_LABEL})*", hostname):
            raise ValueError("Некорректное имя публичного сервера.")
        if re.fullmatch(r"[\d.]+", hostname):
            hostname = str(ipaddress.IPv4Address(hostname))
    port = int(port or default_port)
    if not 1 <= port <= 65535:
        raise ValueError("Порт должен быть от 1 до 65535.")
    return hostname if port == default_port else f"{hostname}:{port}"


def public_url(mode, host, port, explicit=None):
    if explicit:
        if not re.fullmatch(r"https?://[^/?#\s]+/?", explicit, re.ASCII):
            raise ValueError("Укажите полный внешний HTTP(S)-адрес без пути, параметров и реквизитов.")
        origin = urlsplit(explicit)
        if mode != "proxy" and mode != origin.scheme:
            raise ValueError("Схема внешнего адреса должна совпадать с режимом доступа.")
        default = 80 if origin.scheme == "http" else 443
        authority = public_authority(origin.netloc, default)
        if mode != "proxy" and (origin.port or default) != int(port):
            raise ValueError("Для разных внешнего и внутреннего портов выберите --access proxy.")
        return f"{origin.scheme}://{authority}/"
    scheme = "http" if mode == "http" else "https"
    if mode != "proxy" and str(port) != ("80" if mode == "http" else "443"):
        host += ":" + str(port)
    return f"{scheme}://{host}/"


def gateway_ip(path=Path("/proc/net/route")):
    gateways = set()
    for line in path.read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[1] == fields[7] == "00000000" and int(fields[3], 16) & 3 == 3:
            # /proc/net/route writes IPv4 addresses as host-endian hexadecimal integers.
            gateway = ipaddress.IPv4Address(int(fields[2], 16).to_bytes(4, sys.byteorder))
            if not gateway.is_unspecified:
                gateways.add(gateway)
    if len(gateways) != 1:
        raise ValueError("Не удалось однозначно определить шлюз контейнера. Задайте IP доверенного прокси.")
    return gateways.pop()


def proxy_peers(value):
    if value == "gateway":
        return {gateway_ip()}
    if not value or "%" in value:
        raise ValueError("В режиме proxy задайте TRUSTED_PROXY_IPS.")
    addresses = {ipaddress.ip_address(item.strip()) for item in value.split(",")}
    if any(address.is_unspecified or address.is_multicast for address in addresses):
        raise ValueError("Укажите конкретные IP доверенных прокси.")
    return addresses


def install_proxy(app):
    """Read REMOTE_ADDR before the framework creates its Request or opens a session."""
    from werkzeug.wrappers import Response

    origin = urlsplit(app.config["PUBLIC_URL"])
    default_port = 80 if origin.scheme == "http" else 443
    authority = origin.netloc
    peers = proxy_peers(app.config["TRUSTED_PROXY_IPS"])
    delegate = app.wsgi_app

    def handle(environ, start_response):
        try:
            peer = ipaddress.ip_address(environ.get("REMOTE_ADDR", ""))
        except ValueError:
            peer = None
        if (peer is not None and peer.is_loopback and environ["PATH_INFO"] == "/healthz"
                and environ["REQUEST_METHOD"] in ("GET", "HEAD")):
            return delegate(environ, start_response)
        if peer not in peers:
            return Response("Доступ разрешён через доверенный прокси.", status=403)(environ, start_response)
        try:
            if public_authority(environ.get("HTTP_HOST", ""), default_port) != authority:
                raise ValueError
            if environ.get("HTTP_X_FORWARDED_PROTO") != origin.scheme:
                raise ValueError
            if "HTTP_X_FORWARDED_FOR" in environ:
                client = environ["HTTP_X_FORWARDED_FOR"]
                if "%" in client:
                    raise ValueError
                environ["REMOTE_ADDR"] = str(ipaddress.ip_address(client))
        except ValueError:
            return Response("Проверьте Host, X-Forwarded-Proto и X-Forwarded-For прокси.", status=400)(environ, start_response)
        environ["wsgi.url_scheme"] = origin.scheme
        environ["HTTP_HOST"] = authority
        # Downstream libraries must see only the values which have been validated above.
        for key in list(environ):
            if key == "HTTP_FORWARDED" or key.startswith("HTTP_X_FORWARDED_"):
                del environ[key]
        return delegate(environ, start_response)

    app.wsgi_app = handle


def gunicorn_args(mode):
    args = [
        sys.executable, "-m", "gunicorn", "--bind", "0.0.0.0:8443",
        "--workers", "2", "--threads", "3", "--timeout", "180",
        "--forwarded-allow-ips=", "--forwarder-headers=", "--proxy-protocol", "off",
    ]
    if mode == "https":
        pem = str(Path(os.environ.get("DATA_DIR", "/data")) / "tls.pem")
        args.extend(["--certfile", pem, "--keyfile", pem])
    return [*args, "app:create_app()"]


def main():
    mode = os.getenv("ACCESS_MODE", "https")
    if mode not in MODES:
        raise SystemExit("ACCESS_MODE должен быть https, http или proxy.")
    if sys.argv[1:] == ["health"]:
        if mode == "https":
            conn = http.client.HTTPSConnection("127.0.0.1", 8443, timeout=4, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection("127.0.0.1", 8443, timeout=4)
        try:
            conn.request("GET", "/healthz")
            if conn.getresponse().status != 200:
                raise SystemExit(1)
        finally:
            conn.close()
    elif not sys.argv[1:]:
        if mode == "https":
            from .tls import ensure_certificate
            ensure_certificate()
        argv = gunicorn_args(mode)
        os.execv(argv[0], argv)
    else:
        raise SystemExit("Используйте python -m app.network или python -m app.network health.")


if __name__ == "__main__":
    main()
