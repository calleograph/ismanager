"""Choose and apply the published web address without changing credentials or volumes."""
import argparse
import fcntl
import ipaddress
import os
import re
import secrets
import socket
import subprocess
import sys
from urllib.parse import urlsplit

from app.network import public_authority, public_url
from scripts import manage


def lan_address():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Selecting a route discovers the local interface without sending a packet.
        sock.connect(("192.0.2.1", 9))
        address = ipaddress.IPv4Address(sock.getsockname()[0])
    if not any(address in ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise ValueError("Укажите IPv4-адрес интерфейса локальной сети через --bind.")
    return str(address)


def network_settings(old, mode=None, bind=None, port=None, host=None, trusted_proxy=None, external=None):
    previous = old.get("ACCESS_MODE", "https")
    mode = mode or previous
    same = mode == previous
    if mode not in {"http", "proxy", "https"}:
        raise ValueError("Выберите --access http, proxy или https.")
    if bind is None:
        bind = old.get("BIND_ADDRESS") if same else None
    if not bind:
        bind = lan_address() if mode == "http" else "127.0.0.1"
    addr = ipaddress.IPv4Address(bind)
    if addr.is_multicast or addr == ipaddress.IPv4Address("255.255.255.255"):
        raise ValueError("Укажите IPv4-адрес интерфейса через --bind.")
    if port is None:
        port = old.get("PORT") if same else None
    port = int(port) if port is not None else (18443 if mode == "https" else 18084)
    if not 1 <= port <= 65535:
        raise ValueError("Порт должен быть в диапазоне 1–65535.")

    if external is None and same and host is None and (mode == "proxy" or
            (bind == old.get("BIND_ADDRESS") and str(port) == old.get("PORT"))):
        external = old.get("PUBLIC_URL")
    if external:
        external = public_url(mode, host, port, explicit=external)
        origin = urlsplit(external)
        default = 80 if origin.scheme == "http" else 443
        if host and public_authority(host, default) != origin.netloc:
            raise ValueError("--host и --public-url указывают разные адреса. Укажите внешний адрес один раз.")
        host = origin.netloc if mode == "proxy" else origin.hostname
    if host is None and same and (mode == "proxy" or bind == old.get("BIND_ADDRESS")):
        host = old.get("PUBLIC_HOST")
    if not host:
        if mode == "proxy" or addr.is_unspecified:
            raise ValueError("Укажите в --host адрес, который пользователи вводят в браузере.")
        host = "localhost" if addr.is_loopback else str(addr)
    if mode != "proxy" and ":" in host:
        raise ValueError("Для прямого доступа порт задаётся через --port.")
    host = public_authority(host, 80 if external and external.startswith("http://") else 443)

    if mode == "proxy":
        peers = trusted_proxy if trusted_proxy is not None else (old.get("TRUSTED_PROXY_IPS") if same else None)
        if not peers:
            if not addr.is_loopback:
                raise ValueError("Для прокси на другом узле укажите его IP через --trusted-proxy.")
            peers = "gateway"
        if peers == "gateway":
            if not addr.is_loopback:
                raise ValueError("Автовыбор шлюза Docker разрешён при --bind 127.0.0.1.")
        else:
            if "%" in peers:
                raise ValueError("Укажите IP доверенного прокси без идентификатора зоны.")
            addresses = [ipaddress.ip_address(part.strip()) for part in peers.split(",")]
            if any(ip.is_unspecified or ip.is_multicast for ip in addresses):
                raise ValueError("Укажите конкретные IP доверенных прокси.")
            peers = ",".join(dict.fromkeys(map(str, addresses)))
    else:
        if trusted_proxy is not None:
            raise ValueError("--trusted-proxy применяется с --access proxy.")
        peers = ""
    return dict(ACCESS_MODE=mode, BIND_ADDRESS=str(addr), PORT=str(port), PUBLIC_HOST=host,
                TRUSTED_PROXY_IPS=peers, PUBLIC_URL=external or "")


def check_port(cfg, old):
    if cfg["PORT"] == old.get("PORT") and (
        cfg["BIND_ADDRESS"] == old.get("BIND_ADDRESS") or "0.0.0.0" in (cfg["BIND_ADDRESS"], old.get("BIND_ADDRESS"))
    ):
        return
    with socket.socket() as sock:
        sock.bind((cfg["BIND_ADDRESS"], int(cfg["PORT"])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initialize", metavar="NAME")
    parser.add_argument("--access", dest="mode", choices=["http", "proxy", "https"])
    parser.add_argument("--bind")
    parser.add_argument("--port", type=int)
    parser.add_argument("--host")
    parser.add_argument("--trusted-proxy")
    parser.add_argument("--public-url")
    args = parser.parse_args()
    os.umask(0o077)
    manage.STATE.mkdir(exist_ok=True)
    with (manage.STATE / "operation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = {} if args.initialize else manage.settings()
        config = {**old, **network_settings(old, args.mode, args.bind, args.port, args.host,
                                            args.trusted_proxy, args.public_url)}
        check_port(config, old)
        if args.initialize:
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", args.initialize):
                raise ValueError("Недопустимое имя проекта Compose.")
            config.update(COMPOSE_PROJECT_NAME=args.initialize, DATA_VOLUME=args.initialize + "_data",
                          SECRET_KEY=secrets.token_hex(32), ASR_DEVICE="cpu")
            if manage.ENV.exists():
                raise ValueError("Этот экземпляр уже настроен.")
            manage.save_config(config)
        else:
            if (manage.STATE / "pending.json").exists():
                raise ValueError("Завершите восстановление через scripts/manage.py recover.")
            if old != config:
                manage.save_config(config)
            try:
                manage.compose("up", "-d", "--no-build", "--no-deps", "--wait", "--wait-timeout", "90", "web")
            except (subprocess.CalledProcessError, OSError, KeyboardInterrupt):
                manage.save_config(old)
                manage.compose("up", "-d", "--no-build", "--no-deps", "--wait", "--wait-timeout", "90", "web")
                raise


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Настройка сети не завершена: {error}")
