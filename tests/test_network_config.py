import subprocess
import sys
from unittest.mock import Mock

import pytest

from app.network import public_url
from scripts import network_config as network


def url(cfg):
    return public_url(cfg["ACCESS_MODE"], cfg["PUBLIC_HOST"], cfg["PORT"])


def test_new_and_legacy_defaults_and_switch(monkeypatch):
    monkeypatch.setattr(network, "lan_address", lambda: "192.168.8.15")
    old = dict(BIND_ADDRESS="127.0.0.1", PORT="19443", PUBLIC_HOST="localhost")
    assert url(network.network_settings(old)) == "https://localhost:19443/"
    lan = network.network_settings(old, mode="http")
    assert (url(lan), lan["BIND_ADDRESS"]) == ("http://192.168.8.15:18084/", "192.168.8.15")
    assert network.network_settings(lan, mode="http") == lan
    proxy = network.network_settings(lan, mode="proxy", host="portal.example:9443")
    assert url(proxy) == "https://portal.example:9443/"
    assert (proxy["BIND_ADDRESS"], proxy["TRUSTED_PROXY_IPS"]) == ("127.0.0.1", "gateway")
    tls = network.network_settings(proxy, mode="https")
    assert url(tls) == "https://localhost:18443/"
    assert tls["TRUSTED_PROXY_IPS"] == ""


def test_remote_proxy_needs_explicit_peer():
    options = dict(mode="proxy", bind="192.168.8.15", host="portal.example")
    for peers in (None, "gateway", "0.0.0.0", "*", "10.0.0.0/8"):
        with pytest.raises(ValueError):
            network.network_settings({}, **options, trusted_proxy=peers)
    cfg = network.network_settings({}, **options, trusted_proxy="192.168.8.11,192.168.8.12")
    assert cfg["TRUSTED_PROXY_IPS"] == "192.168.8.11,192.168.8.12"


def test_failed_network_switch_restores_entire_config(tmp_path, monkeypatch):
    manage = network.manage
    monkeypatch.setattr(manage, "STATE", tmp_path)
    monkeypatch.setattr(manage, "ENV", tmp_path / ".env")
    old = dict(BIND_ADDRESS="127.0.0.1", PORT="18443", PUBLIC_HOST="localhost", DATA_VOLUME="existing",
               SECRET_KEY="old-key", ASR_DEVICE="cpu")
    manage.save_config(old)
    monkeypatch.setattr(network, "check_port", lambda *_: None)
    compose = Mock(side_effect=[subprocess.CalledProcessError(1, "compose"), None])
    monkeypatch.setattr(manage, "compose", compose)
    monkeypatch.setattr(sys, "argv", ["network_config", "--access", "http", "--bind", "192.168.8.15"])
    with pytest.raises(subprocess.CalledProcessError):
        network.main()
    assert manage.settings() == old
    assert compose.call_count == 2


def test_public_http_origin_is_independent_of_proxy_backend():
    cfg = network.network_settings({}, mode="proxy", port=18086, external="http://Portal.Example:8106")
    assert cfg["BIND_ADDRESS"] == "127.0.0.1" and cfg["PORT"] == "18086"
    assert cfg["PUBLIC_HOST"] == "portal.example:8106" and cfg["TRUSTED_PROXY_IPS"] == "gateway"
    assert cfg["PUBLIC_URL"] == "http://portal.example:8106/"
    assert network.network_settings(cfg) == cfg
    secure = network.network_settings(cfg, external="https://portal.example")
    assert secure["PUBLIC_URL"] == "https://portal.example/" and secure["PORT"] == "18086"
    for origin in ("http://unrelated@portal.example", "http://example:0", "http://example/path", "https://example/#x"):
        with pytest.raises(ValueError):
            network.network_settings({}, mode="proxy", external=origin)
    with pytest.raises(ValueError):
        network.network_settings({}, mode="http", bind="127.0.0.1", port=18086, external="http://portal.example:8106")
