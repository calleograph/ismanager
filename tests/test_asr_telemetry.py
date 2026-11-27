import json
import time

from app import telemetry


def test_container_limits_and_load_are_measured_from_cpu_deltas(tmp_path, monkeypatch):
    (tmp_path / "cpu.max").write_text("250000 100000")
    (tmp_path / "memory.max").write_text(str(1024 * 1024**2))
    (tmp_path / "memory.current").write_text(str(193 * 1024**2))
    (tmp_path / "cpu.stat").write_text("usage_usec 3000000\nuser_usec 2700000")
    monkeypatch.setattr(telemetry.os, "sched_getaffinity", lambda pid: set(range(8)))
    monkeypatch.setattr(telemetry, "meminfo", lambda: {"MemTotal": 4096})
    ticks = iter([20, 22])
    monkeypatch.setattr(telemetry.time, "monotonic", lambda: next(ticks))
    initial, previous = telemetry.sample(tmp_path)
    assert initial["busy_cores"] is None
    (tmp_path / "cpu.stat").write_text("usage_usec 6000000")
    metrics, _ = telemetry.sample(tmp_path, previous)
    assert metrics == dict(cores=2.5, busy_cores=1.5, memory_mib=193, capacity_mib=1024)


def test_public_telemetry_excludes_system_details_and_expires(tmp_path):
    info = {"time": time.time(), "hostname": "secret", "components": {"torch": "secret"},
            "resources": {"cores": 8, "busy_cores": 1, "hostname": "private", "memory_mib": "bad"}}
    data = tmp_path / "asr-resources.json"
    data.write_text(json.dumps(info))
    assert telemetry.public_counters(telemetry.worker_info(tmp_path)) == {"cores": 8, "busy_cores": 1}
    data.write_text(json.dumps(info | {"time": time.time() - 60}))
    assert telemetry.worker_info(tmp_path) == {}


def test_host_cpu_and_worker_cpu_use_distinct_denominators(monkeypatch):
    readings = iter(["cpu  4 1 2 80 10 1 1 1 2 0", "cpu  8 1 4 92 11 2 1 1 4 0"])
    monkeypatch.setattr(telemetry, "read", lambda path: next(readings))
    monkeypatch.setattr(telemetry.os, "cpu_count", lambda: 10)
    monkeypatch.setattr(telemetry, "_last_ticks", None)
    monkeypatch.setattr(telemetry, "_last_cpu", {})
    assert telemetry.host_cpu() == {}
    assert telemetry.host_cpu() == {"percent": 35.0, "busy_cores": 3.5}
