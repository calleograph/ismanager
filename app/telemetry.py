"""Resource counters for the speech worker and the administrator's system screen."""
import json
import logging
import os
import platform
import shutil
import sqlite3
import threading
import time
from functools import cache
from importlib import metadata
from pathlib import Path

MIB = 1024 ** 2
COUNTERS = ("cores", "busy_cores", "memory_mib", "capacity_mib")
_host_lock = threading.Lock()
_last_ticks = None
_last_cpu = {}


def read(path):
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def meminfo():
    values = {}
    for line in read(Path("/proc/meminfo")).splitlines():
        key, _, rest = line.partition(":")
        if key in ("MemAvailable", "MemTotal"):
            values[key] = int(rest.split()[0]) // 1024
    return values


def host_cpu():
    # Linux already includes the guest ticks in user and nice. Count only the first eight fields.
    global _last_ticks, _last_cpu
    with _host_lock:
        lines = read(Path("/proc/stat")).splitlines()
        if not lines or not lines[0].startswith("cpu "):
            return {}
        ticks = [int(value) for value in lines[0].split()[1:9]]
        if len(ticks) < 5:
            return {}
        total = sum(ticks)
        idle = ticks[3] + ticks[4]
        if _last_ticks and total > _last_ticks[0]:
            ratio = max(0, min(1, 1 - (idle - _last_ticks[1]) / (total - _last_ticks[0])))
            _last_cpu = {"percent": round(ratio * 100, 1), "busy_cores": round(ratio * (os.cpu_count() or 1), 2)}
        _last_ticks = total, idle
        return _last_cpu.copy()


def cgroup_directory():
    root = Path("/sys/fs/cgroup")
    for line in read(Path("/proc/self/cgroup")).splitlines():
        if line.startswith("0::"):
            rel = Path(line[3:].lstrip("/"))
            if ".." not in rel.parts and (root / rel / "cpu.stat").is_file():
                return root / rel
    return root


def cpu_cores(directory):
    try:
        cores = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cores = os.cpu_count() or 1
    quota = read(directory / "cpu.max").split()
    if len(quota) == 2 and quota[0].isdigit() and int(quota[1]) > 0:
        cores = min(cores, int(quota[0]) / int(quota[1]))
    return cores


def asr_threads(directory):
    configured = os.getenv("ASR_THREADS") or os.getenv("OMP_NUM_THREADS")
    limit = int(configured) if configured and configured.isdecimal() else 4
    return max(1, min(limit, int(cpu_cores(directory))))


def sample(directory, previous=None):
    cores = cpu_cores(directory)
    cpu = dict(line.split() for line in read(directory / "cpu.stat").splitlines())
    counter = int(cpu["usage_usec"]) / 1e6 if "usage_usec" in cpu else time.process_time()
    now = time.monotonic()
    busy = None
    if previous and now > previous[0]:
        busy = round(max(0, (counter - previous[1]) / (now - previous[0])), 2)
    memory = read(directory / "memory.current")
    total = meminfo().get("MemTotal")
    limit = read(directory / "memory.max")
    if limit.isdigit():
        total = min(total or int(limit) // MIB, int(limit) // MIB)
    if memory.isdigit():
        used = int(memory) // MIB
    else:
        rss = next((s for s in read(Path("/proc/self/status")).splitlines() if s.startswith("VmRSS:")), "")
        used = int(rss.split()[1]) // 1024 if rss else None
    return {"cores": round(cores, 2), "busy_cores": busy, "memory_mib": used, "capacity_mib": total}, (now, counter)


def versions(packages):
    result = {}
    for label, name in packages.items():
        try:
            result[label] = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return result


def publish_worker(data_dir):
    directory = cgroup_directory()
    components = versions({"PyTorch": "torch", "GigaAM": "gigaam", "Silero VAD": "silero-vad"})
    threads = asr_threads(directory)
    previous = None
    while True:
        try:
            counters, previous = sample(directory, previous)
            info = {"time": time.time(), "resources": counters, "components": components,
                    "host_cpu": host_cpu(),
                    "device": os.getenv("ASR_DEVICE", "cpu"), "threads": threads}
            tmp = data_dir / "asr-resources.tmp"
            tmp.write_text(json.dumps(info))
            tmp.replace(data_dir / "asr-resources.json")
        except (OSError, ValueError) as exc:
            logging.getLogger("asr").warning("Resource counters unavailable (%s)", type(exc).__name__)
        time.sleep(2)


def worker_info(data_dir):
    try:
        payload = json.loads((Path(data_dir) / "asr-resources.json").read_text())
        if 0 <= time.time() - payload["time"] < 20:
            return payload
    except (OSError, KeyError, TypeError, ValueError):
        pass
    return {}


def public_counters(info):
    values = info.get("resources", {})
    return {k: values[k] for k in COUNTERS if isinstance(values.get(k), (float, int))}


def admin_counters(data_dir, worker=None):
    if worker is None:
        worker = worker_info(data_dir)
    ram = meminfo()
    cpu = worker.get("host_cpu") or host_cpu()
    return dict(cpu=cpu, cores=os.cpu_count(), total=ram.get("MemTotal"), available=ram.get("MemAvailable"),
                worker=public_counters(worker))


@cache
def server_details():
    cpu = None
    try:
        with Path("/proc/cpuinfo").open() as info:
            cpu = next((line.partition(":")[2].strip() for line in info if line.startswith("model name")), None)
    except OSError:
        pass
    packages = versions({"Flask": "flask", "Gunicorn": "gunicorn"})
    packages.update({"Python": platform.python_version(), "SQLite": sqlite3.sqlite_version})
    return cpu, packages


def system_info(data_dir):
    worker = worker_info(data_dir)
    cpu, packages = server_details()
    disk = shutil.disk_usage(data_dir)
    return dict(cpu=cpu, live=admin_counters(data_dir, worker),
                kernel=platform.release(), arch=platform.machine(), disk_free=disk.free // MIB, disk_total=disk.total // MIB,
                components=packages | worker.get("components", {}), worker=worker)
