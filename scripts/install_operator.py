"""Install a dedicated systemd unit for this checkout and Compose project."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

from manage import ROOT, STATE, replace, settings

user = os.geteuid() != 0
cfg = settings()
unit = "ismanager-operator-" + cfg["COMPOSE_PROJECT_NAME"] + ".service"
directory = Path.home()/".config/systemd/user" if user else Path("/etc/systemd/system")
destination = directory / unit
path = str(ROOT / "scripts/host_helper.py")
if any(c in path for c in '\n\r"\\%$'):
    raise SystemExit("Недопустимый символ в пути для службы systemd.")
content = f"""[Unit]
Description=IS Manager release and backup helper ({cfg['COMPOSE_PROJECT_NAME']})
After=network.target

[Service]
ExecStart=/usr/bin/python3 "{path}"
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy={'default.target' if user else 'multi-user.target'}
"""
cmd = ["systemctl", *(["--user"] if user else [])]
marker = STATE / "control" / "operator-disabled"
if sys.argv[1:] == ["--disable"]:
    replace(marker, "disabled\n", 0o644)
    if destination.exists() and path in destination.read_text() and shutil.which("systemctl") and Path("/run/systemd/system").is_dir():
        subprocess.run([*cmd, "disable", "--now", unit], check=True)
    print("Веб-управление обновлениями отключено. Используйте python3 scripts/manage.py check или update.")
    sys.exit(0)
if sys.argv[1:]:
    sys.exit("Используйте --disable для отключения помощника.")
if destination.exists() and path not in destination.read_text():
    raise SystemExit("Имя службы уже используется другой установкой.")
directory.mkdir(exist_ok=True, parents=True)
destination.write_text(content)
subprocess.run([*cmd, "daemon-reload"], check=True)
subprocess.run([*cmd, "enable", unit], check=True)
subprocess.run([*cmd, "restart", unit], check=True)
marker.unlink(missing_ok=True)
print("Помощник веб-обновлений включён.")
