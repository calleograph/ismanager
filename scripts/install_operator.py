"""Install a dedicated systemd unit for this checkout and Compose project."""
import os
import subprocess
from pathlib import Path

from manage import ROOT, settings

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
directory.mkdir(exist_ok=True, parents=True)
if destination.exists() and path not in destination.read_text():
    raise SystemExit("Имя службы уже используется другой установкой.")
destination.write_text(content)
cmd = ["systemctl", *(["--user"] if user else [])]
subprocess.run([*cmd, "daemon-reload"], check=True)
subprocess.run([*cmd, "enable", unit], check=True)
subprocess.run([*cmd, "restart", unit], check=True)
