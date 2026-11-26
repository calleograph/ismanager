#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=https://github.com/calleograph/ismanager.git
target=/opt/ismanager
explicit_dir=0
ref=""
name="${COMPOSE_PROJECT_NAME:-ismanager}"
port="${PORT:-18443}"
address="${BIND_ADDRESS:-127.0.0.1}"
public_host="${PUBLIC_HOST:-localhost}"
operator_only=0
no_operator=0
shared=0
while (($#)); do
  case "$1" in
    --dir) explicit_dir=1; target="$2"; shift 2;;
    --ref) ref="$2"; shift 2;;
    --name) name="$2"; shift 2;;
    --port) port="$2"; shift 2;;
    --bind) address="$2"; shift 2;;
    --host) public_host="$2"; shift 2;;
    --shared-host) shared=1; shift;;
    --operator) operator_only=1; shift;;
    --no-operator) no_operator=1; shift;;
    --help) echo "install.sh [--dir PATH] [--ref TAG] [--shared-host] [--name NAME] [--port PORT] [--bind IP] [--host DNS] [--no-operator | --operator]"; exit 0;;
    *) echo "Неизвестный параметр: $1" >&2; exit 2;;
  esac
done
here="$(cd "$(dirname "$0")" && pwd)"
if ! command -v git >/dev/null || ! command -v python3 >/dev/null || ! docker compose version >/dev/null 2>&1; then
  if ((shared || EUID != 0)); then
    echo "Для этого режима нужны Git, Python 3.10+, Docker Engine и Docker Compose v2." >&2; exit 1
  fi
  source /etc/os-release
  [[ "$ID" == ubuntu ]] || { echo "Автоматическая установка пакетов предусмотрена на Ubuntu."; exit 1; }
  apt-get -qq update
  apt-get install -y git python3 ca-certificates
  if ! command -v docker >/dev/null; then apt-get install -y docker.io; fi
  if ! docker compose version >/dev/null 2>&1; then
    if apt-cache show docker-compose-v2 >/dev/null 2>&1; then apt-get install -y docker-compose-v2
    else apt-get install -y docker-compose-plugin; fi
  fi
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Требуется Python 3.10+"'
docker info >/dev/null
if { ((! explicit_dir)) || [[ "$(realpath -m "$target")" == "$here" ]]; } && [[ -f "$here/scripts/manage.py" && -f "$here/compose.yaml" ]] && git -C "$here" rev-parse --git-dir >/dev/null 2>&1; then
  cd "$here"
else
  if [[ ! -e "$target" ]] || [[ -d "$target" && -z "$(ls -A "$target")" ]]; then
    (umask 022; git clone "$repo" "$target")
    if [[ -z "$ref" ]]; then ref=$(git -C "$target" tag --list | grep -Ex 'v[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1); fi
    git -C "$target" switch --detach "${ref:?Не найден релиз}"
  else
    [[ "$(git -C "$target" remote get-url origin)" == "$repo" && -f "$target/scripts/manage.py" ]] || { echo "Каталог уже занят."; exit 1; }
    # A failed first bootstrap may have a checkout and a key but no deployment data yet.
    volume=$(sed -n 's/^DATA_VOLUME=//p' "$target/.env" 2>/dev/null || true)
    if [[ -z "$volume" ]] || ! docker volume inspect "$volume" >/dev/null 2>&1; then
      [[ -z "$(git -C "$target" status --porcelain --untracked-files=no)" ]] || { echo "Сохраните изменения рабочей копии."; exit 1; }
      git -C "$target" fetch --tags origin main
      if [[ -z "$ref" ]]; then ref=$(git -C "$target" tag --merged FETCH_HEAD | grep -Ex 'v[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1); fi
      (umask 022; git -C "$target" switch --detach "${ref:?Не найден релиз}")
    fi
  fi
  cd "$target"
fi
if [[ -n "$ref" && "$(git rev-parse HEAD)" != "$(git rev-parse --verify "$ref^{commit}")" ]]; then
  echo "Текущая копия отличается от --ref. Для смены версии выполните scripts/manage.py update или используйте новый --dir." >&2; exit 1
fi
if [[ ! -f .env ]]; then
  [[ "$name" =~ ^[a-z0-9][a-z0-9_-]*$ && "$port" =~ ^[0-9]{1,5}$ && "$public_host" =~ ^[a-zA-Z0-9.-]+$ ]] || { echo "Проверьте имя, порт и DNS."; exit 2; }
  python3 - "$address" "$port" <<'PY'
import ipaddress, socket, sys, shutil
ipaddress.IPv4Address(sys.argv[1])
assert 1 <= int(sys.argv[2]) <= 65535, "Недопустимый порт"
with socket.socket() as sock:
    sock.bind((sys.argv[1], int(sys.argv[2])))
print(f"Свободно на разделе установки: {shutil.disk_usage('.').free // 2**30} ГиБ.")
PY
  if docker volume inspect "${name}_data" >/dev/null 2>&1 || [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$name")" ]]; then
    echo "Имя проекта или том уже заняты. Используйте другой --name либо рабочий каталог прежней установки." >&2; exit 1
  fi
  tmp=$(mktemp ./.env.XXXXXX)
  trap 'rm -f "$tmp"' EXIT
  cat >"$tmp" <<EOF
COMPOSE_PROJECT_NAME=$name
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
PORT=$port
BIND_ADDRESS=$address
PUBLIC_HOST=$public_host
DATA_VOLUME=${name}_data
ASR_DEVICE=cpu
EOF
  ln "$tmp" .env
  rm "$tmp"
  trap - EXIT
fi
mkdir -p .runtime/control
chmod 755 .runtime/control
if ((! operator_only)); then
  echo "Сборка контейнеров, загрузка моделей и проверка готовности. При первой установке пароль admin будет выведен в терминал."
  python3 scripts/manage.py install
fi
if ((! no_operator)); then
  python3 scripts/install_operator.py
fi
python3 - <<'PY'
from scripts.manage import settings
cfg=settings()
print(f"IS Manager · https://{cfg['PUBLIC_HOST']}:{cfg['PORT']}/")
PY
