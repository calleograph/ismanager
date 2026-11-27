#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=https://github.com/calleograph/ismanager.git
target=/opt/ismanager
explicit_dir=0
ref=""
name="${COMPOSE_PROJECT_NAME:-ismanager}"
network_args=()
operator_only=0
no_operator=0
shared=0
while (($#)); do
  case "$1" in
    --dir) explicit_dir=1; target="$2"; shift 2;;
    --ref) ref="$2"; shift 2;;
    --name) name="$2"; shift 2;;
    --access|--port|--bind|--host|--trusted-proxy|--public-url) network_args+=("$1" "${2:?Укажите значение $1}"); shift 2;;
    --shared-host) shared=1; shift;;
    --operator) operator_only=1; shift;;
    --no-operator) no_operator=1; shift;;
    --help) echo "install.sh [--dir PATH] [--ref TAG] [--shared-host] [--name NAME] [--access http|proxy|https] [--port PORT] [--bind IPv4] [--public-url URL] [--host HOST] [--trusted-proxy IP[,IP]] [--no-operator | --operator]"; exit 0;;
    *) echo "Неизвестный параметр: $1" >&2; exit 2;;
  esac
done
here="$(cd "$(dirname "$0")" && pwd)"
(( !operator_only || !no_operator )) || { echo "Выберите --operator или --no-operator." >&2; exit 2; }
if ((operator_only)) && [[ -z "$ref" ]] && (("${#network_args[@]}" == 0)); then
  if ((!explicit_dir)) && [[ -f "$here/scripts/install_operator.py" ]]; then target="$here"; fi
  [[ -f "$target/.env" && -f "$target/scripts/install_operator.py" ]] || {
    echo "Укажите --dir существующей установки IS Manager." >&2; exit 2
  }
  cd "$target"
  exec python3 scripts/install_operator.py
fi
echo "Проверяем Git, Python, Docker Engine, Compose v2 и Buildx."
if ! command -v git >/dev/null || ! command -v python3 >/dev/null || ! docker compose version >/dev/null 2>&1 || \
   { ((!shared && EUID == 0)) && ! docker buildx version >/dev/null 2>&1; }; then
  if ((shared || EUID != 0)); then
    echo "Для этого режима нужны Git, Python 3.10+, Docker Engine и Compose v2. Проверьте docker info и docker compose version." >&2; exit 1
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
  if ! docker buildx version >/dev/null 2>&1; then
    buildx_package=docker-buildx
    if dpkg-query -s docker-ce-cli 2>/dev/null | grep -q '^Status: install ok installed$'; then buildx_package=docker-buildx-plugin; fi
    if apt-cache show "$buildx_package" >/dev/null 2>&1; then apt-get install -y "$buildx_package"; fi
  fi
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Требуется Python 3.10+"'
docker info >/dev/null
if ! docker buildx version 2>/dev/null; then
  echo "Buildx отсутствует. Для сборки будет использован прежний docker build. Чтобы включить Buildx, установите docker-buildx (Ubuntu) или docker-buildx-plugin (репозиторий Docker)." >&2
fi
echo "Проверяем каталог установки и версию IS Manager."
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
updated=0
if [[ -n "$ref" && "$(git rev-parse HEAD)" != "$(git rev-parse --verify "$ref^{commit}" 2>/dev/null || true)" ]]; then
  git fetch --tags origin main
  newest=$(git tag --merged FETCH_HEAD | grep -Ex 'v[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1)
  [[ "$ref" == "$newest" && -f .env && -d .runtime/control ]] || {
    echo "Для установки другой версии используйте новый --dir. Для возврата версии установленного приложения выполните scripts/manage.py rollback." >&2
    exit 1
  }
  # An older installed release may be unable to upgrade itself. Run the release's versioned helper against this installation.
  helper=$(mktemp .runtime/upgrade-XXXXXX.py)
  trap 'rm -f "$helper"' EXIT
  git show "$ref:scripts/manage.py" > "$helper"
  python3 "$helper" update
  rm "$helper"
  trap - EXIT
  updated=1
fi
# Old release tags keep their own installation logic and TLS-only settings.
if [[ ! -f scripts/network_config.py ]]; then
  for ((i=0; i<${#network_args[@]}; i+=2)); do
    if [[ "${network_args[i]}" == --access || "${network_args[i]}" == --trusted-proxy ]]; then
      echo "Этот релиз поддерживает только прямой HTTPS. Сначала обновите IS Manager." >&2; exit 2
    fi
  done
  legacy=(--name "$name" "${network_args[@]}")
  (( !shared )) || legacy+=(--shared-host)
  (( !operator_only )) || legacy+=(--operator)
  (( !no_operator )) || legacy+=(--no-operator)
  exec bash ./install.sh "${legacy[@]}"
fi
existing_env=1
if [[ ! -f .env ]]; then
  ((! operator_only)) || { echo "Сначала установите приложение или укажите каталог существующей установки." >&2; exit 2; }
  existing_env=0
  [[ "$name" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "Проверьте имя проекта Compose." >&2; exit 2; }
  if docker volume inspect "${name}_data" >/dev/null 2>&1 || [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$name")" ]]; then
    echo "Имя проекта или том уже заняты. Используйте другой --name либо рабочий каталог прежней установки." >&2; exit 1
  fi
  defaults=()
  [[ -z "${ACCESS_MODE:-}" ]] || defaults+=(--access "$ACCESS_MODE")
  [[ -z "${BIND_ADDRESS:-}" ]] || defaults+=(--bind "$BIND_ADDRESS")
  [[ -z "${PORT:-}" ]] || defaults+=(--port "$PORT")
  [[ -z "${PUBLIC_HOST:-}" ]] || defaults+=(--host "$PUBLIC_HOST")
  [[ -z "${PUBLIC_URL:-}" ]] || defaults+=(--public-url "$PUBLIC_URL")
  [[ -z "${TRUSTED_PROXY_IPS:-}" ]] || defaults+=(--trusted-proxy "$TRUSTED_PROXY_IPS")
  python3 -m scripts.network_config --initialize "$name" "${defaults[@]}" "${network_args[@]}"
fi
mkdir -p .runtime/control
chmod 755 .runtime/control
network_only=0
if ((existing_env && ${#network_args[@]})) && \
   [[ "$(sed -n 's/^APP_REVISION=//p' .env)" == "$(git rev-parse --short=12 HEAD)" ]] && \
   [[ -n "$(docker compose ps --status running -q web)" && -n "$(docker compose ps --status running -q worker)" && -n "$(docker compose ps --status running -q redactor)" ]]; then
  network_only=1
fi
if ((! operator_only && !network_only)); then
  echo "Сборка контейнеров, загрузка моделей и проверка готовности. При первой установке пароль admin будет выведен в терминал."
  if ((updated)); then
    docker compose exec -T web flask --app app admin-password --if-missing
  else
    python3 scripts/manage.py install
  fi
fi
if ((existing_env && ${#network_args[@]})); then
  python3 -m scripts.network_config "${network_args[@]}"
fi
if ((no_operator)); then
  if grep -q 'operator-disabled' scripts/install_operator.py; then
    python3 scripts/install_operator.py --disable
  else
    # Previous releases only implemented installation and would ignore --disable.
    touch .runtime/control/operator-disabled
    chmod 644 .runtime/control/operator-disabled
    echo "Управление через CLI · python3 scripts/manage.py check"
  fi
elif ((operator_only)) || { [[ ! -f .runtime/control/operator-disabled ]] && ((!network_only || updated)) &&
     { ((!existing_env)) || [[ -S .runtime/control/operator.sock ]]; }; }; then
  python3 scripts/install_operator.py
fi
python3 - <<'PY'
from scripts.manage import settings
from app.network import public_url
cfg = settings()
print("Открыть IS Manager · " + (cfg.get("PUBLIC_URL") or public_url(cfg.get("ACCESS_MODE", "https"), cfg["PUBLIC_HOST"], cfg["PORT"])))
print(f"Порт приложения на сервере · {cfg['BIND_ADDRESS']}:{cfg['PORT']}")
PY
