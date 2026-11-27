#!/bin/bash
set -euo pipefail
[[ -f /.dockerenv && "$(hostname -s)" == "dc" ]] || { echo "Только для тестового контейнера dc"; exit 1; }
rm -f /etc/samba/smb.conf
samba-tool domain provision --realm=EXAMPLE.TEST --domain=EXAMPLE --server-role=dc \
  --dns-backend=SAMBA_INTERNAL --adminpass="$(openssl rand -hex 24)Qq!" \
  --option='acl_xattr:security_acl_name = user.NTACL'
mkdir -p /var/lib/samba/private/tls
cd /var/lib/samba/private/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=Test-CA -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=dc.example.test -keyout key.pem -out server.csr 2>/dev/null
ip=$(hostname -i | cut -d' ' -f1)
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -out cert.pem \
  -extfile <(printf 'subjectAltName=DNS:dc.example.test,IP:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' "$ip") 2>/dev/null
chmod 600 key.pem
samba-tool user create service "$SERVICE_PASS"
samba-tool user create analyst "$USER_PASS"
samba-tool user create outsider "$USER_PASS"
samba-tool group add Analysts
samba-tool group add Readers
samba-tool group addmembers Analysts analyst
samba-tool group addmembers Readers Analysts
if [[ ${WATCH_SHARE:-} == 1 ]]; then
  # Dedicated test shares. Only the domain account used by the watcher can connect.
  install -d -m 0777 /srv/watch-input /srv/watch-output
  cat >> /etc/samba/smb.conf <<'CONF'
[watch-input]
    path = /srv/watch-input
    read only = no
    valid users = EXAMPLE\analyst
[watch-output]
    path = /srv/watch-output
    read only = no
    valid users = EXAMPLE\analyst
CONF
fi
exec samba --foreground --no-process-group
