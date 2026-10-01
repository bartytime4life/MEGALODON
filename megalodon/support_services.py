"""Fixed, reviewable service setup. No caller supplies shell code or paths."""

_PRELUDE = r'''set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
case "${PKEXEC_UID:-}" in ''|*[!0-9]*) exit 2;; esac
[ "$PKEXEC_UID" -gt 0 ]
write_dropin() {
  directory="$1"; destination="$2"
  [ ! -L "$directory" ] && [ ! -L "$destination" ]
  [ ! -e "$destination" ] || [ -f "$destination" ]
  /usr/bin/install -d -m 755 -o root -g root "$directory"
  [ "$(/usr/bin/stat -c %u "$directory")" = 0 ]
  [ -z "$(/usr/bin/find "$directory" -maxdepth 0 -perm /022 -print)" ]
  if [ -e "$destination" ] && [ ! -e "$destination.previous" ]; then
    /usr/bin/cp -p -- "$destination" "$destination.previous"
  fi
  temporary=$(/usr/bin/mktemp "$directory/.megalodon-XXXXXXXX")
  /usr/bin/cat > "$temporary"
  /usr/bin/chmod 644 "$temporary"
  /usr/bin/mv -T -- "$temporary" "$destination"
}
'''

QWEN_LOCAL_SCRIPT = _PRELUDE + r'''
write_dropin /etc/systemd/system/ollama.service.d /etc/systemd/system/ollama.service.d/zz-megalodon-local.conf <<'CONFIG'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
CONFIG
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl restart ollama.service
/usr/bin/systemctl is-active --quiet ollama.service
'''

SURICATA_SCRIPT = _PRELUDE + r'''
case "$1" in ''|*[!a-zA-Z0-9_.:@-]*) exit 2;; esac
[ "${#1}" -le 15 ] && [ -e "/sys/class/net/$1" ]
[ -f /usr/bin/suricata ] && [ ! -L /usr/bin/suricata ]
[ "$(/usr/bin/stat -c %u /usr/bin/suricata)" = 0 ]
[ -z "$(/usr/bin/find /usr/bin/suricata -maxdepth 0 -perm /022 -print)" ]
[ -d /var/log/suricata ] && [ ! -L /var/log/suricata ]
/usr/bin/setfacl -m "u:${PKEXEC_UID}:r-x,d:u:${PKEXEC_UID}:r-x" /var/log/suricata
if [ -f /var/log/suricata/eve.json ] && [ ! -L /var/log/suricata/eve.json ]; then
  /usr/bin/setfacl -m "u:${PKEXEC_UID}:r--" /var/log/suricata/eve.json
fi
write_dropin /etc/systemd/system/suricata.service.d /etc/systemd/system/suricata.service.d/zz-megalodon-passive.conf <<CONFIG
[Service]
Group=suricata
RuntimeDirectory=suricata
RuntimeDirectoryMode=0770
PIDFile=/run/suricata/suricata.pid
ExecStart=
ExecStart=/usr/bin/suricata --af-packet=$1 --runmode single -c /etc/suricata/suricata.yaml --pidfile /run/suricata/suricata.pid --user suricata --group suricata
CONFIG
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl restart suricata.service
/usr/bin/systemctl is-active --quiet suricata.service
'''
