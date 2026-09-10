#!/usr/bin/env bash
# proxy-server: прокси Xray (VLESS + Reality) одной командой на свежем Ubuntu 24.04.
# Запуск от root:
#   bash <(curl -fsSL https://raw.githubusercontent.com/oggrebnev-maker/proxy-server/main/install.sh)
#
# Что делает: обновляет систему, ставит Xray, firewall, fail2ban, автообновления безопасности,
# создаёт пользователя с sudo и SSH-ключом, отдаёт данные для подключения и proxy.env для ai-starter.
# Root и вход по паролю отключаются ТОЛЬКО после того, как вы подтвердите вход новым пользователем.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ---------- настройки (можно переопределить переменными окружения) ----------
NEW_USER="${NEW_USER:-proxyadmin}"
SSH_PORT="${SSH_PORT:-22}"
XRAY_PORT="${XRAY_PORT:-443}"
REALITY_DEST="${REALITY_DEST:-www.microsoft.com}"   # сайт-маскировка для Reality
WORKDIR="/root/proxy-server"
OUT="$WORKDIR/output"
STATE="$WORKDIR/state"
XRAY_CONF="/usr/local/etc/xray/config.json"

# ---------- утилиты ----------
say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mОШИБКА: %s\033[0m\n' "$*" >&2; exit 1; }
done_step() { touch "$STATE/$1"; }
is_done()   { [ -f "$STATE/$1" ]; }

# ---------- проверки ----------
[ "$(id -u)" -eq 0 ] || die "запускайте от root"
. /etc/os-release
[ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "24.04" ] || die "поддерживается только Ubuntu 24.04 (у вас $ID $VERSION_ID)"
mkdir -p "$OUT" "$STATE"; chmod 700 "$WORKDIR" "$OUT" "$STATE"

SERVER_IP="$(curl -4fsS --max-time 10 https://api.ipify.org || curl -4fsS --max-time 10 https://ifconfig.me || true)"
[ -n "$SERVER_IP" ] || die "не удалось определить внешний IP — проверьте сеть"
ok "сервер: $SERVER_IP, Ubuntu $VERSION_ID"

# ---------- 1. система ----------
if ! is_done 01-system; then
  say "Обновление системы и установка зависимостей"
  apt-get update -q
  apt-get -y -q -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
  apt-get install -y -q curl unzip jq ufw fail2ban unattended-upgrades openssl qrencode
  done_step 01-system
fi
ok "система обновлена"

# ---------- 2. Xray ----------
if ! is_done 02-xray; then
  say "Установка Xray"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root >/dev/null
  done_step 02-xray
fi
command -v xray >/dev/null || die "xray не установился"
ok "xray $(xray version | head -1 | awk '{print $2}')"

# ---------- 3. ключи и конфиг Xray ----------
if ! is_done 03-config; then
  say "Генерация ключей и конфигурации"
  UUID="$(xray uuid)"
  KEYS="$(xray x25519)"
  PRIV="$(echo "$KEYS" | awk -F': ' '/Private/{print $2}')"
  PUB="$(echo "$KEYS"  | awk -F': ' '/Public/{print $2}')"
  SID="$(openssl rand -hex 8)"

  cat > "$XRAY_CONF" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "tag": "vless-reality",
    "listen": "0.0.0.0",
    "port": $XRAY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision", "email": "client" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$REALITY_DEST:443",
        "xver": 0,
        "serverNames": ["$REALITY_DEST"],
        "privateKey": "$PRIV",
        "shortIds": ["$SID"]
      }
    },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block",  "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [{ "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }]
  }
}
EOF
  chmod 600 "$XRAY_CONF"
  printf 'UUID=%s\nPUB=%s\nSID=%s\n' "$UUID" "$PUB" "$SID" > "$STATE/xray.vars"; chmod 600 "$STATE/xray.vars"
  xray run -test -c "$XRAY_CONF" >/dev/null || die "конфиг xray не прошёл проверку"
  done_step 03-config
fi
. "$STATE/xray.vars"
systemctl enable --now xray >/dev/null 2>&1; systemctl restart xray
sleep 1; systemctl is-active --quiet xray || die "xray не запустился: journalctl -u xray -n 30"
ok "xray работает на порту $XRAY_PORT"

# ---------- 4. пользователь и SSH-ключ ----------
if ! is_done 04-user; then
  say "Создание пользователя $NEW_USER с sudo и SSH-ключом"
  if ! id "$NEW_USER" >/dev/null 2>&1; then
    adduser --disabled-password --gecos "" "$NEW_USER" >/dev/null
  fi
  usermod -aG sudo "$NEW_USER"
  USER_PASS="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
  echo "$NEW_USER:$USER_PASS" | chpasswd
  echo "$USER_PASS" > "$STATE/user.pass"; chmod 600 "$STATE/user.pass"

  H="/home/$NEW_USER"
  install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "$H/.ssh"
  ssh-keygen -q -t ed25519 -N "" -C "$NEW_USER@$SERVER_IP" -f "$OUT/id_ed25519" <<<y >/dev/null 2>&1 || true
  install -m 600 -o "$NEW_USER" -g "$NEW_USER" "$OUT/id_ed25519.pub" "$H/.ssh/authorized_keys"
  chmod 600 "$OUT/id_ed25519"
  done_step 04-user
fi
USER_PASS="$(cat "$STATE/user.pass")"
ok "пользователь $NEW_USER создан, ключ лежит в $OUT/id_ed25519"

# ---------- 5. firewall, fail2ban, автообновления ----------
if ! is_done 05-security; then
  say "Firewall, fail2ban, автообновления безопасности"
  ufw --force reset >/dev/null
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw allow "$SSH_PORT"/tcp comment 'SSH' >/dev/null
  ufw allow "$XRAY_PORT"/tcp comment 'Xray' >/dev/null
  ufw --force enable >/dev/null

  cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 5
findtime = 10m
bantime = 1h
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1; systemctl restart fail2ban

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  done_step 05-security
fi
ok "ufw активен (порты $SSH_PORT, $XRAY_PORT), fail2ban работает"

# ---------- 6. файлы для человека и для ai-starter ----------
VLESS="vless://$UUID@$SERVER_IP:$XRAY_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_DEST&fp=chrome&pbk=$PUB&sid=$SID&type=tcp#proxy-$SERVER_IP"
echo "$VLESS" > "$OUT/vless.txt"
cat > "$OUT/proxy.env" <<EOF
# Данные прокси для ai-starter. Скопируйте этот файл в проект.
PROXY_ENABLED=true
PROXY_TYPE=xray
PROXY_HOST=$SERVER_IP
PROXY_PORT=$XRAY_PORT
PROXY_XRAY_LINK=$VLESS
EOF
cat > "$OUT/README.txt" <<EOF
ПРОКСИ-СЕРВЕР $SERVER_IP — данные для подключения
=================================================
SSH:      ssh -p $SSH_PORT -i id_ed25519 $NEW_USER@$SERVER_IP
Логин:    $NEW_USER
Пароль:   $USER_PASS   (нужен только для sudo; вход по паролю выключен)
Ключ:     id_ed25519 (приватный, храните как пароль), id_ed25519.pub (публичный)

VPN/прокси-ссылка (Hiddify, v2rayNG, Streisand, Nekoray):
$VLESS

Для ai-starter: файл proxy.env

Восстановление доступа при потере ключа: консоль хостера (VNC) под root — пароль root
хостер не менял, изменён только способ входа по SSH.
EOF
chmod 600 "$OUT"/*

say "ГОТОВО. Скопируйте и сохраните этот блок целиком"
echo "--------------------------------------------------------------------------"
cat "$OUT/README.txt"
echo
echo "ПРИВАТНЫЙ КЛЮЧ id_ed25519 (вставьте в Termius → Keychain → New key → Private key):"
cat "$OUT/id_ed25519"
echo "--------------------------------------------------------------------------"
echo "QR-код ссылки для телефона:"
qrencode -t ANSIUTF8 "$VLESS" || true
echo "Файлы также лежат в $OUT (скачать: scp -r root@$SERVER_IP:$OUT ./)"

# ---------- 7. отключение root и паролей — только после подтверждения ----------
if ! is_done 07-harden; then
  say "Последний шаг: отключение входа root и по паролю"
  echo "1. Сохраните приватный ключ в Termius, добавьте хост $SERVER_IP, порт $SSH_PORT, пользователь $NEW_USER, ключ."
  echo "2. Откройте ВТОРОЕ окно и подключитесь. Выполните там: sudo -n true || sudo true  (введите пароль $NEW_USER)."
  echo "3. Если вошли и sudo сработал — вернитесь сюда и введите слово: yes"
  echo "   Любой другой ответ оставит текущий доступ без изменений; скрипт можно запустить повторно позже."
  read -r -p "Вход новым пользователем проверен? (yes/нет): " ANSWER
  if [ "$ANSWER" = "yes" ]; then
    cat > /etc/ssh/sshd_config.d/00-proxy-server.conf <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 4
EOF
    sshd -t || { rm -f /etc/ssh/sshd_config.d/00-proxy-server.conf; die "sshd отверг конфиг, изменения отменены"; }
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    done_step 07-harden
    ok "root и вход по паролю отключены. Текущее окно продолжает работать — не закрывайте его, пока не проверите вход ещё раз."
  else
    warn "SSH не изменён. Когда будете готовы — запустите скрипт снова, он перейдёт сразу к этому шагу."
  fi
fi

echo
say "Всё. Проверить прокси с любой машины: клиент Xray с ссылкой из vless.txt."
