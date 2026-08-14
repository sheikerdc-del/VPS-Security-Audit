#!/usr/bin/env bash

# ============================================================
# VPS SECURITY AUDIT
# Read-only security audit for Linux VPS
#
# Supported:
#   Ubuntu / Debian
#
# DOES NOT:
#   - install packages
#   - delete files
#   - modify configuration
#   - restart services
#   - kill processes
#   - change firewall
#
# Usage:
#   sudo bash vps-audit.sh
#
# Optional:
#   sudo bash vps-audit.sh | tee vps-audit-$(date +%F-%H%M).log
# ============================================================

set +e

export LC_ALL=C

SCRIPT_VERSION="1.0"
START_TIME="$(date '+%Y-%m-%d %H:%M:%S')"

# ------------------------------------------------------------
# COLORS
# ------------------------------------------------------------

if [ -t 1 ]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    GRAY='\033[0;90m'
    RESET='\033[0m'
else
    RED=''
    YELLOW=''
    GREEN=''
    BLUE=''
    CYAN=''
    WHITE=''
    GRAY=''
    RESET=''
fi

# ------------------------------------------------------------
# COUNTERS
# ------------------------------------------------------------

OK_COUNT=0
WARNING_COUNT=0
CRITICAL_COUNT=0

section() {
    echo
    echo "================================================================"
    echo " $1"
    echo "================================================================"
}

ok() {
    OK_COUNT=$((OK_COUNT + 1))
    echo -e "${GREEN}[OK]${RESET} $1"
}

warn() {
    WARNING_COUNT=$((WARNING_COUNT + 1))
    echo -e "${YELLOW}[WARNING]${RESET} $1"
}

critical() {
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    echo -e "${RED}[CRITICAL]${RESET} $1"
}

info() {
    echo -e "${CYAN}[INFO]${RESET} $1"
}

detail() {
    echo "       $1"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------
# ROOT CHECK
# ------------------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo
    echo -e "${YELLOW}WARNING:${RESET} запуск не от root."
    echo "Некоторые проверки будут неполными."
    echo
    echo "Рекомендуется:"
    echo "sudo bash $0"
    echo
fi

# ------------------------------------------------------------
# HEADER
# ------------------------------------------------------------

clear 2>/dev/null

echo
echo -e "${WHITE}==============================================================${RESET}"
echo -e "${WHITE}                 VPS SECURITY AUDIT                          ${RESET}"
echo -e "${WHITE}==============================================================${RESET}"
echo
echo "Version : $SCRIPT_VERSION"
echo "Started : $START_TIME"
echo "Host    : $(hostname 2>/dev/null)"
echo "Kernel  : $(uname -r 2>/dev/null)"
echo "OS      : $(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo unknown)"
echo "Uptime  : $(uptime -p 2>/dev/null || uptime)"
echo

# ============================================================
# 1. SYSTEM
# ============================================================

section "1. SYSTEM"

info "Hostname: $(hostname 2>/dev/null)"
info "Kernel: $(uname -a 2>/dev/null)"

if [ -r /etc/os-release ]; then
    . /etc/os-release
    info "OS: ${PRETTY_NAME:-unknown}"
fi

if command_exists systemd-detect-virt; then
    info "Virtualization: $(systemd-detect-virt 2>/dev/null)"
fi

echo

info "CPU:"
nproc 2>/dev/null
echo

info "Memory:"
free -h 2>/dev/null

echo
info "Disk:"
df -hT 2>/dev/null | head -20

# ============================================================
# 2. CURRENT USERS / SESSIONS
# ============================================================

section "2. CURRENT SESSIONS"

WHO_OUTPUT="$(who 2>/dev/null)"

if [ -n "$WHO_OUTPUT" ]; then
    echo "$WHO_OUTPUT"
else
    ok "Нет активных интерактивных пользовательских сессий."
fi

echo

info "w:"
w 2>/dev/null | head -20

# ============================================================
# 3. LOGIN HISTORY
# ============================================================

section "3. LOGIN HISTORY"

if command_exists last; then
    LAST_OUTPUT="$(last -a 2>/dev/null | head -50)"
    echo "$LAST_OUTPUT"

    UNKNOWN_ROOT_LOGINS="$(echo "$LAST_OUTPUT" | grep -E 'root.*([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)"

    if [ "$UNKNOWN_ROOT_LOGINS" -gt 0 ]; then
        warn "Обнаружены записи входов root. Проверьте IP вручную."
    else
        ok "Подозрительных записей root в последних 50 событиях не обнаружено."
    fi
else
    warn "Команда last недоступна."
fi

# ============================================================
# 4. SSH LOG
# ============================================================

section "4. SSH SECURITY"

SSH_SERVICE=""

if systemctl is-active --quiet ssh 2>/dev/null; then
    SSH_SERVICE="ssh"
elif systemctl is-active --quiet sshd 2>/dev/null; then
    SSH_SERVICE="sshd"
fi

if [ -n "$SSH_SERVICE" ]; then
    ok "SSH service работает: $SSH_SERVICE"
else
    info "SSH service не определён через systemd."
fi

echo
info "SSH listening ports:"
ss -lntp 2>/dev/null | grep -Ei '(:22|sshd|ssh)' || true

echo
info "Последние SSH authentication events:"

if [ -f /var/log/auth.log ]; then

    ACCEPTED="$(grep -Ei 'sshd.*Accepted' /var/log/auth.log 2>/dev/null | tail -30)"
    FAILED="$(grep -Ei 'sshd.*Failed|sshd.*Invalid user' /var/log/auth.log 2>/dev/null | tail -30)"

    if [ -n "$ACCEPTED" ]; then
        echo
        echo "--- ACCEPTED ---"
        echo "$ACCEPTED"
    fi

    if [ -n "$FAILED" ]; then
        echo
        echo "--- FAILED / INVALID ---"
        echo "$FAILED"
    fi

    FAILED_COUNT="$(grep -Eic 'sshd.*Failed|sshd.*Invalid user' /var/log/auth.log 2>/dev/null)"

    if [ "$FAILED_COUNT" -gt 100 ]; then
        critical "Обнаружено $FAILED_COUNT неудачных SSH-попыток в auth.log."
    elif [ "$FAILED_COUNT" -gt 20 ]; then
        warn "Обнаружено $FAILED_COUNT неудачных SSH-попыток."
    else
        ok "Количество неудачных SSH-попыток: $FAILED_COUNT"
    fi

else

    JOURNAL_SSH="$(journalctl -u ssh --since '7 days ago' 2>/dev/null)"

    if [ -z "$JOURNAL_SSH" ]; then
        JOURNAL_SSH="$(journalctl -u sshd --since '7 days ago' 2>/dev/null)"
    fi

    if [ -n "$JOURNAL_SSH" ]; then
        echo "$JOURNAL_SSH" | grep -Ei 'accepted|failed|invalid' | tail -50

        FAILED_COUNT="$(echo "$JOURNAL_SSH" | grep -Eic 'failed|invalid user')"

        if [ "$FAILED_COUNT" -gt 100 ]; then
            critical "Обнаружено много SSH authentication failures: $FAILED_COUNT"
        elif [ "$FAILED_COUNT" -gt 20 ]; then
            warn "SSH authentication failures: $FAILED_COUNT"
        else
            ok "SSH authentication failures: $FAILED_COUNT"
        fi
    else
        warn "Не удалось получить SSH authentication logs."
    fi

fi

# ============================================================
# 5. SSH CONFIGURATION
# ============================================================

section "5. SSH CONFIGURATION"

SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then

    ROOT_LOGIN="$(grep -Ei '^[[:space:]]*PermitRootLogin' "$SSHD_CONFIG" | tail -1)"
    PASSWORD_AUTH="$(grep -Ei '^[[:space:]]*PasswordAuthentication' "$SSHD_CONFIG" | tail -1)"
    PUBKEY_AUTH="$(grep -Ei '^[[:space:]]*PubkeyAuthentication' "$SSHD_CONFIG" | tail -1)"

    echo "PermitRootLogin       : ${ROOT_LOGIN:-default}"
    echo "PasswordAuthentication: ${PASSWORD_AUTH:-default}"
    echo "PubkeyAuthentication  : ${PUBKEY_AUTH:-default}"

    if echo "$ROOT_LOGIN" | grep -qiE 'yes'; then
        critical "PermitRootLogin yes."
    else
        ok "Прямой root SSH login не разрешён явно."
    fi

    if echo "$PASSWORD_AUTH" | grep -qiE 'yes'; then
        warn "PasswordAuthentication yes."
    else
        ok "Password authentication не включён явно."
    fi

else
    warn "Не найден /etc/ssh/sshd_config."
fi

# ============================================================
# 6. USERS
# ============================================================

section "6. USER ACCOUNTS"

echo
info "Users with login shells:"

awk -F: '$7 ~ /(bash|sh|zsh|fish)$/ {printf "%-20s %-30s %s\n",$1,$6,$7}' /etc/passwd 2>/dev/null

echo
info "UID 0 accounts:"

UID0="$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)"

echo "$UID0"

UID0_COUNT="$(echo "$UID0" | grep -c .)"

if [ "$UID0_COUNT" -gt 1 ]; then
    critical "Обнаружено несколько UID 0 пользователей."
else
    ok "UID 0 пользователь только один: root."
fi

echo
info "Users with sudo/admin privileges:"

if getent group sudo >/dev/null 2>&1; then
    getent group sudo
fi

if getent group wheel >/dev/null 2>&1; then
    getent group wheel
fi

# ============================================================
# 7. SSH AUTHORIZED KEYS
# ============================================================

section "7. SSH AUTHORIZED KEYS"

KEY_FILES="$(find /root /home -type f -name authorized_keys 2>/dev/null)"

if [ -z "$KEY_FILES" ]; then
    ok "authorized_keys не обнаружены."
else

    while IFS= read -r keyfile; do

        echo
        echo "===== $keyfile ====="

        KEY_COUNT="$(grep -vE '^[[:space:]]*(#|$)' "$keyfile" 2>/dev/null | wc -l)"

        echo "Keys: $KEY_COUNT"

        grep -vE '^[[:space:]]*(#|$)' "$keyfile" 2>/dev/null

        if [ "$keyfile" = "/root/.ssh/authorized_keys" ] && [ "$KEY_COUNT" -gt 0 ]; then
            warn "У root есть SSH authorized_keys. Убедитесь, что все ключи ваши."
        fi

    done <<< "$KEY_FILES"

fi

# ============================================================
# 8. NETWORK LISTENING PORTS
# ============================================================

section "8. LISTENING PORTS"

echo
ss -lntup 2>/dev/null

echo

LISTEN_COUNT="$(ss -lntup 2>/dev/null | tail -n +2 | wc -l)"

info "Listening sockets: $LISTEN_COUNT"

# ============================================================
# 9. ESTABLISHED CONNECTIONS
# ============================================================

section "9. ACTIVE NETWORK CONNECTIONS"

ESTABLISHED="$(ss -tunap 2>/dev/null | grep ESTAB)"

if [ -n "$ESTABLISHED" ]; then
    echo "$ESTABLISHED"
else
    ok "Активных TCP ESTABLISHED соединений не обнаружено."
fi

# ============================================================
# 10. PROCESSES
# ============================================================

section "10. RUNNING PROCESSES"

echo
info "Top CPU processes:"
ps aux --sort=-%cpu 2>/dev/null | head -16

echo
info "Top RAM processes:"
ps aux --sort=-%mem 2>/dev/null | head -16

echo
info "Process tree:"
if command_exists pstree; then
    pstree -ap 2>/dev/null | head -100
else
    warn "pstree не установлен."
fi

# ============================================================
# 11. SUSPICIOUS PROCESS LOCATIONS
# ============================================================

section "11. PROCESSES FROM TEMPORARY DIRECTORIES"

FOUND_TEMP_PROCESS=0

for PID in /proc/[0-9]*; do

    PID="${PID##*/}"

    [ -r "/proc/$PID/exe" ] || continue

    EXE="$(readlink -f "/proc/$PID/exe" 2>/dev/null)"

    case "$EXE" in

        /tmp/*|/var/tmp/*|/dev/shm/*)
            echo "PID $PID -> $EXE"
            ps -p "$PID" -o pid,ppid,user,%cpu,%mem,lstart,cmd 2>/dev/null
            FOUND_TEMP_PROCESS=1
            ;;

    esac

done

if [ "$FOUND_TEMP_PROCESS" -eq 1 ]; then
    critical "Обнаружен работающий executable из /tmp, /var/tmp или /dev/shm."
else
    ok "Работающих процессов из временных каталогов не обнаружено."
fi

# ============================================================
# 12. CPU LOAD
# ============================================================

section "12. CPU LOAD"

LOAD1="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
CPU_COUNT="$(nproc 2>/dev/null || echo 1)"

info "Load average: $LOAD1"
info "CPU cores: $CPU_COUNT"

LOAD_INT="$(printf "%.0f" "$LOAD1" 2>/dev/null)"

if [ "$LOAD_INT" -ge $((CPU_COUNT * 2)) ]; then
    warn "Высокая нагрузка CPU."
else
    ok "Load average находится в нормальном диапазоне."
fi

# ============================================================
# 13. CRON
# ============================================================

section "13. CRON PERSISTENCE"

CRON_FOUND=0

echo
info "System cron directories:"

for DIR in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do

    if [ -d "$DIR" ]; then

        FILES="$(find "$DIR" -maxdepth 1 -type f -printf '%p\n' 2>/dev/null)"

        if [ -n "$FILES" ]; then
            echo
            echo "===== $DIR ====="
            echo "$FILES"
        fi

    fi

done

echo
info "User crontabs:"

for USERNAME in $(cut -d: -f1 /etc/passwd 2>/dev/null); do

    CRON="$(crontab -u "$USERNAME" -l 2>/dev/null)"

    if [ -n "$CRON" ]; then

        echo
        echo "===== $USERNAME ====="
        echo "$CRON"

        if echo "$CRON" | grep -Eq '/tmp|/var/tmp|/dev/shm|curl|wget|base64|bash -c|python|perl|nc '; then
            CRON_FOUND=1
        fi

    fi

done

if [ "$CRON_FOUND" -eq 1 ]; then
    critical "В cron обнаружены потенциально подозрительные команды."
else
    ok "Явно подозрительных cron-команд не обнаружено."
fi

# ============================================================
# 14. SYSTEMD SERVICES
# ============================================================

section "14. SYSTEMD SERVICES"

if command_exists systemctl; then

    echo
    info "Enabled services:"
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null

    echo
    info "Running services:"
    systemctl --type=service --state=running 2>/dev/null

    echo
    info "Recently modified systemd unit files:"

    find /etc/systemd/system /lib/systemd/system \
        -type f -mtime -14 -ls 2>/dev/null | head -100

else
    warn "systemctl недоступен."
fi

# ============================================================
# 15. SUID / SGID
# ============================================================

section "15. SUID / SGID FILES"

SUID_LIST="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)"

echo "$SUID_LIST"

SUID_COUNT="$(echo "$SUID_LIST" | grep -c .)"

info "SUID/SGID files found: $SUID_COUNT"

if echo "$SUID_LIST" | grep -Eq '/tmp/|/var/tmp/|/dev/shm/'; then
    critical "SUID/SGID executable найден во временном каталоге."
else
    ok "SUID/SGID файлов во временных каталогах не обнаружено."
fi

# ============================================================
# 16. LD_PRELOAD
# ============================================================

section "16. LD_PRELOAD"

if [ -f /etc/ld.so.preload ]; then

    echo "/etc/ld.so.preload:"
    cat /etc/ld.so.preload 2>/dev/null

    if [ -s /etc/ld.so.preload ]; then
        critical "/etc/ld.so.preload существует и содержит данные."
    else
        ok "/etc/ld.so.preload пуст."
    fi

else
    ok "/etc/ld.so.preload отсутствует."
fi

# ============================================================
# 17. KERNEL MODULES
# ============================================================

section "17. KERNEL MODULES"

if command_exists lsmod; then
    lsmod 2>/dev/null | head -100
else
    warn "lsmod недоступен."
fi

# ============================================================
# 18. FIREWALL
# ============================================================

section "18. FIREWALL"

FIREWALL_FOUND=0

if command_exists ufw; then

    echo
    echo "--- UFW ---"
    ufw status verbose 2>/dev/null

    if ufw status 2>/dev/null | grep -qi "active"; then
        FIREWALL_FOUND=1
        ok "UFW активен."
    else
        warn "UFW не активен."
    fi

fi

if command_exists nft; then

    echo
    echo "--- NFTABLES ---"
    nft list ruleset 2>/dev/null | head -200

fi

if command_exists iptables; then

    echo
    echo "--- IPTABLES ---"
    iptables -S 2>/dev/null | head -200
fi

if [ "$FIREWALL_FOUND" -eq 0 ]; then
    info "Не удалось подтвердить активный UFW."
fi

# ============================================================
# 19. DOCKER
# ============================================================

section "19. DOCKER SECURITY"

if command_exists docker; then

    echo
    info "Docker version:"
    docker version --format '{{.Server.Version}}' 2>/dev/null

    echo
    info "Containers:"
    docker ps -a 2>/dev/null

    echo
    info "Images:"
    docker images 2>/dev/null

    echo
    info "Docker networks:"
    docker network ls 2>/dev/null

    echo
    info "Docker socket:"
    ls -la /var/run/docker.sock 2>/dev/null

    if [ -S /var/run/docker.sock ]; then
        SOCKET_PERM="$(stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null)"
        info "docker.sock: $SOCKET_PERM"
    fi

    PRIVILEGED="$(docker ps -q 2>/dev/null | while read ID; do docker inspect "$ID" --format '{{.Name}} privileged={{.HostConfig.Privileged}}' 2>/dev/null; done)"

    if [ -n "$PRIVILEGED" ]; then
        echo
        echo "$PRIVILEGED"

        if echo "$PRIVILEGED" | grep -q 'privileged=true'; then
            warn "Обнаружен privileged Docker container."
        fi
    fi

else
    ok "Docker не установлен."
fi

# ============================================================
# 20. RECENT FILE CHANGES
# ============================================================

section "20. RECENT SYSTEM FILE CHANGES"

info "Files changed during last 7 days in important directories:"

for DIR in /etc /usr/local/bin /opt /root; do

    if [ -d "$DIR" ]; then

        echo
        echo "===== $DIR ====="

        find "$DIR" -xdev -type f -mtime -7 \
            -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' \
            2>/dev/null | sort -r | head -50

    fi

done

# ============================================================
# 21. TEMPORARY DIRECTORIES
# ============================================================

section "21. TEMPORARY DIRECTORIES"

for DIR in /tmp /var/tmp /dev/shm; do

    if [ -d "$DIR" ]; then

        echo
        echo "===== $DIR ====="

        find "$DIR" -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' \
            2>/dev/null | sort -r | head -100

    fi

done

# ============================================================
# 22. SHELL PROFILES
# ============================================================

section "22. SHELL PROFILE CHECK"

PROFILE_FILES="
/root/.bashrc
/root/.profile
/root/.bash_profile
/etc/profile
/etc/bash.bashrc
"

for FILE in $PROFILE_FILES; do

    if [ -f "$FILE" ]; then

        echo
        echo "===== $FILE ====="

        grep -nEi \
            'curl|wget|base64|nc |netcat|/tmp/|/dev/shm|/var/tmp|python -c|perl -e|bash -c|eval ' \
            "$FILE" 2>/dev/null || true

    fi

done

# ============================================================
# 23. HOSTS FILE
# ============================================================

section "23. /etc/hosts"

cat /etc/hosts 2>/dev/null

if grep -Eq '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*(google|github|microsoft|amazon|cloudflare)' /etc/hosts 2>/dev/null; then
    warn "В /etc/hosts обнаружены нестандартные hostname mappings."
else
    ok "/etc/hosts не содержит очевидных подозрительных mappings."
fi

# ============================================================
# 24. DNS
# ============================================================

section "24. DNS CONFIGURATION"

if [ -f /etc/resolv.conf ]; then
    cat /etc/resolv.conf
fi

if command_exists resolvectl; then
    echo
    resolvectl status 2>/dev/null | head -100
fi

# ============================================================
# 25. SUDOERS
# ============================================================

section "25. SUDO CONFIGURATION"

echo
echo "--- /etc/sudoers ---"

grep -vE '^[[:space:]]*(#|$)' /etc/sudoers 2>/dev/null | head -100

echo
echo "--- /etc/sudoers.d ---"

if [ -d /etc/sudoers.d ]; then
    for FILE in /etc/sudoers.d/*; do

        [ -f "$FILE" ] || continue

        echo
        echo "===== $FILE ====="
        grep -vE '^[[:space:]]*(#|$)' "$FILE" 2>/dev/null

    done
fi

# ============================================================
# 26. WORLD-WRITABLE FILES
# ============================================================

section "26. WORLD-WRITABLE FILES"

WORLD_WRITABLE="$(find /etc /usr/local /opt /var -xdev -type f -perm -0002 2>/dev/null | head -100)"

if [ -n "$WORLD_WRITABLE" ]; then

    echo "$WORLD_WRITABLE"

    WORLD_COUNT="$(echo "$WORLD_WRITABLE" | wc -l)"

    warn "Найдено world-writable файлов: $WORLD_COUNT"

else

    ok "World-writable файлов в проверяемых системных каталогах не обнаружено."

fi

# ============================================================
# 27. CRYPTO MINER INDICATORS
# ============================================================

section "27. CRYPTO MINER INDICATORS"

MINER_PROCESS=0

MINER_PATTERNS="
xmrig
minerd
cpuminer
cgminer
bfgminer
ethminer
lolminer
nbminer
t-rex
phoenixminer
teamredminer
"

for PATTERN in $MINER_PATTERNS; do

    MATCH="$(ps aux 2>/dev/null | grep -Ei "$PATTERN" | grep -v grep)"

    if [ -n "$MATCH" ]; then

        echo "$MATCH"
        MINER_PROCESS=1

    fi

done

if [ "$MINER_PROCESS" -eq 1 ]; then
    critical "Обнаружены процессы с именами, характерными для crypto miners."
else
    ok "Явных crypto-miner процессов не обнаружено."
fi

# ============================================================
# 28. SUSPICIOUS NETWORK TOOLS
# ============================================================

section "28. SUSPICIOUS NETWORK TOOL PROCESSES"

NETWORK_SUSPICIOUS="$(ps aux 2>/dev/null | grep -Ei \
'nc |ncat |socat |chisel|frp |frpc|frps|ngrok|plink|proxychains|torsocks' \
| grep -v grep)"

if [ -n "$NETWORK_SUSPICIOUS" ]; then

    echo "$NETWORK_SUSPICIOUS"

    warn "Обнаружены процессы, которые могут использоваться для tunneling/proxy/reverse shell."

else

    ok "Подозрительных tunneling/proxy процессов не обнаружено."

fi

# ============================================================
# 29. REVERSE SHELL INDICATORS
# ============================================================

section "29. REVERSE SHELL INDICATORS"

REVERSE_SHELLS="$(ps aux 2>/dev/null | grep -Ei \
'bash -i|sh -i|/dev/tcp/|nc -e|ncat -e|socat.*exec|python.*socket|perl.*socket' \
| grep -v grep)"

if [ -n "$REVERSE_SHELLS" ]; then

    echo "$REVERSE_SHELLS"

    critical "Обнаружены процессы с признаками reverse shell."

else

    ok "Очевидных reverse-shell процессов не обнаружено."

fi

# ============================================================
# 30. OPEN FILES / NETWORK
# ============================================================

section "30. PROCESSES WITH NETWORK SOCKETS"

if command_exists lsof; then

    lsof -nP -i 2>/dev/null | head -200

else

    info "lsof не установлен — используем ss."
    ss -tunap 2>/dev/null

fi

# ============================================================
# 31. KERNEL / MODULE WARNINGS
# ============================================================

section "31. KERNEL WARNINGS"

if command_exists journalctl; then

    KERNEL_ERRORS="$(journalctl -k -p warning..alert --since '7 days ago' 2>/dev/null | tail -100)"

    if [ -n "$KERNEL_ERRORS" ]; then
        echo "$KERNEL_ERRORS"
    else
        ok "Критических kernel warnings за 7 дней не найдено."
    fi

fi

# ============================================================
# 32. SYSTEM ERRORS
# ============================================================

section "32. SYSTEM ERRORS"

if command_exists journalctl; then

    SYSTEM_ERRORS="$(journalctl -p err..alert --since '7 days ago' 2>/dev/null | tail -100)"

    if [ -n "$SYSTEM_ERRORS" ]; then
        echo "$SYSTEM_ERRORS"
        warn "Обнаружены системные ошибки в journal."
    else
        ok "Ошибок уровня err/alert за последние 7 дней не найдено."
    fi

fi

# ============================================================
# 33. FAILED SERVICES
# ============================================================

section "33. FAILED SYSTEMD SERVICES"

if command_exists systemctl; then

    FAILED_SERVICES="$(systemctl --failed --no-legend 2>/dev/null)"

    if [ -n "$FAILED_SERVICES" ]; then

        echo "$FAILED_SERVICES"

        warn "Обнаружены failed systemd services."

    else

        ok "Failed systemd services не обнаружены."

    fi

fi

# ============================================================
# 34. LOGIN FAILURES BY IP
# ============================================================

section "34. SSH FAILED LOGIN IPs"

if [ -f /var/log/auth.log ]; then

    echo
    grep -Ei 'Failed password|Invalid user' /var/log/auth.log 2>/dev/null \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort | uniq -c | sort -nr | head -30

else

    JOURNAL_IPS="$(journalctl --since '7 days ago' 2>/dev/null \
        | grep -Ei 'Failed password|Invalid user' \
        | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort | uniq -c | sort -nr | head -30)"

    echo "$JOURNAL_IPS"

fi

# ============================================================
# 35. ROOT LOGIN ATTEMPTS
# ============================================================

section "35. ROOT LOGIN ATTEMPTS"

ROOT_ATTEMPTS=0

if [ -f /var/log/auth.log ]; then

    ROOT_ATTEMPTS="$(grep -Ei 'sshd.*(Failed|Accepted).*root' /var/log/auth.log 2>/dev/null | wc -l)"

else

    ROOT_ATTEMPTS="$(journalctl --since '30 days ago' 2>/dev/null \
        | grep -Ei 'sshd.*(Failed|Accepted).*root' \
        | wc -l)"

fi

info "Root SSH attempts found: $ROOT_ATTEMPTS"

if [ "$ROOT_ATTEMPTS" -gt 50 ]; then
    warn "Много попыток SSH-доступа к root."
else
    ok "Количество root SSH попыток не выглядит аномальным."
fi

# ============================================================
# 36. FILESYSTEM CHECKS
# ============================================================

section "36. FILESYSTEM / MOUNTS"

mount | head -100 2>/dev/null

echo
info "Mounted filesystems:"
findmnt 2>/dev/null | head -100

# ============================================================
# 37. /DEV/SHM
# ============================================================

section "37. /DEV/SHM EXECUTABLES"

SHM_EXEC="$(find /dev/shm -type f -perm /111 -ls 2>/dev/null)"

if [ -n "$SHM_EXEC" ]; then

    echo "$SHM_EXEC"

    critical "Исполняемые файлы обнаружены в /dev/shm."

else

    ok "Исполняемых файлов в /dev/shm не обнаружено."

fi

# ============================================================
# 38. RECENT ROOT FILES
# ============================================================

section "38. RECENT ROOT FILES"

if [ -d /root ]; then

    find /root -maxdepth 3 -type f -mtime -7 \
        -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' \
        2>/dev/null | sort -r | head -100

fi

# ============================================================
# 39. BASH HISTORY
# ============================================================

section "39. COMMAND HISTORY"

for HISTORY_FILE in /root/.bash_history /root/.zsh_history; do

    if [ -f "$HISTORY_FILE" ]; then

        echo
        echo "===== $HISTORY_FILE ====="

        tail -100 "$HISTORY_FILE" 2>/dev/null

    fi

done

# ============================================================
# 40. SECURITY TOOLS
# ============================================================

section "40. SECURITY TOOLS"

if command_exists fail2ban-client; then

    echo "--- Fail2ban ---"

    fail2ban-client status 2>/dev/null

    ok "Fail2ban установлен."

else

    warn "Fail2ban не установлен."

fi

if command_exists auditctl; then

    echo
    echo "--- auditd ---"

    auditctl -s 2>/dev/null

    ok "auditd/auditctl доступен."

else

    info "auditd не обнаружен."

fi

# ============================================================
# 41. ROOTKIT TOOLS IF ALREADY INSTALLED
# ============================================================

section "41. ROOTKIT DETECTION TOOLS"

if command_exists rkhunter; then

    info "rkhunter найден. Запускается только read-only проверка:"
    rkhunter --check --sk 2>/dev/null

else

    info "rkhunter не установлен. Ничего не устанавливаем."
fi

if command_exists chkrootkit; then

    echo
    info "chkrootkit найден:"
    chkrootkit 2>/dev/null

else

    info "chkrootkit не установлен. Ничего не устанавливаем."
fi

# ============================================================
# 42. PACKAGE MANAGER RECENT CHANGES
# ============================================================

section "42. PACKAGE MANAGER ACTIVITY"

if [ -d /var/log/apt ]; then

    echo "--- APT history ---"

    for FILE in /var/log/apt/history.log /var/log/apt/history.log.*; do

        if [ -f "$FILE" ]; then
            echo
            echo "===== $FILE ====="
            tail -100 "$FILE" 2>/dev/null
        fi

    done

fi

# ============================================================
# 43. NETWORK INTERFACES
# ============================================================

section "43. NETWORK INTERFACES"

ip addr 2>/dev/null

echo
info "Routes:"
ip route 2>/dev/null

# ============================================================
# 44. FINAL SUMMARY
# ============================================================

END_TIME="$(date '+%Y-%m-%d %H:%M:%S')"

echo
echo
echo -e "${WHITE}==============================================================${RESET}"
echo -e "${WHITE}                    AUDIT SUMMARY                            ${RESET}"
echo -e "${WHITE}==============================================================${RESET}"
echo

echo -e "${GREEN}OK        : $OK_COUNT${RESET}"
echo -e "${YELLOW}WARNING   : $WARNING_COUNT${RESET}"
echo -e "${RED}CRITICAL  : $CRITICAL_COUNT${RESET}"

echo
echo "Started : $START_TIME"
echo "Finished: $END_TIME"
echo

if [ "$CRITICAL_COUNT" -gt 0 ]; then

    echo -e "${RED}==============================================================${RESET}"
    echo -e "${RED} CRITICAL: обнаружены признаки, требующие немедленной проверки ${RESET}"
    echo -e "${RED}==============================================================${RESET}"
    echo
    echo "НЕ удаляйте подозрительные файлы автоматически."
    echo "НЕ перезагружайте VPS до анализа."
    echo "НЕ устанавливайте случайные rootkit-cleaner инструменты."
    echo

elif [ "$WARNING_COUNT" -gt 0 ]; then

    echo -e "${YELLOW}==============================================================${RESET}"
    echo -e "${YELLOW} WARNING: найдены элементы, требующие ручной проверки         ${RESET}"
    echo -e "${YELLOW}==============================================================${RESET}"
    echo

else

    echo -e "${GREEN}==============================================================${RESET}"
    echo -e "${GREEN} OK: явных признаков компрометации не обнаружено              ${RESET}"
    echo -e "${GREEN}==============================================================${RESET}"
    echo

fi

echo
echo "ВАЖНО:"
echo "Этот скрипт не может гарантировать отсутствие взлома."
echo "Если злоумышленник получил root и установил rootkit,"
echo "часть системных инструментов может показывать ложную картину."
echo
echo "Для полноценной forensic-проверки необходимо анализировать"
echo "диск/снапшот с доверенной внешней системы."
echo
echo "=============================================================="
echo
