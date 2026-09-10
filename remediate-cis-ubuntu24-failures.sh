#!/usr/bin/env bash
# Remediate non-reboot failures from 01-checks-3-.csv (CIS Ubuntu 24.04).
# Default mode is a read-only preview. Review output before using --apply.
set -Eeuo pipefail

APPLY=0
ENABLE_PAM_HARDENING=0
ENABLE_APPARMOR=0
REMOVE_UNUSED_PACKAGES=0
ENABLE_MOUNT_HARDENING=0
ENABLE_NETWORK_HARDENING=0
ENABLE_SSH_HARDENING=0
ENABLE_AUDIT_HARDENING=0
ENABLE_LOG_PERMISSIONS=0
FIREWALL_BACKEND="none"
STRICT_EGRESS=0
ACKNOWLEDGE_RISK=0

# Site-policy values. Override in the environment or edit before use.
NTP_SERVERS="${NTP_SERVERS:-}"
FALLBACK_NTP_SERVERS="${FALLBACK_NTP_SERVERS:-}"
REMOTE_LOG_HOST="${REMOTE_LOG_HOST:-}"
REMOTE_LOG_PORT="${REMOTE_LOG_PORT:-514}"
JOURNAL_UPLOAD_URL="${JOURNAL_UPLOAD_URL:-}"
JOURNAL_SERVER_KEY="${JOURNAL_SERVER_KEY:-}"
JOURNAL_SERVER_CERT="${JOURNAL_SERVER_CERT:-}"
JOURNAL_TRUSTED_CERT="${JOURNAL_TRUSTED_CERT:-}"
GRUB_SUPERUSER="${GRUB_SUPERUSER:-}"
GRUB_PASSWORD_HASH="${GRUB_PASSWORD_HASH:-}"
SSH_PORT="${SSH_PORT:-22}"
FIREWALL_ALLOW_TCP="${FIREWALL_ALLOW_TCP:-$SSH_PORT}"
FIREWALL_ALLOW_UDP="${FIREWALL_ALLOW_UDP:-}"

usage() {
  cat <<'EOF'
Usage: sudo ./remediate-cis-ubuntu24-failures.sh [options]

The default is a dry run. Options:
  --apply                       Apply the low-impact subset after backups
  --enable-mount-hardening     Change/remount existing separate filesystems
  --enable-network-hardening   Apply live network sysctl changes
  --enable-ssh-hardening       Change, validate, and reload OpenSSH settings
  --enable-audit-hardening     Add live audit rules (boot parameters excluded)
  --enable-log-permissions     Tighten permissions recursively under /var/log
  --enable-pam-hardening       Enable PAM, password aging, timeout, and root umask policy
  --enable-apparmor            Put all loaded AppArmor profiles in enforce mode
  --remove-unused-packages     Purge GDM, rsync, telnet, and FTP clients
  --firewall-backend NAME      none, nftables, ufw, or iptables
  --strict-egress              Use default-deny output policy (high impact)
  --acknowledge-risk           Required with any high-impact option in apply mode
  -h, --help                    Show this help

The script never reboots or shuts down the host. Audit hardening configures
CIS disk-full actions and must only be enabled after capacity review.

Optional environment variables:
  NTP_SERVERS, FALLBACK_NTP_SERVERS, REMOTE_LOG_HOST, REMOTE_LOG_PORT
  JOURNAL_UPLOAD_URL, JOURNAL_SERVER_KEY, JOURNAL_SERVER_CERT
  JOURNAL_TRUSTED_CERT, GRUB_SUPERUSER, GRUB_PASSWORD_HASH
  SSH_PORT, FIREWALL_ALLOW_TCP (space-separated), FIREWALL_ALLOW_UDP

Examples:
  sudo ./remediate-cis-ubuntu24-failures.sh | tee cis-remediation-plan.log
  sudo ./remediate-cis-ubuntu24-failures.sh --apply
  sudo NTP_SERVERS='time1.example time2.example' ./remediate-cis-ubuntu24-failures.sh --apply
EOF
}

while (($#)); do
  case "$1" in
    --apply) APPLY=1 ;;
    --enable-pam-hardening) ENABLE_PAM_HARDENING=1 ;;
    --enable-apparmor) ENABLE_APPARMOR=1 ;;
    --remove-unused-packages) REMOVE_UNUSED_PACKAGES=1 ;;
    --enable-mount-hardening) ENABLE_MOUNT_HARDENING=1 ;;
    --enable-network-hardening) ENABLE_NETWORK_HARDENING=1 ;;
    --enable-ssh-hardening) ENABLE_SSH_HARDENING=1 ;;
    --enable-audit-hardening) ENABLE_AUDIT_HARDENING=1 ;;
    --enable-log-permissions) ENABLE_LOG_PERMISSIONS=1 ;;
    --firewall-backend)
      [[ $# -ge 2 ]] || { echo "Missing value for --firewall-backend" >&2; exit 2; }
      FIREWALL_BACKEND="$2"; shift ;;
    --strict-egress) STRICT_EGRESS=1 ;;
    --acknowledge-risk) ACKNOWLEDGE_RISK=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$FIREWALL_BACKEND" in none|nftables|ufw|iptables) ;; *) echo "Invalid firewall backend" >&2; exit 2 ;; esac
if (( APPLY )) && {
  (( ENABLE_MOUNT_HARDENING || ENABLE_NETWORK_HARDENING || ENABLE_SSH_HARDENING ||
     ENABLE_AUDIT_HARDENING || ENABLE_LOG_PERMISSIONS ||
     ENABLE_PAM_HARDENING || ENABLE_APPARMOR || REMOVE_UNUSED_PACKAGES || STRICT_EGRESS )) ||
  [[ "$FIREWALL_BACKEND" != none ]]
}; then
  (( ACKNOWLEDGE_RISK )) || {
    echo "High-impact options require --acknowledge-risk on this running server." >&2
    exit 2
  }
fi
(( EUID == 0 )) || { echo "Run as root (sudo)." >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo "This script requires Ubuntu." >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04* ]] || {
  echo "Refusing unsupported OS: ${PRETTY_NAME:-unknown}; expected Ubuntu 24.04." >&2; exit 1;
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/cis-ubuntu24-$STAMP"
CHANGED=0
SKIPPED=0

log() { printf '%s\n' "$*"; }
skip() { log "SKIP: $*"; SKIPPED=$((SKIPPED + 1)); }
quote_cmd() { printf ' %q' "$@"; }
run() {
  printf '%s' "$([[ $APPLY -eq 1 ]] && echo RUN || echo PLAN):"
  quote_cmd "$@"; printf '\n'
  if (( APPLY )); then "$@"; fi
}
backup() {
  local path="$1" rel
  [[ -e "$path" || -L "$path" ]] || return 0
  rel="${path#/}"
  if (( APPLY )) && [[ ! -e "$BACKUP_DIR/$rel" ]]; then
    mkdir -p "$BACKUP_DIR/$(dirname "$rel")"
    cp -a -- "$path" "$BACKUP_DIR/$rel"
  fi
}
write_file() {
  local path="$1" mode="$2" content="$3" tmp
  log "$([[ $APPLY -eq 1 ]] && echo WRITE || echo PLAN): $path (mode $mode)"
  if (( APPLY )); then
    backup "$path"
    mkdir -p "$(dirname "$path")"
    tmp="$(mktemp "${path}.XXXXXX")"
    printf '%s\n' "$content" > "$tmp"
    chown root:root "$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$path"
  fi
  CHANGED=$((CHANGED + 1))
}
replace_setting() {
  local file="$1" key="$2" value="$3" sep="${4:- = }" tmp
  log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): $file: $key$sep$value"
  if (( APPLY )); then
    backup "$file"; mkdir -p "$(dirname "$file")"; touch "$file"
    tmp="$(mktemp "${file}.XXXXXX")"
    awk -v k="$key" -v v="$value" -v s="$sep" '
      BEGIN { done=0 }
      $0 ~ "^[[:space:]#]*" k "[[:space:]]*=" { if (!done) print k s v; done=1; next }
      $0 ~ "^[[:space:]#]*" k "[[:space:]]+" && s == " " { if (!done) print k s v; done=1; next }
      { print }
      END { if (!done) print k s v }
    ' "$file" > "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || chown root:root "$tmp"
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
    mv -f "$tmp" "$file"
  fi
  CHANGED=$((CHANGED + 1))
}
have() { command -v "$1" >/dev/null 2>&1; }
systemd_available() { [[ -d /run/systemd/system ]] && have systemctl; }
audit_is_immutable() {
  have auditctl && auditctl -s 2>/dev/null | awk '$1 == "enabled" && $2 == "2" {found=1} END {exit !found}'
}

log "Mode: $([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)"
log "Production guard: disruptive categories are opt-in and require --acknowledge-risk when applied."
(( APPLY )) && mkdir -p "$BACKUP_DIR"

# 35513, 35519-20, 35522-23, 35525-27, 35529-31, 35533-35
# Add mount flags only where a separate mount already exists. Never repartition online.
add_mount_options() {
  local target="$1" options="$2" source fstype current newopts line tmp
  if ! findmnt -rn --target "$target" >/dev/null 2>&1; then skip "$target is not mounted"; return; fi
  source="$(findmnt -rn -o SOURCE --target "$target")"
  [[ "$(findmnt -rn -o TARGET --target "$target")" == "$target" ]] || {
    skip "$target is not a separate mount; partition design requires maintenance planning"; return;
  }
  [[ -f /etc/fstab ]] || { skip "/etc/fstab is absent"; return; }
  line="$(awk -v t="$target" '$1 !~ /^#/ && $2 == t {print; exit}' /etc/fstab)"
  [[ -n "$line" ]] || { skip "$target has no /etc/fstab entry"; return; }
  current="$(awk '{print $4}' <<< "$line")"; newopts="$current"
  for opt in $options; do [[ ",$newopts," == *",$opt,"* ]] || newopts="$newopts,$opt"; done
  if [[ "$newopts" != "$current" ]]; then
    log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): /etc/fstab add '$options' to $target"
    if (( APPLY )); then
      backup /etc/fstab; tmp="$(mktemp /etc/fstab.XXXXXX)"
      awk -v t="$target" -v o="$newopts" 'BEGIN{OFS="\t"} $1 !~ /^#/ && $2==t {$4=o} {print}' /etc/fstab > "$tmp"
      chown root:root "$tmp"; chmod 0644 "$tmp"; mv -f "$tmp" /etc/fstab
      mount -o remount "$target"
    fi
  fi
}
if (( ENABLE_MOUNT_HARDENING )); then
  add_mount_options /tmp "noexec"
  add_mount_options /home "nodev nosuid"
  add_mount_options /var "nodev nosuid"
  add_mount_options /var/tmp "nodev nosuid noexec"
  add_mount_options /var/log "nodev nosuid noexec"
  add_mount_options /var/log/audit "nodev nosuid noexec"
else
  skip "mount/remount changes need --enable-mount-hardening and a maintenance window"
fi
skip "35518/35521/35524/35528/35532 require a storage/repartitioning maintenance plan"

# 35506, 35509, 35604-07 are intentionally excluded. Fully remediating loaded
# kernel modules can require a reboot and may break Snap, storage, or networking.
skip "kernel-module controls are excluded because this is a no-reboot script"

# 35538-39
if (( ENABLE_APPARMOR )); then
  have aa-enforce && run aa-enforce /etc/apparmor.d/* || skip "aa-enforce is unavailable"
else
  skip "AppArmor enforcement needs --enable-apparmor and application compatibility testing"
fi

# 35540
if [[ -n "$GRUB_SUPERUSER" && -n "$GRUB_PASSWORD_HASH" ]]; then
  [[ "$GRUB_PASSWORD_HASH" == grub.pbkdf2.* ]] || { echo "GRUB_PASSWORD_HASH is not a GRUB PBKDF2 hash" >&2; exit 1; }
  write_file /etc/grub.d/01_cis_users 0700 "#!/bin/sh
cat <<'GRUB_EOF'
set superusers=\"$GRUB_SUPERUSER\"
password_pbkdf2 $GRUB_SUPERUSER $GRUB_PASSWORD_HASH
GRUB_EOF"
else
  skip "bootloader password needs GRUB_SUPERUSER and GRUB_PASSWORD_HASH"
fi
# 35543, 35545
write_file /etc/security/limits.d/60-cis-core.conf 0644 '* hard core 0'
write_file /etc/sysctl.d/60-cis-core.conf 0644 'fs.suid_dumpable = 0'
if (( ENABLE_NETWORK_HARDENING )); then
  write_file /etc/sysctl.d/61-cis-network.conf 0644 'net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1'
else
  skip "live network sysctls need --enable-network-hardening after routing review"
fi
write_file /etc/systemd/coredump.conf.d/60-cis.conf 0644 '[Coredump]
Storage=none
ProcessSizeMax=0'
if (( APPLY )); then
  sysctl -q -w fs.suid_dumpable=0
  (( ENABLE_NETWORK_HARDENING )) && sysctl --system >/dev/null
fi
if [[ -e /etc/default/apport ]]; then replace_setting /etc/default/apport enabled 0 '='; fi
if systemd_available; then run systemctl disable --now apport.service 2>/dev/null || true; run systemctl mask apport.service 2>/dev/null || true; fi

# 35552, 35573, 35585, 35587
if (( REMOVE_UNUSED_PACKAGES )); then
  run env DEBIAN_FRONTEND=noninteractive apt-get purge -y gdm3 rsync telnet inetutils-telnet ftp tnftp
  run env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
else
  skip "package removals need --remove-unused-packages (GDM, rsync, telnet, FTP clients)"
fi

# 35588, 35591-92: configure the installed time implementation only with approved servers.
if [[ -n "$NTP_SERVERS" ]]; then
  if dpkg-query -W -f='${Status}' chrony 2>/dev/null | grep -q 'ok installed'; then
    write_file /etc/chrony/conf.d/60-cis.conf 0644 "user _chrony
$(for s in $NTP_SERVERS; do printf 'server %s iburst\n' "$s"; done)"
    systemd_available && run systemctl enable --now chrony.service
  else
    write_file /etc/systemd/timesyncd.conf.d/60-cis.conf 0644 "[Time]
NTP=$NTP_SERVERS
FallbackNTP=$FALLBACK_NTP_SERVERS"
    systemd_available && run systemctl enable --now systemd-timesyncd.service
  fi
else
  skip "time synchronization needs site-approved NTP_SERVERS"
fi

# 35600
if [[ -e /etc/cron.deny ]]; then run chown root:root /etc/cron.deny; run chmod 0600 /etc/cron.deny
else write_file /etc/cron.allow 0640 ''; [[ $(getent group crontab || true) ]] && run chown root:crontab /etc/cron.allow; fi

# 35623-39: scanners often report all three mutually exclusive firewall profiles.
configure_nftables() {
  local tcp_rules="" udp_rules="" output_policy="accept"
  for p in $FIREWALL_ALLOW_TCP; do tcp_rules+="    tcp dport $p accept\n"; done
  for p in $FIREWALL_ALLOW_UDP; do udp_rules+="    udp dport $p accept\n"; done
  (( STRICT_EGRESS )) && output_policy="drop"
  local rules="#!/usr/sbin/nft -f
flush ruleset
table inet cis_filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname \"lo\" accept
    ip saddr 127.0.0.0/8 iifname != \"lo\" drop
    ip6 saddr ::1 iifname != \"lo\" drop
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
$(printf '%b' "$tcp_rules$udp_rules")  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy $output_policy; oifname \"lo\" accept; ct state established,related accept; }
}"
  if (( APPLY )); then
    have nft || apt-get install -y nftables
    local testfile; testfile="$(mktemp)"; printf '%s\n' "$rules" > "$testfile"
    nft -c -f "$testfile"; rm -f "$testfile"
  fi
  write_file /etc/nftables.conf 0644 "$rules"
  if (( APPLY )); then
    have iptables && iptables -F || true
    have ip6tables && ip6tables -F || true
  else
    log 'PLAN: flush legacy iptables/ip6tables rules after nftables validation'
  fi
  if systemd_available; then run systemctl disable --now ufw.service 2>/dev/null || true; run systemctl enable --now nftables.service; fi
}
configure_ufw() {
  if (( APPLY )); then have ufw || apt-get install -y ufw; fi
  run ufw allow in on lo; run ufw allow out on lo; run ufw deny in from 127.0.0.0/8; run ufw deny in from ::1
  for p in $FIREWALL_ALLOW_TCP; do run ufw allow "$p/tcp"; done
  for p in $FIREWALL_ALLOW_UDP; do run ufw allow "$p/udp"; done
  run ufw default deny incoming; run ufw default deny routed
  (( STRICT_EGRESS )) && run ufw default deny outgoing || run ufw default allow outgoing
  run ufw --force enable
}
configure_iptables() {
  if (( APPLY )); then have iptables || apt-get install -y iptables iptables-persistent; fi
  run iptables -P INPUT ACCEPT
  if (( APPLY )); then
    iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT
    iptables -C INPUT -s 127.0.0.0/8 ! -i lo -j DROP 2>/dev/null || iptables -I INPUT 2 -s 127.0.0.0/8 ! -i lo -j DROP
    iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  else log 'PLAN: ensure direct IPv4 loopback, anti-spoofing, and established-connection rules'; fi
  for p in $FIREWALL_ALLOW_TCP; do
    if (( APPLY )); then iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p tcp --dport "$p" -j ACCEPT
    else log "PLAN: allow inbound TCP $p"; fi
  done
  for p in $FIREWALL_ALLOW_UDP; do
    if (( APPLY )); then iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p udp --dport "$p" -j ACCEPT
    else log "PLAN: allow inbound UDP $p"; fi
  done
  run iptables -P INPUT DROP; run iptables -P FORWARD DROP
  if (( STRICT_EGRESS )); then
    if (( APPLY )); then
      iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o lo -j ACCEPT
      iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -C OUTPUT -p udp -m multiport --dports 53,123 -j ACCEPT 2>/dev/null || iptables -I OUTPUT 3 -p udp -m multiport --dports 53,123 -j ACCEPT
      iptables -C OUTPUT -p tcp -m multiport --dports 53,80,443 -j ACCEPT 2>/dev/null || iptables -I OUTPUT 3 -p tcp -m multiport --dports 53,80,443 -j ACCEPT
    else log 'PLAN: allow loopback, established traffic, DNS, NTP, HTTP, and HTTPS egress'; fi
    run iptables -P OUTPUT DROP
  else run iptables -P OUTPUT ACCEPT; fi
  if have ip6tables || (( ! APPLY )); then
    run ip6tables -P INPUT ACCEPT
    if (( APPLY )); then
      ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -i lo -j ACCEPT
      ip6tables -C INPUT -s ::1 ! -i lo -j DROP 2>/dev/null || ip6tables -I INPUT 2 -s ::1 ! -i lo -j DROP
      ip6tables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -I INPUT 3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    else log 'PLAN: ensure direct IPv6 loopback, anti-spoofing, and established-connection rules'; fi
    for p in $FIREWALL_ALLOW_TCP; do
      if (( APPLY )); then ip6tables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p tcp --dport "$p" -j ACCEPT; fi
    done
    for p in $FIREWALL_ALLOW_UDP; do
      if (( APPLY )); then ip6tables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p udp --dport "$p" -j ACCEPT; fi
    done
    run ip6tables -P INPUT DROP; run ip6tables -P FORWARD DROP
    if (( STRICT_EGRESS )); then
      if (( APPLY )); then
        ip6tables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -o lo -j ACCEPT
        ip6tables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        ip6tables -C OUTPUT -p udp -m multiport --dports 53,123 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 3 -p udp -m multiport --dports 53,123 -j ACCEPT
        ip6tables -C OUTPUT -p tcp -m multiport --dports 53,80,443 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 3 -p tcp -m multiport --dports 53,80,443 -j ACCEPT
      fi
      run ip6tables -P OUTPUT DROP
    else run ip6tables -P OUTPUT ACCEPT; fi
  fi
  if systemd_available; then
    run systemctl disable --now ufw.service 2>/dev/null || true
    run systemctl disable --now nftables.service 2>/dev/null || true
  fi
  if (( APPLY )) && have netfilter-persistent; then run netfilter-persistent save; fi
}
case "$FIREWALL_BACKEND" in
  nftables) configure_nftables ;;
  ufw) configure_ufw ;;
  iptables) configure_iptables ;;
  none) skip "firewall remediation needs one explicit --firewall-backend choice" ;;
esac

# 35640, 35644, 35646-50, 35652-53, 35655-61
if (( ENABLE_SSH_HARDENING )) && [[ -d /etc/ssh ]]; then
  write_file /etc/ssh/sshd_config.d/00-cis-hardening.conf 0600 'Banner /etc/issue.net
ClientAliveInterval 15
ClientAliveCountMax 3
DisableForwarding yes
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
LoginGraceTime 60
LogLevel VERBOSE
MaxAuthTries 4
MaxSessions 10
MaxStartups 10:30:60
PermitEmptyPasswords no
PermitRootLogin no
PermitUserEnvironment no
UsePAM yes'
  [[ -e /etc/ssh/sshd_config ]] && { run chown root:root /etc/ssh/sshd_config; run chmod 0600 /etc/ssh/sshd_config; }
  if (( APPLY )) && have sshd; then
    if sshd -t; then systemd_available && systemctl reload ssh.service 2>/dev/null || true
    else echo "ERROR: sshd validation failed; restore from $BACKUP_DIR" >&2; exit 1; fi
  fi
else
  skip "OpenSSH changes need --enable-ssh-hardening after checking tunnels and client compatibility"
fi

# 35664
write_file /etc/sudoers.d/00-cis-logfile 0440 'Defaults logfile="/var/log/sudo.log"'
if (( APPLY )) && have visudo; then visudo -cf /etc/sudoers >/dev/null || { echo "sudoers validation failed" >&2; exit 1; }; fi

# 35668, 35672-90. Explicit opt-in because PAM mistakes can deny all logins.
if (( ENABLE_PAM_HARDENING )); then
  if ! getent group sugroup >/dev/null; then run groupadd --system sugroup; fi
  if [[ -e /etc/pam.d/su ]] && ! grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=sugroup' /etc/pam.d/su; then
    log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): append pam_wheel restriction to /etc/pam.d/su"
    if (( APPLY )); then backup /etc/pam.d/su; printf '%s\n' 'auth required pam_wheel.so use_uid group=sugroup' >> /etc/pam.d/su; fi
  fi
  write_file /usr/share/pam-configs/faillock 0644 'Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail'
  write_file /usr/share/pam-configs/faillock_notify 0644 'Name: Notify failed logins and reset upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth
Account-Type: Primary
Account:
 required pam_faillock.so'
  write_file /usr/share/pam-configs/pwhistory 0644 'Name: Password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
 requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok'
  write_file /etc/security/faillock.conf 0644 'deny = 5
unlock_time = 900
even_deny_root
root_unlock_time = 900'
  write_file /etc/security/pwquality.conf.d/60-cis.conf 0644 'difok = 2
minlen = 14
minclass = 4
maxrepeat = 3
maxsequence = 3'
  if (( APPLY )); then
    if [[ -f /usr/share/pam-configs/unix ]]; then
      backup /usr/share/pam-configs/unix
      sed -ri '/pam_unix\.so/s/(^|[[:space:]])nullok([[:space:]]|$)/ /g' /usr/share/pam-configs/unix
    fi
    pam-auth-update --enable unix faillock faillock_notify pwhistory
  else log 'PLAN: pam-auth-update --enable unix faillock faillock_notify pwhistory'; fi
else
  skip "PAM/password-quality changes need --enable-pam-hardening and console recovery access"
fi

# 35694-98, 35703, 35705
if (( ENABLE_PAM_HARDENING )); then
  replace_setting /etc/login.defs PASS_MAX_DAYS 365 ' '
  replace_setting /etc/login.defs PASS_MIN_DAYS 1 ' '
  if (( APPLY )); then
    while IFS=: read -r user hash _ min max _ inactive _; do
      [[ "$hash" == \$*\$* ]] || continue
      [[ "$max" =~ ^[0-9]+$ ]] && (( max >= 1 && max <= 365 )) || chage --maxdays 365 "$user"
      [[ "$min" =~ ^[0-9]+$ ]] && (( min >= 1 )) || chage --mindays 1 "$user"
      [[ "$inactive" =~ ^[0-9]+$ ]] && (( inactive <= 45 )) || chage --inactive 45 "$user"
    done < /etc/shadow
    useradd -D -f 45
  else
    log 'PLAN: normalize password aging for local accounts with password hashes'
  fi
  write_file /etc/profile.d/60-cis-timeout.sh 0644 'TMOUT=900
readonly TMOUT
export TMOUT'
  for f in /root/.bash_profile /root/.bashrc; do
    [[ -e "$f" ]] || continue
    if (( APPLY )); then backup "$f"; sed -ri 's/^[[:space:]]*umask[[:space:]]+.*/umask 027/' "$f"; fi
  done
  grep -RqsE '^[[:space:]]*umask[[:space:]]+0?27' /root/.bash_profile /root/.bashrc 2>/dev/null || {
    if (( APPLY )); then printf '%s\n' 'umask 027' >> /root/.bashrc; else log 'PLAN: append umask 027 to /root/.bashrc'; fi
  }
else
  skip "password aging, shell timeout, and root umask need --enable-pam-hardening"
fi

# 35708, 35714-15
write_file /etc/systemd/journald.conf.d/60-cis.conf 0644 '[Journal]
SystemMaxUse=1G
SystemKeepFree=500M
RuntimeMaxUse=200M
RuntimeKeepFree=50M
MaxFileSec=1month
Compress=yes
Storage=persistent'
systemd_available && (( APPLY )) && systemctl reload-or-restart systemd-journald.service

# 35709-11: remote journal upload is only enabled when all site parameters exist.
if [[ -n "$JOURNAL_UPLOAD_URL" && -n "$JOURNAL_SERVER_KEY" && -n "$JOURNAL_SERVER_CERT" && -n "$JOURNAL_TRUSTED_CERT" ]]; then
  if (( APPLY )); then apt-get install -y systemd-journal-remote; fi
  write_file /etc/systemd/journal-upload.conf.d/60-cis.conf 0600 "[Upload]
URL=$JOURNAL_UPLOAD_URL
ServerKeyFile=$JOURNAL_SERVER_KEY
ServerCertificateFile=$JOURNAL_SERVER_CERT
TrustedCertificateFile=$JOURNAL_TRUSTED_CERT"
  systemd_available && run systemctl enable --now systemd-journal-upload.service
else
  skip "journal upload needs URL, key, server certificate, and trusted CA values"
fi

# 35720-21
if [[ -n "$REMOTE_LOG_HOST" ]]; then
  write_file /etc/rsyslog.d/61-cis-forward.conf 0644 "*.* action(type=\"omfwd\" target=\"$REMOTE_LOG_HOST\" port=\"$REMOTE_LOG_PORT\" protocol=\"tcp\" action.resumeRetryCount=\"100\" queue.type=\"LinkedList\" queue.size=\"1000\")"
else
  skip "rsyslog forwarding needs REMOTE_LOG_HOST"
fi
if grep -RslE '^[[:space:]]*(module\(load="imtcp"\)|input\(type="imtcp"|\$ModLoad[[:space:]]+imtcp|\$InputTCPServerRun)' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null | grep -q .; then
  skip "rsyslog TCP receive directives exist; review before disabling on a possible log server"
fi
if (( APPLY )) && have rsyslogd; then rsyslogd -N1 >/dev/null; systemd_available && systemctl reload-or-restart rsyslog.service; fi

# 35722, 35752, 35755, 35765-70: conservative permissions.
if (( ENABLE_LOG_PERMISSIONS )) && [[ -d /var/log ]]; then
  run find /var/log -xdev -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +
else
  skip "recursive /var/log changes need --enable-log-permissions after owner/mode review"
fi
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do [[ -e "$tool" ]] && run chmod go-w "$tool"; done
for f in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-; do [[ -e "$f" ]] && { run chown root:shadow "$f"; run chmod 0640 "$f"; }; done
for f in /etc/security/opasswd /etc/security/opasswd.old; do [[ -e "$f" ]] && { run chown root:root "$f"; run chmod 0600 "$f"; }; done

# 35725-26 are intentionally excluded because kernel audit boot parameters
# require a reboot. Remaining audit controls can be loaded on a mutable daemon.
skip "audit=1 and audit_backlog_limit boot controls are excluded because they require reboot"
if (( ENABLE_AUDIT_HARDENING )) && audit_is_immutable; then
  skip "audit rules are immutable; changing them would require reboot"
elif (( ENABLE_AUDIT_HARDENING )) && [[ -d /etc/audit || $(dpkg-query -W -f='${Status}' auditd 2>/dev/null || true) == *installed* ]]; then
  replace_setting /etc/audit/auditd.conf max_log_file_action keep_logs
  replace_setting /etc/audit/auditd.conf disk_full_action halt
  replace_setting /etc/audit/auditd.conf disk_error_action halt
  replace_setting /etc/audit/auditd.conf space_left_action email
  replace_setting /etc/audit/auditd.conf admin_space_left_action single
  UID_MIN="$(awk '$1=="UID_MIN" {print $2; exit}' /etc/login.defs)"; [[ "$UID_MIN" =~ ^[0-9]+$ ]] || UID_MIN=1000
  write_file /etc/audit/rules.d/60-cis.rules 0640 "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-w /var/log/sudo.log -p wa -k sudo_log_file
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$UID_MIN -F auid!=unset -k access
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,lchown,fchownat,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$UID_MIN -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,chown,fchown,lchown,fchownat,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$UID_MIN -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=$UID_MIN -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=$UID_MIN -F auid!=unset -k delete
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=$UID_MIN -F auid!=unset -k usermod
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=$UID_MIN -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=$UID_MIN -F auid!=unset -k kernel_modules"
  if (( APPLY )) && [[ "$(uname -m)" != x86_64 ]]; then
    backup /etc/audit/rules.d/60-cis.rules
    sed -i '/-F arch=b32/d' /etc/audit/rules.d/60-cis.rules
  fi
  if (( APPLY )) && have augenrules; then augenrules --check; augenrules --load || skip "audit rules require reboot or architecture-specific tuning"; fi
elif (( ENABLE_AUDIT_HARDENING )); then
  skip "auditd is not installed; install it under your package-change process before applying audit rules"
else
  skip "live audit changes need --enable-audit-hardening after capacity and disk-full review"
fi
if (( ENABLE_AUDIT_HARDENING )) && [[ -f /etc/aide/aide.conf ]]; then
  aide_lines="# Audit Tools"
  for tool in auditctl auditd ausearch aureport autrace augenrules; do
    path="$(readlink -f "/sbin/$tool" 2>/dev/null || true)"; [[ -n "$path" ]] && aide_lines+=$'\n'"$path p+i+n+u+g+s+b+acl+xattrs+sha512"
  done
  log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): managed audit-tool block in /etc/aide/aide.conf"
  if (( APPLY )); then
    backup /etc/aide/aide.conf
    aide_tmp="$(mktemp /etc/aide/aide.conf.XXXXXX)"
    awk '/^# BEGIN CIS AUDIT TOOLS$/{drop=1; next} /^# END CIS AUDIT TOOLS$/{drop=0; next} !drop{print}' /etc/aide/aide.conf > "$aide_tmp"
    printf '\n%s\n%s\n%s\n' '# BEGIN CIS AUDIT TOOLS' "$aide_lines" '# END CIS AUDIT TOOLS' >> "$aide_tmp"
    chown root:root "$aide_tmp"; chmod 0644 "$aide_tmp"; mv -f "$aide_tmp" /etc/aide/aide.conf
  fi
elif (( ENABLE_AUDIT_HARDENING )); then
  skip "AIDE is not installed/configured; audit-tool integrity entries were not added"
fi

if (( APPLY )); then
  if [[ -n "$GRUB_SUPERUSER" && -n "$GRUB_PASSWORD_HASH" ]]; then
    have update-grub && run update-grub
  fi
  systemd_available && run systemctl daemon-reload
fi

log "Completed. Planned/written configuration units: $CHANGED; skipped categories/items: $SKIPPED."
if (( APPLY )); then
  log "Backups: $BACKUP_DIR"
  log "No reboot-required remediation is included. Re-run the original scanner afterward."
else
  log "No changes were made. Review this output, then rerun with --apply and chosen opt-in flags."
fi
