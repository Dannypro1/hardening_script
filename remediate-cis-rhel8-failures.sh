#!/usr/bin/env bash
# CIS RHEL 8 remediation for failed controls in 01-checks-5-.csv.
# Dry-run by default. No automatic reboot. Review and stage on a running server.
set -Eeuo pipefail

APPLY=0
ACK=0
ENABLE_STORAGE=0
ENABLE_MODULES=0
REMOVE_PACKAGES=0
ENABLE_SSH=0
ENABLE_AUTH=0
ENABLE_AUDIT=0
ENABLE_LOG_PERMS=0
INITIALIZE_AIDE=0
DISABLE_IPV6=0
ENABLE_SERVICES=0
FIREWALL_BACKEND="none"

BANNER_TEXT="${BANNER_TEXT:-Authorized users only. All activity may be monitored and reported.}"
NTP_SERVERS="${NTP_SERVERS:-}"
REMOTE_LOG_HOST="${REMOTE_LOG_HOST:-}"
REMOTE_LOG_PORT="${REMOTE_LOG_PORT:-514}"
SSH_ALLOW_USERS="${SSH_ALLOW_USERS:-}"
SSH_ALLOW_GROUPS="${SSH_ALLOW_GROUPS:-}"
SSH_PORT="${SSH_PORT:-22}"
FIREWALL_ALLOW_TCP="${FIREWALL_ALLOW_TCP:-$SSH_PORT}"
FIREWALL_ALLOW_UDP="${FIREWALL_ALLOW_UDP:-}"
FIREWALL_EGRESS_TCP="${FIREWALL_EGRESS_TCP:-53 80 443}"
FIREWALL_EGRESS_UDP="${FIREWALL_EGRESS_UDP:-53 123}"

usage() {
  cat <<'EOF'
Usage: sudo ./remediate-cis-rhel8-failures.sh [options]

Default behavior is a read-only preview.
  --apply                    Apply low-impact remediations and make backups
  --acknowledge-risk         Required with any high-impact option in apply mode
  --enable-storage           Remount existing separate filesystems with CIS flags
  --enable-modules           Disable/unload failed filesystem and USB modules
  --remove-packages          Remove failed unnecessary package groups
  --firewall-backend NAME   firewalld, nftables, iptables, or none
  --disable-ipv6             Disable IPv6 live and persistently
  --enable-ssh               Apply, validate, and reload SSH hardening
  --enable-auth              Apply authselect, PAM, password, su, and account policy
  --enable-audit             Apply audit rules, immutability, and boot parameters
  --enable-log-permissions   Recursively tighten /var/log permissions
  --initialize-aide          Run the initial AIDE scan at lowest CPU/I/O priority
  --enable-services         Install packages and enable/restart affected services
  -h, --help                 Show help

Site values are supplied with environment variables:
  NTP_SERVERS="ntp1.example ntp2.example"
  REMOTE_LOG_HOST=loghost.example REMOTE_LOG_PORT=514
  SSH_ALLOW_USERS="admin1 admin2" or SSH_ALLOW_GROUPS="sshadmins"
  FIREWALL_ALLOW_TCP="22 443" FIREWALL_ALLOW_UDP=""
  FIREWALL_EGRESS_TCP="53 80 443" FIREWALL_EGRESS_UDP="53 123"

The script never reboots. Boot-parameter changes made by --enable-audit are
reported as pending reboot. Never combine all high-impact flags on a live host.
EOF
}

while (($#)); do
  case "$1" in
    --apply) APPLY=1 ;;
    --acknowledge-risk) ACK=1 ;;
    --enable-storage) ENABLE_STORAGE=1 ;;
    --enable-modules) ENABLE_MODULES=1 ;;
    --remove-packages) REMOVE_PACKAGES=1 ;;
    --disable-ipv6) DISABLE_IPV6=1 ;;
    --enable-ssh) ENABLE_SSH=1 ;;
    --enable-auth) ENABLE_AUTH=1 ;;
    --enable-audit) ENABLE_AUDIT=1 ;;
    --enable-log-permissions) ENABLE_LOG_PERMS=1 ;;
    --initialize-aide) INITIALIZE_AIDE=1 ;;
    --enable-services) ENABLE_SERVICES=1 ;;
    --firewall-backend)
      [[ $# -ge 2 ]] || { echo "Missing firewall backend" >&2; exit 2; }
      FIREWALL_BACKEND="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$FIREWALL_BACKEND" in none|firewalld|nftables|iptables) ;; *) echo "Invalid firewall backend" >&2; exit 2 ;; esac
if (( APPLY )) && { (( ENABLE_STORAGE || ENABLE_MODULES || REMOVE_PACKAGES || DISABLE_IPV6 || ENABLE_SSH || ENABLE_AUTH || ENABLE_AUDIT || ENABLE_LOG_PERMS || INITIALIZE_AIDE || ENABLE_SERVICES )) || [[ "$FIREWALL_BACKEND" != none ]]; }; then
  (( ACK )) || { echo "High-impact options require --acknowledge-risk." >&2; exit 2; }
fi
(( EUID == 0 )) || { echo "Run as root." >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" =~ ^(rhel|rocky|almalinux|ol|centos)$ && "${VERSION_ID%%.*}" == 8 ]] || {
  echo "Unsupported OS: ${PRETTY_NAME:-unknown}; expected a RHEL 8 family host." >&2; exit 1;
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/cis-rhel8-$STAMP"
CHANGED=0
SKIPPED=0
REBOOT_PENDING=0

log() { printf '%s\n' "$*"; }
skip() { log "SKIP: $*"; SKIPPED=$((SKIPPED + 1)); }
have() { command -v "$1" >/dev/null 2>&1; }
systemd_available() { [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; }
quote_cmd() { printf ' %q' "$@"; }
run() {
  printf '%s' "$([[ $APPLY -eq 1 ]] && echo RUN || echo PLAN):"; quote_cmd "$@"; printf '\n'
  if (( APPLY )); then "$@"; fi
}
backup() {
  local path="$1" rel="${1#/}"
  [[ -e "$path" || -L "$path" ]] || return 0
  if (( APPLY )) && [[ ! -e "$BACKUP_DIR/$rel" ]]; then
    mkdir -p "$BACKUP_DIR/$(dirname "$rel")"; cp -a -- "$path" "$BACKUP_DIR/$rel"
  fi
}
write_file() {
  local path="$1" mode="$2" content="$3" tmp
  log "$([[ $APPLY -eq 1 ]] && echo WRITE || echo PLAN): $path"
  if (( APPLY )); then
    backup "$path"; mkdir -p "$(dirname "$path")"; tmp="$(mktemp "${path}.XXXXXX")"
    printf '%s\n' "$content" > "$tmp"; chown root:root "$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$path"
  fi
  CHANGED=$((CHANGED + 1))
}
replace_setting() {
  local file="$1" key="$2" value="$3" sep="${4:- = }" tmp
  log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): $file: $key$sep$value"
  if (( APPLY )); then
    backup "$file"; mkdir -p "$(dirname "$file")"; touch "$file"; tmp="$(mktemp "${file}.XXXXXX")"
    awk -v k="$key" -v v="$value" -v s="$sep" '
      BEGIN{done=0}
      $0 ~ "^[[:space:]#]*" k "([[:space:]]*=|[[:space:]]+)" {if(!done) print k s v; done=1; next}
      {print} END{if(!done) print k s v}
    ' "$file" > "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || chown root:root "$tmp"
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 0644 "$tmp"; mv -f "$tmp" "$file"
  fi
  CHANGED=$((CHANGED + 1))
}
prepend_managed_block() {
  local file="$1" name="$2" content="$3" mode="$4" tmp
  log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): managed $name block in $file"
  if (( APPLY )); then
    backup "$file"; touch "$file"; tmp="$(mktemp "${file}.XXXXXX")"
    printf '# BEGIN %s\n%s\n# END %s\n' "$name" "$content" "$name" > "$tmp"
    awk -v b="# BEGIN $name" -v e="# END $name" '$0==b{drop=1;next} $0==e{drop=0;next} !drop{print}' "$file" >> "$tmp"
    chown root:root "$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$file"
  fi
}
append_managed_block() {
  local file="$1" name="$2" content="$3" mode="$4" tmp
  log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): managed $name block in $file"
  if (( APPLY )); then
    backup "$file"; touch "$file"; tmp="$(mktemp "${file}.XXXXXX")"
    awk -v b="# BEGIN $name" -v e="# END $name" '$0==b{drop=1;next} $0==e{drop=0;next} !drop{print}' "$file" > "$tmp"
    printf '\n# BEGIN %s\n%s\n# END %s\n' "$name" "$content" "$name" >> "$tmp"
    chown root:root "$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$file"
  fi
}
pkg_installed() { rpm -q "$1" >/dev/null 2>&1; }

log "Mode: $([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)"
(( APPLY )) && mkdir -p "$BACKUP_DIR"

# 5000-5002, 5032: kernel modules.
disable_module() {
  local mod="$1" conf="/etc/modprobe.d/60-cis-${1}.conf"
  if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "${mod//-/_}"; then
    run modprobe -r "$mod" || { skip "$mod is in use; configuration is persistent but removal needs maintenance/reboot"; REBOOT_PENDING=1; }
  fi
  write_file "$conf" 0644 "install $mod /bin/false
blacklist $mod"
}
if (( ENABLE_MODULES )); then
  for m in cramfs squashfs udf usb-storage; do disable_module "$m"; done
else skip "5000-5002/5032 module controls need --enable-modules after dependency review"; fi

# 5003-5029: options are live-remounted only for existing separate mounts.
add_mount_options() {
  local target="$1" options="$2" line current newopts tmp
  [[ "$(findmnt -rn -o TARGET --target "$target" 2>/dev/null || true)" == "$target" ]] || { skip "$target is not a separate mount"; return; }
  line="$(awk -v t="$target" '$1 !~ /^#/ && $2==t{print;exit}' /etc/fstab)"
  [[ -n "$line" ]] || { skip "$target has no fstab entry"; return; }
  current="$(awk '{print $4}' <<< "$line")"; newopts="$current"
  for o in $options; do [[ ",$newopts," == *",$o,"* ]] || newopts="$newopts,$o"; done
  [[ "$newopts" == "$current" ]] && return
  log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): add '$options' to $target"
  if (( APPLY )); then
    backup /etc/fstab; tmp="$(mktemp /etc/fstab.XXXXXX)"
    awk -v t="$target" -v o="$newopts" 'BEGIN{OFS="\t"} $1!~/^#/&&$2==t{$4=o}{print}' /etc/fstab > "$tmp"
    chown root:root "$tmp"; chmod 0644 "$tmp"; mv -f "$tmp" /etc/fstab; mount -o remount "$target"
  fi
}
if (( ENABLE_STORAGE )); then
  add_mount_options /tmp 'nodev noexec nosuid'
  add_mount_options /var 'nodev noexec nosuid'
  add_mount_options /var/tmp 'nodev noexec nosuid'
  add_mount_options /var/log 'nodev noexec nosuid'
  add_mount_options /var/log/audit 'nodev noexec nosuid'
  add_mount_options /home 'nodev nosuid usrquota grpquota'
  add_mount_options /dev/shm 'noexec'
else skip "mount changes need --enable-storage"; fi
skip "new /tmp,/var,/var/tmp,/var/log,/var/log/audit,/home filesystems require approved storage and a maintenance migration"

# 5033: package signature validation.
replace_setting /etc/dnf/dnf.conf gpgcheck 1 '='
if [[ -d /etc/yum.repos.d ]]; then
  while IFS= read -r -d '' repo; do
    log "$([[ $APPLY -eq 1 ]] && echo EDIT || echo PLAN): enforce gpgcheck=1 in every section of $repo"
    if (( APPLY )); then
      backup "$repo"; repo_tmp="$(mktemp "${repo}.XXXXXX")"
      awk '
        function finish(){if(section && !gpg) print "gpgcheck=1"}
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {finish(); section=1; gpg=0; print; next}
        /^[[:space:]]*gpgcheck[[:space:]]*=/ {if(section){if(!gpg) print "gpgcheck=1"; gpg=1} next}
        {print}
        END{finish()}
      ' "$repo" > "$repo_tmp"
      chown --reference="$repo" "$repo_tmp"; chmod --reference="$repo" "$repo_tmp"; mv -f "$repo_tmp" "$repo"
    fi
  done < <(find /etc/yum.repos.d -type f -name '*.repo' -print0)
fi

# 5034-5035: AIDE package/timer. Initialization is deliberately low priority.
if ! pkg_installed aide; then
  (( ENABLE_SERVICES )) && run dnf -y install aide || skip "AIDE installation needs --enable-services"
fi
write_file /etc/systemd/system/aidecheck.service 0644 '[Unit]
Description=AIDE integrity check
[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/sbin/aide --check
[Install]
WantedBy=multi-user.target'
write_file /etc/systemd/system/aidecheck.timer 0644 '[Unit]
Description=Daily AIDE integrity check
[Timer]
OnCalendar=*-*-* 05:00:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target'
if (( INITIALIZE_AIDE )); then
  if (( APPLY )) && ! have aide; then
    skip "AIDE initialization skipped because aide is unavailable"
  else
    run nice -n 19 ionice -c 3 aide --init
    if (( APPLY )) && [[ -f /var/lib/aide/aide.db.new.gz ]]; then run mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; fi
  fi
else skip "initial AIDE database needs --initialize-aide; it can be I/O intensive"; fi
if systemd_available && (( ENABLE_SERVICES )); then run systemctl daemon-reload; run systemctl enable aidecheck.service; run systemctl enable --now aidecheck.timer
else skip "AIDE timer activation needs --enable-services"; fi

# 5039-5041: core dumps and ASLR.
append_managed_block /etc/systemd/coredump.conf 'CIS COREDUMP' '[Coredump]
Storage=none
ProcessSizeMax=0' 0644
write_file /etc/sysctl.d/60-cis-kernel.conf 0644 'kernel.randomize_va_space = 2'
(( APPLY )) && sysctl -q -w kernel.randomize_va_space=2

# 5047-5068, 5074, 5082-5087: SELinux finding and unnecessary software.
if ps -eZ 2>/dev/null | grep -q unconfined_service_t; then
  skip "5047 has unconfined services; policy assignment requires service-by-service SELinux analysis"
fi
if (( REMOVE_PACKAGES )); then
  run dnf -y remove setroubleshoot mcstrans gdm xorg-x11-server-common avahi-autoipd avahi cups httpd nginx ypbind rsh talk
  for unit in nfs-server.service rpcbind.service rpcbind.socket rsyncd.service; do systemd_available && run systemctl mask --now "$unit" 2>/dev/null || true; done
else skip "package/service removal needs --remove-packages after workload review"; fi
write_file /etc/issue 0644 "$BANNER_TEXT"
write_file /etc/issue.net 0644 "$BANNER_TEXT"
write_file /etc/dconf/db/local.d/00-cis-media-automount 0644 '[org/gnome/desktop/media-handling]
automount=false
automount-open=false'
(( APPLY )) && have dconf && dconf update || true

# 5064: Chrony requires an approved source.
if [[ -n "$NTP_SERVERS" ]]; then
  chrony_lines="$(for s in $NTP_SERVERS; do printf 'server %s iburst\n' "$s"; done)"
  append_managed_block /etc/chrony.conf 'CIS CHRONY' "$chrony_lines" 0644
  replace_setting /etc/sysconfig/chronyd OPTIONS '"-u chrony"' '='
  if systemd_available && (( ENABLE_SERVICES )); then run systemctl enable --now chronyd.service
  else skip "chronyd activation needs --enable-services"; fi
else skip "chrony needs approved NTP_SERVERS"; fi

# 5081: bind Postfix only to loopback when installed.
if pkg_installed postfix; then
  replace_setting /etc/postfix/main.cf inet_interfaces loopback-only ' = '
  if (( ENABLE_SERVICES )) && (( APPLY )) && postfix check; then systemd_available && run systemctl restart postfix.service
  else skip "Postfix restart needs --enable-services"; fi
fi

# 5091: disable IPv6 live; grubby persists the choice for the next boot.
if (( DISABLE_IPV6 )); then
  write_file /etc/sysctl.d/60-cis-disable-ipv6.conf 0644 'net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1'
  if (( APPLY )); then sysctl -q -w net.ipv6.conf.all.disable_ipv6=1; sysctl -q -w net.ipv6.conf.default.disable_ipv6=1; fi
  if have grubby; then run grubby --update-kernel=ALL --args='ipv6.disable=1'; REBOOT_PENDING=1; fi
else skip "IPv6 disable needs --disable-ipv6 after application/network review"; fi

# 5096-5114: choose one firewall implementation. Profiles are mutually exclusive.
configure_firewalld() {
  run dnf -y install firewalld
  systemd_available && { run systemctl mask --now nftables.service 2>/dev/null || true; run systemctl enable --now firewalld.service; }
  for p in $FIREWALL_ALLOW_TCP; do run firewall-cmd --permanent --add-port="$p/tcp"; done
  for p in $FIREWALL_ALLOW_UDP; do run firewall-cmd --permanent --add-port="$p/udp"; done
  run firewall-cmd --reload
}
configure_nftables() {
  local tcp="" udp="" out_tcp="" out_udp=""
  for p in $FIREWALL_ALLOW_TCP; do tcp+="    tcp dport $p accept\n"; done
  for p in $FIREWALL_ALLOW_UDP; do udp+="    udp dport $p accept\n"; done
  for p in $FIREWALL_EGRESS_TCP; do out_tcp+="    tcp dport $p accept\n"; done
  for p in $FIREWALL_EGRESS_UDP; do out_udp+="    udp dport $p accept\n"; done
  local rules="#!/usr/sbin/nft -f
flush ruleset
table inet cis_filter {
 chain input { type filter hook input priority 0; policy drop; iifname \"lo\" accept; ip saddr 127.0.0.0/8 iifname != \"lo\" drop; ip6 saddr ::1 iifname != \"lo\" drop; ct state established,related accept; ip protocol icmp accept; ip6 nexthdr ipv6-icmp accept;
$(printf '%b' "$tcp$udp") }
 chain forward { type filter hook forward priority 0; policy drop; }
 chain output { type filter hook output priority 0; policy drop; oifname \"lo\" accept; ct state established,related accept;
$(printf '%b' "$out_tcp$out_udp") }
}"
  if (( APPLY )); then dnf -y install nftables; t="$(mktemp)"; printf '%s\n' "$rules" > "$t"; nft -c -f "$t"; rm -f "$t"; fi
  write_file /etc/sysconfig/nftables.conf 0600 "$rules"
  systemd_available && { run systemctl mask --now firewalld.service 2>/dev/null || true; run systemctl enable --now nftables.service; }
}
configure_iptables() {
  run dnf -y install iptables-services
  systemd_available && { run systemctl mask --now firewalld.service nftables.service 2>/dev/null || true; }
  if (( APPLY )); then
    iptables -P INPUT ACCEPT
    iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT
    iptables -C INPUT -s 127.0.0.0/8 ! -i lo -j DROP 2>/dev/null || iptables -I INPUT 2 -s 127.0.0.0/8 ! -i lo -j DROP
    iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    for p in $FIREWALL_ALLOW_TCP; do iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p tcp --dport "$p" -j ACCEPT; done
    for p in $FIREWALL_ALLOW_UDP; do iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p udp --dport "$p" -j ACCEPT; done
    iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o lo -j ACCEPT
    iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    for p in $FIREWALL_EGRESS_TCP; do iptables -C OUTPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 3 -p tcp --dport "$p" -j ACCEPT; done
    for p in $FIREWALL_EGRESS_UDP; do iptables -C OUTPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 3 -p udp --dport "$p" -j ACCEPT; done
    iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP; service iptables save
    if have ip6tables; then
      ip6tables -P INPUT ACCEPT
      ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -i lo -j ACCEPT
      ip6tables -C INPUT -s ::1 ! -i lo -j DROP 2>/dev/null || ip6tables -I INPUT 2 -s ::1 ! -i lo -j DROP
      ip6tables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -I INPUT 3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      for p in $FIREWALL_ALLOW_TCP; do ip6tables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p tcp --dport "$p" -j ACCEPT; done
      for p in $FIREWALL_ALLOW_UDP; do ip6tables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p udp --dport "$p" -j ACCEPT; done
      ip6tables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -o lo -j ACCEPT
      ip6tables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      for p in $FIREWALL_EGRESS_TCP; do ip6tables -C OUTPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 3 -p tcp --dport "$p" -j ACCEPT; done
      for p in $FIREWALL_EGRESS_UDP; do ip6tables -C OUTPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 3 -p udp --dport "$p" -j ACCEPT; done
      ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT DROP; service ip6tables save
    fi
  else log 'PLAN: configure stateful IPv4 loopback/default-deny rules'; fi
  systemd_available && run systemctl enable --now iptables.service
}
case "$FIREWALL_BACKEND" in
  firewalld) configure_firewalld ;; nftables) configure_nftables ;; iptables) configure_iptables ;;
  none) skip "firewall failures require one explicit --firewall-backend choice" ;;
esac

# 5118-5139: audit boot configuration and event rules.
audit_immutable() { have auditctl && auditctl -s 2>/dev/null | awk '$1=="enabled"&&$2=="2"{x=1}END{exit !x}'; }
if (( ENABLE_AUDIT )); then
  if audit_immutable; then
    skip "audit is immutable; rules cannot be changed until a scheduled reboot"
  else
    run dnf -y install audit acl
    replace_setting /etc/audit/auditd.conf max_log_file_action keep_logs
    replace_setting /etc/audit/auditd.conf disk_full_action halt
    replace_setting /etc/audit/auditd.conf disk_error_action halt
    UID_MIN="$(awk '$1=="UID_MIN"{print $2;exit}' /etc/login.defs)"; [[ "$UID_MIN" =~ ^[0-9]+$ ]] || UID_MIN=1000
    write_file /etc/audit/rules.d/60-cis.rules 0640 "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$UID_MIN -F auid!=unset -k access
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=$UID_MIN -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=$UID_MIN -F auid!=unset -k delete
-w /etc/selinux -p wa -k MAC-policy
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=$UID_MIN -F auid!=unset -k usermod
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=$UID_MIN -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=$UID_MIN -F auid!=unset -k kernel_modules"
    write_file /etc/audit/rules.d/99-finalize.rules 0640 '-e 2'
    if (( APPLY )) && [[ "$(uname -m)" != x86_64 ]]; then sed -i '/-F arch=b32/d' /etc/audit/rules.d/60-cis.rules; fi
    if (( APPLY )); then
      if ! augenrules --check || ! augenrules --load; then
        for rule in 60-cis.rules 99-finalize.rules; do
          if [[ -e "$BACKUP_DIR/etc/audit/rules.d/$rule" ]]; then
            cp -a "$BACKUP_DIR/etc/audit/rules.d/$rule" "/etc/audit/rules.d/$rule"
          else
            rm -f "/etc/audit/rules.d/$rule"
          fi
        done
        augenrules --load >/dev/null 2>&1 || true
        echo "Audit validation/load failed; persistent rules were rolled back." >&2
        exit 1
      fi
    fi
    if have grubby; then run grubby --update-kernel=ALL --args='audit=1 audit_backlog_limit=8192'; REBOOT_PENDING=1; fi
  fi
else skip "audit controls need --enable-audit; immutability prevents later live rule changes"; fi

# 5142-5154: local/remote logging.
if ! pkg_installed rsyslog; then
  (( ENABLE_SERVICES )) && run dnf -y install rsyslog || skip "rsyslog installation needs --enable-services"
fi
append_managed_block /etc/systemd/journald.conf 'CIS JOURNALD' '[Journal]
ForwardToSyslog=yes
Compress=yes
Storage=persistent' 0644
append_managed_block /etc/rsyslog.conf 'CIS RSYSLOG' '$FileCreateMode 0640' 0644
if [[ -n "$REMOTE_LOG_HOST" ]]; then
  write_file /etc/rsyslog.d/61-cis-forward.conf 0644 "*.* action(type=\"omfwd\" target=\"$REMOTE_LOG_HOST\" port=\"$REMOTE_LOG_PORT\" protocol=\"tcp\" action.resumeRetryCount=\"100\" queue.type=\"LinkedList\")"
else skip "remote rsyslog forwarding needs REMOTE_LOG_HOST"; fi
if (( ENABLE_SERVICES )); then run dnf -y install systemd-journal-remote; fi
if systemd_available && (( ENABLE_SERVICES )); then
  run systemctl enable --now rsyslog.service
  run systemctl enable systemd-journal-upload.service
  run systemctl mask --now systemd-journal-remote.socket
else skip "logging package/service activation needs --enable-services"; fi
if grep -RslE '^[[:space:]]*(\[Socket\]|ListenStream=19532|module\(load="imtcp"\)|input\(type="imtcp")' /etc/systemd/journal-remote.conf /etc/systemd/system/systemd-journal-remote.socket.d /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null | grep -q .; then
  skip "remote log receiver directives exist; review before disabling on a possible collector"
fi
if (( ENABLE_LOG_PERMS )); then run find /var/log -xdev -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +; else skip "log permission recursion needs --enable-log-permissions"; fi
if (( APPLY && ENABLE_SERVICES )) && have rsyslogd; then rsyslogd -N1 >/dev/null; systemctl reload-or-restart rsyslog.service; systemctl restart systemd-journald.service; fi

# 5156-5163: cron/at ownership and access.
[[ -e /etc/crontab ]] && { run chown root:root /etc/crontab; run chmod 0600 /etc/crontab; }
for p in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  [[ -e "$p" ]] && { run chown root:root "$p"; run chmod 0700 "$p"; }
done
write_file /etc/cron.allow 0600 ''; write_file /etc/at.allow 0600 ''
for p in /etc/cron.deny /etc/at.deny; do [[ -e "$p" ]] && run rm -f "$p"; done

# 5165, 5167, 5170, 5175-83: SSH.
if (( ENABLE_SSH )); then
  access=""; [[ -n "$SSH_ALLOW_USERS" ]] && access="AllowUsers $SSH_ALLOW_USERS"; [[ -n "$SSH_ALLOW_GROUPS" ]] && access+=$'\n'"AllowGroups $SSH_ALLOW_GROUPS"
  [[ -n "$access" ]] || { echo "--enable-ssh requires SSH_ALLOW_USERS or SSH_ALLOW_GROUPS" >&2; exit 2; }
  ssh_block="$access
PermitRootLogin no
X11Forwarding no
AllowTcpForwarding no
Banner /etc/issue.net
MaxAuthTries 4
MaxStartups 10:30:60
LoginGraceTime 60
ClientAliveInterval 900
ClientAliveCountMax 0"
  prepend_managed_block /etc/ssh/sshd_config 'CIS RHEL8' "$ssh_block" 0600
  while IFS= read -r -d '' key; do run chown root:root "$key"; run chmod 0600 "$key"; done < <(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' ! -name '*.pub' -print0)
  if (( APPLY )); then
    if sshd -t; then systemctl reload sshd.service
    else cp -a "$BACKUP_DIR/etc/ssh/sshd_config" /etc/ssh/sshd_config; echo "SSH validation failed; restored" >&2; exit 1; fi
  fi
else skip "SSH changes need --enable-ssh plus an explicit allow list"; fi

# 5185-5203: sudo, authselect/PAM, password aging, timeout, and umask.
write_file /etc/sudoers.d/00-cis 0440 'Defaults use_pty
Defaults logfile="/var/log/sudo.log"'
if (( APPLY )) && have visudo; then visudo -cf /etc/sudoers >/dev/null || exit 1; fi
if (( ENABLE_AUTH )); then
  getent group sugroup >/dev/null || run groupadd --system sugroup
  grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' /etc/pam.d/su || { (( APPLY )) && backup /etc/pam.d/su; (( APPLY )) && printf '%s\n' 'auth required pam_wheel.so use_uid group=sugroup' >> /etc/pam.d/su || log 'PLAN: restrict su to sugroup'; }
  if have authselect; then
    current_profile="$(authselect current -r 2>/dev/null | head -n1 || true)"
    if [[ "$current_profile" != custom/* ]]; then
      base_profile="${current_profile:-sssd}"
      run authselect create-profile cis -b "$base_profile" --symlink-meta
      run authselect select custom/cis with-faillock without-nullok --force
      current_profile='custom/cis'
    fi
    run authselect enable-feature with-faillock
    run authselect apply-changes
  fi
  replace_setting /etc/security/pwquality.conf minlen 14
  replace_setting /etc/security/pwquality.conf minclass 4
  if ! grep -Eq '^[[:space:]]*enforce_for_root([[:space:]]|$)' /etc/security/pwquality.conf 2>/dev/null; then
    if (( APPLY )); then backup /etc/security/pwquality.conf; printf '%s\n' 'enforce_for_root' >> /etc/security/pwquality.conf
    else log 'PLAN: add enforce_for_root to /etc/security/pwquality.conf'; fi
  fi
  write_file /etc/security/faillock.conf 0644 'deny = 5
unlock_time = 900'
  auth_profile_path="/etc/authselect/${current_profile:-custom/cis}"
  for f in "$auth_profile_path/system-auth" "$auth_profile_path/password-auth"; do
    [[ -f "$f" ]] || continue
    if (( APPLY )); then
      backup "$f"
      sed -ri '/pam_pwquality\.so/ { /try_first_pass/! s/$/ try_first_pass/; /retry=/! s/$/ retry=3/; /enforce_for_root/! s/$/ enforce_for_root/; }' "$f"
      sed -ri '/pam_faillock\.so/ { /deny=/! s/$/ deny=5/; /unlock_time=/! s/$/ unlock_time=900/; }' "$f"
      sed -ri '/pam_pwhistory\.so/ { /remember=/! s/$/ remember=5/; }' "$f"
      sed -ri '/pam_unix\.so/ { /remember=/! s/$/ remember=5/; }' "$f"
    fi
  done
  (( APPLY )) && have authselect && authselect apply-changes
  replace_setting /etc/login.defs PASS_MAX_DAYS 365 ' '
  replace_setting /etc/login.defs PASS_MIN_DAYS 7 ' '
  replace_setting /etc/login.defs UMASK 027 ' '
  replace_setting /etc/login.defs USERGROUPS_ENAB no ' '
  if (( APPLY )); then
    useradd -D -f 30
    while IFS=: read -r u hash _ min max _ inactive _; do
      [[ "$hash" == \$*\$* ]] || continue
      chage --maxdays 365 --mindays 7 --inactive 30 "$u"
    done < /etc/shadow
  else log 'PLAN: update password aging for accounts with password hashes'; fi
  write_file /etc/profile.d/60-cis-session.sh 0644 'readonly TMOUT=900 ; export TMOUT
umask 027'
else skip "authselect/PAM/account changes need --enable-auth and console recovery access"; fi

# 5208
if [[ -e /etc/passwd- ]]; then run chown root:root /etc/passwd-; run chmod 0600 /etc/passwd-; fi

log "Completed. Configuration units: $CHANGED; skipped/manual items: $SKIPPED."
if (( APPLY )); then
  log "Backups: $BACKUP_DIR"
  if (( REBOOT_PENDING )); then log "REBOOT PENDING: boot/module controls need a scheduled reboot; the script did not reboot."; fi
else log "No changes made. Review the preview, then use --apply with selected high-impact flags."; fi
