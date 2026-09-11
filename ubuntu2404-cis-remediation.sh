#!/usr/bin/env bash
# Ubuntu 24.04 CIS remediation tool generated from 01-checks-6-.csv.
# Scope: all 121 failed controls in that export. Run with --audit first.

set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
MODE="audit"
ASSUME_YES=0

# High-impact gates. These remain off until explicitly approved.
APPLY_MODULE_DENYLIST="${APPLY_MODULE_DENYLIST:-0}"
APPLY_STORAGE_OPTIONS="${APPLY_STORAGE_OPTIONS:-0}"
APPLY_APPARMOR_ENFORCE="${APPLY_APPARMOR_ENFORCE:-0}"
APPLY_GRUB_PASSWORD="${APPLY_GRUB_PASSWORD:-0}"
APPLY_PACKAGE_REMOVAL="${APPLY_PACKAGE_REMOVAL:-0}"
APPLY_FIREWALL="${APPLY_FIREWALL:-0}"
APPLY_SSH="${APPLY_SSH:-0}"
APPLY_PAM="${APPLY_PAM:-0}"
APPLY_EXISTING_USERS="${APPLY_EXISTING_USERS:-0}"
APPLY_RSYSLOG_RECEIVER_DISABLE="${APPLY_RSYSLOG_RECEIVER_DISABLE:-0}"
APPLY_AIDE_INIT="${APPLY_AIDE_INIT:-0}"

# Site-specific values.
NTP_SERVERS="${NTP_SERVERS:-}"
GRUB_SUPERUSER="${GRUB_SUPERUSER:-}"
GRUB_PBKDF2_HASH="${GRUB_PBKDF2_HASH:-}"
SSH_PORT="${SSH_PORT:-22}"
SSH_ALLOW_FROM="${SSH_ALLOW_FROM:-}"
UFW_OUTBOUND_PORTS="${UFW_OUTBOUND_PORTS:-53/udp 53/tcp 80/tcp 123/udp 443/tcp}"
CRON_ALLOWED_USERS="${CRON_ALLOWED_USERS:-root}"
SU_GROUP="${SU_GROUP:-sugroup}"
REMOTE_LOG_HOST="${REMOTE_LOG_HOST:-}"
REMOTE_LOG_PORT="${REMOTE_LOG_PORT:-6514}"
REMOTE_LOG_CA_FILE="${REMOTE_LOG_CA_FILE:-}"
REMOTE_LOG_CERT_FILE="${REMOTE_LOG_CERT_FILE:-}"
REMOTE_LOG_KEY_FILE="${REMOTE_LOG_KEY_FILE:-}"
JOURNAL_UPLOAD_URL="${JOURNAL_UPLOAD_URL:-}"
JOURNAL_UPLOAD_CA="${JOURNAL_UPLOAD_CA:-}"
JOURNAL_UPLOAD_CERT="${JOURNAL_UPLOAD_CERT:-}"
JOURNAL_UPLOAD_KEY="${JOURNAL_UPLOAD_KEY:-}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/sentinel-ubuntu2404-cis-${STAMP}}"
LOG_FILE="${LOG_FILE:-/var/log/sentinel-ubuntu2404-cis-${STAMP}.log}"
MANUAL_FILE="${MANUAL_FILE:-/var/log/sentinel-ubuntu2404-cis-manual-${STAMP}.txt}"

# Exact manifest of all failed scanner IDs in 01-checks-6-.csv.
CONTROL_IDS=(
  35506 35509 35513 35518 35519 35520 35521 35522 35523 35524 35525 35526
  35527 35528 35529 35530 35531 35532 35533 35534 35535 35538 35539 35540
  35543 35545 35552 35573 35585 35587 35588 35591 35592 35600 35604 35605
  35606 35607 35616 35623 35624 35626 35627 35629 35631 35632 35633 35634
  35635 35636 35637 35638 35639 35640 35644 35646 35647 35652 35654 35657
  35664 35668 35672 35673 35675 35676 35677 35678 35679 35680 35681 35682
  35683 35687 35688 35689 35690 35694 35695 35698 35703 35705 35708 35709
  35710 35711 35714 35715 35720 35721 35722 35725 35726 35728 35729 35730
  35731 35732 35733 35734 35735 35736 35737 35738 35739 35740 35741 35742
  35743 35744 35745 35746 35747 35748 35755 35760 35765 35766 35767 35768
  35770
)

usage() {
  printf '%s\n' \
    "Usage: $0 [--audit|--apply] [--yes] [--help]" \
    "" \
    "  --audit  Show current state and planned changes; write nothing (default)." \
    "  --apply  Apply low-risk changes and any explicitly enabled gates." \
    "  --yes    Skip the APPLY confirmation prompt." \
    "" \
    "Examples:" \
    "  sudo $0 --audit" \
    "  sudo env NTP_SERVERS='ntp1.example ntp2.example' $0 --apply" \
    "  sudo env APPLY_FIREWALL=1 SSH_ALLOW_FROM='10.0.0.0/8' $0 --apply" \
    "" \
    "Review the variables at the top of the script before production use."
}

while (($#)); do
  case "$1" in
    --audit) MODE="audit" ;;
    --apply) MODE="apply" ;;
    --yes) ASSUME_YES=1 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ ${EUID} -ne 0 ]]; then
  printf 'Run as root.\n' >&2
  exit 1
fi

source /etc/os-release 2>/dev/null || true
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
  printf 'Refusing to run: expected Ubuntu 24.04, found ID=%s VERSION_ID=%s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE" "$MANUAL_FILE"
chmod 0600 "$LOG_FILE" "$MANUAL_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
manual() { log "MANUAL: $*"; printf '%s\n' "$*" >> "$MANUAL_FILE"; }
trap 'rc=$?; log "ERROR line $LINENO command=$BASH_COMMAND status=$rc"; exit "$rc"' ERR
run() {
  if [[ "$MODE" == "audit" ]]; then
    printf '[PLAN]'; printf ' %q' "$@"; printf '\n'
  else
    printf '[RUN ]'; printf ' %q' "$@"; printf '\n'
    "$@"
  fi
}
backup() {
  local path="$1"
  [[ -e "$path" || -L "$path" ]] || return 0
  if [[ "$MODE" == "apply" ]]; then
    mkdir -p "$BACKUP_DIR$(dirname "$path")"
    cp -a -- "$path" "$BACKUP_DIR$path"
  fi
}
write_file() {
  local path="$1" mode="$2" content="$3" tmp
  if [[ "$MODE" == "audit" ]]; then log "PLAN write $path mode=$mode"; return 0; fi
  backup "$path"
  mkdir -p "$(dirname "$path")"
  tmp="$(mktemp "${path}.XXXXXX")"
  printf '%s\n' "$content" > "$tmp"
  chmod "$mode" "$tmp"
  chown root:root "$tmp"
  mv -f "$tmp" "$path"
}
set_key_value() {
  local path="$1" key="$2" value="$3" sep="${4:- = }" tmp
  if [[ "$MODE" == "audit" ]]; then log "PLAN set $key$value in $path"; return 0; fi
  backup "$path"; mkdir -p "$(dirname "$path")"; touch "$path"
  tmp="$(mktemp "${path}.XXXXXX")"
  awk -v k="$key" -v v="$value" -v s="$sep" '
    BEGIN{done=0}
    $0 ~ "^[[:space:]#]*" k "[[:space:]]*=" {if(!done){print k s v; done=1}; next}
    $0 ~ "^[[:space:]#]*" k "[[:space:]]+" {if(!done){print k s v; done=1}; next}
    {print}
    END{if(!done) print k s v}
  ' "$path" > "$tmp"
  chmod --reference="$path" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
  chown --reference="$path" "$tmp" 2>/dev/null || chown root:root "$tmp"
  mv -f "$tmp" "$path"
}
append_managed_block() {
  local path="$1" name="$2" content="$3" begin="# BEGIN SENTINEL $name" end="# END SENTINEL $name" tmp
  if [[ "$MODE" == "audit" ]]; then log "PLAN update managed block $name in $path"; return 0; fi
  backup "$path"; mkdir -p "$(dirname "$path")"; touch "$path"
  tmp="$(mktemp "${path}.XXXXXX")"
  awk -v b="$begin" -v e="$end" '$0==b{skip=1;next} $0==e{skip=0;next} !skip{print}' "$path" > "$tmp"
  printf '\n%s\n%s\n%s\n' "$begin" "$content" "$end" >> "$tmp"
  chmod --reference="$path" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
  chown --reference="$path" "$tmp" 2>/dev/null || chown root:root "$tmp"
  mv -f "$tmp" "$path"
}
apt_install() { run env DEBIAN_FRONTEND=noninteractive apt-get -y install "$@"; }
apt_purge() { run env DEBIAN_FRONTEND=noninteractive apt-get -y purge "$@"; }
apt_purge_installed() {
  local package installed=()
  for package in "$@"; do dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | grep -qx installed && installed+=("$package"); done
  ((${#installed[@]} == 0)) || apt_purge "${installed[@]}"
}
enable_now() { run systemctl unmask "$@"; run systemctl enable --now "$@"; }
mask_now() { run systemctl disable --now "$@"; run systemctl mask "$@"; }

confirm_apply() {
  [[ "$MODE" == "apply" ]] || return 0
  [[ "$ASSUME_YES" -eq 1 ]] && return 0
  printf 'Apply enabled Ubuntu 24.04 remediations? Type APPLY: '
  read -r answer
  [[ "$answer" == "APPLY" ]] || { log "Cancelled"; exit 1; }
}

preflight() {
  log "Sentinel-AI Ubuntu 24.04 CIS remediation v$VERSION mode=$MODE"
  log "Backup directory: $BACKUP_DIR"
  log "Manual action log: $MANUAL_FILE"
  [[ -n "${SSH_CONNECTION:-}" ]] && log "WARNING: active SSH session detected; firewall, SSH, PAM, or reboot changes can lock out access."
  df -h / /var /tmp 2>/dev/null || true
  findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS / /tmp /home /var /var/tmp /var/log /var/log/audit 2>/dev/null || true
  if [[ "$MODE" == "apply" ]]; then
    mkdir -p "$BACKUP_DIR"; chmod 0700 "$BACKUP_DIR"
    run apt-get update
  fi
}

disable_module() {
  local module="$1"
  write_file "/etc/modprobe.d/99-cis-${module}.conf" 0644 "install $module /bin/false
blacklist $module"
  if lsmod | awk '{print $1}' | grep -Fxq "$module"; then
    manual "Module $module is loaded. Confirm it is unused, preserve dependent workload state, and unload it during a maintenance window."
  fi
}
remediate_modules() {
  log "Controls 35506, 35509, 35604-35607: unused filesystem and network protocol modules"
  if [[ "$APPLY_MODULE_DENYLIST" != "1" ]]; then
    manual "Set APPLY_MODULE_DENYLIST=1 only after confirming Snap, containers, network filesystems, clustered filesystems, and SCTP applications do not require the listed modules."
    return
  fi
  local module
  for module in squashfs afs ceph cifs exfat ext fat fscache fuse gfs2 nfs_common nfsd smbfs_common dccp tipc rds sctp; do
    disable_module "$module"
  done
}

mount_is_separate() {
  findmnt -rn -M "$1" >/dev/null 2>&1 && [[ "$(findmnt -rn -o TARGET -M "$1" 2>/dev/null)" == "$1" ]]
}
ensure_mount_options() {
  local target="$1" options="$2"
  if ! mount_is_separate "$target"; then
    manual "$target is not separately mounted. Create and migrate an approved LVM/filesystem, preserve ownership and AppArmor-relevant paths, update /etc/fstab, reboot, and validate."
    return
  fi
  if [[ "$APPLY_STORAGE_OPTIONS" != "1" ]]; then
    manual "$target is separate; set APPLY_STORAGE_OPTIONS=1 after testing options '$options' with its applications."
    return
  fi
  if ! awk -v t="$target" '$1 !~ /^#/ && $2==t{found=1} END{exit !found}' /etc/fstab; then
    manual "$target has no direct /etc/fstab entry. Add '$options' to its native mount unit or approved mount configuration."
    return
  fi
  if [[ "$MODE" == "apply" ]]; then
    backup /etc/fstab
    local tmp; tmp="$(mktemp /etc/fstab.XXXXXX)"
    awk -v t="$target" -v need="$options" '
      BEGIN{OFS="\t"}
      $1 !~ /^#/ && $2==t {
        n=split(need,a,",");
        for(i=1;i<=n;i++) if("," $4 "," !~ "," a[i] ",") $4=$4 "," a[i]
      }
      {print}
    ' /etc/fstab > "$tmp"
    chmod 0644 "$tmp"; chown root:root "$tmp"; mv -f "$tmp" /etc/fstab
  else
    log "PLAN add $options to /etc/fstab for $target"
  fi
  run mount -o "remount,$options" "$target"
}
remediate_mounts() {
  log "Controls 35513, 35518-35535: filesystem separation and mount options"
  ensure_mount_options /tmp noexec
  ensure_mount_options /home nodev,nosuid
  ensure_mount_options /var nodev,nosuid
  ensure_mount_options /var/tmp nodev,nosuid,noexec
  ensure_mount_options /var/log nodev,nosuid,noexec
  ensure_mount_options /var/log/audit nodev,nosuid,noexec
}

remediate_apparmor_grub_core() {
  log "Controls 35538-35545: AppArmor, GRUB authentication, core dumps, apport"
  apt_install apparmor apparmor-utils
  enable_now apparmor.service
  if [[ "$APPLY_APPARMOR_ENFORCE" == "1" ]]; then
    if [[ "$MODE" == "apply" ]]; then
      local profile
      while IFS= read -r -d '' profile; do aa-enforce "$profile" || manual "Could not enforce AppArmor profile file $profile; inspect syntax and application denials."; done < <(find /etc/apparmor.d -maxdepth 1 -type f -print0)
    else
      log "PLAN set loadable AppArmor profiles to enforce mode"
    fi
  else
    manual "Controls 35538/35539: review complain-mode and unconfined processes, then set APPLY_APPARMOR_ENFORCE=1. Enforcing untested profiles can block applications."
  fi
  if [[ "$APPLY_GRUB_PASSWORD" == "1" ]]; then
    [[ -n "$GRUB_SUPERUSER" && "$GRUB_PBKDF2_HASH" == grub.pbkdf2.sha512.* ]] || { log "GRUB_SUPERUSER and a valid grub.pbkdf2.sha512 hash are required"; exit 2; }
    write_file /etc/grub.d/01_users 0700 "#!/bin/sh
cat <<'EOF'
set superusers=\"$GRUB_SUPERUSER\"
password_pbkdf2 $GRUB_SUPERUSER $GRUB_PBKDF2_HASH
EOF"
    if [[ "$MODE" == "apply" ]]; then
      backup /etc/grub.d/10_linux
      sed -ri '/^[[:space:]]*CLASS=/ { /--unrestricted/! s/"$/ --unrestricted"/; }' /etc/grub.d/10_linux
    else log "PLAN mark normal Linux menu entries unrestricted while protecting GRUB editing"; fi
    run update-grub
  else
    manual "Control 35540: generate a GRUB PBKDF2 hash offline, preserve console recovery, then set APPLY_GRUB_PASSWORD=1 with GRUB_SUPERUSER and GRUB_PBKDF2_HASH."
  fi
  write_file /etc/security/limits.d/60-cis-core.conf 0644 "* hard core 0"
  write_file /etc/sysctl.d/60-cis-core.conf 0644 "fs.suid_dumpable = 0"
  write_file /etc/systemd/coredump.conf.d/60-cis.conf 0644 "[Coredump]
Storage=none
ProcessSizeMax=0"
  write_file /etc/default/apport 0644 "enabled=0"
  systemctl list-unit-files apport.service >/dev/null 2>&1 && mask_now apport.service || true
  run sysctl --system
  run systemctl daemon-reload
}

remediate_packages_time_cron() {
  log "Controls 35552, 35573, 35585, 35587, 35588, 35591, 35592, 35600"
  mask_now rsync.service rsync.socket 2>/dev/null || true
  apt_purge_installed telnet inetutils-telnet ftp tnftp inetutils-ftp
  if [[ "$APPLY_PACKAGE_REMOVAL" == "1" ]]; then
    apt_purge gdm3
  else
    manual "Control 35552: set APPLY_PACKAGE_REMOVAL=1 only if the system does not require a graphical login."
  fi
  apt_install chrony
  if [[ -n "$NTP_SERVERS" ]]; then
    local sources="# Organization-approved time sources" server
    local ntp_array=()
    IFS=' ' read -r -a ntp_array <<< "$NTP_SERVERS"
    for server in "${ntp_array[@]}"; do sources+=$'\n'"server $server iburst"; done
    write_file /etc/chrony/sources.d/60-cis.sources 0644 "$sources"
  else
    manual "Controls 35588/35591/35592: supply organization-approved NTP_SERVERS; existing sources were retained."
  fi
  write_file /etc/chrony/conf.d/60-cis-user.conf 0644 "user _chrony"
  systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1 && mask_now systemd-timesyncd.service || true
  enable_now chrony.service
  write_file /etc/cron.allow 0640 "$(tr ' ' '\n' <<<"$CRON_ALLOWED_USERS")"
  local cron_group=root
  getent group crontab >/dev/null && cron_group=crontab
  run chown "root:$cron_group" /etc/cron.allow
  if [[ -e /etc/cron.deny ]]; then
    backup /etc/cron.deny
    run chmod 0640 /etc/cron.deny
    run chown "root:$cron_group" /etc/cron.deny
  fi
}

remediate_network_firewall() {
  log "Controls 35616, 35623-35639: packet logging and one firewall implementation"
  write_file /etc/sysctl.d/60-cis-martians.conf 0644 "net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1"
  run sysctl --system
  if [[ "$APPLY_FIREWALL" != "1" ]]; then
    manual "Controls 35623-35639: UFW is selected for Ubuntu. Confirm console access, inbound management sources, and outbound application requirements, then set APPLY_FIREWALL=1. nftables/iptables branches should become not applicable."
    return
  fi
  apt_install ufw
  backup /etc/ufw
  systemctl list-unit-files nftables.service >/dev/null 2>&1 && mask_now nftables.service || true
  run ufw default deny incoming
  run ufw default deny outgoing
  run ufw default deny routed
  run ufw allow in on lo
  run ufw allow out on lo
  run ufw deny in from 127.0.0.0/8
  run ufw deny in from ::1
  if [[ -n "$SSH_ALLOW_FROM" ]]; then
    run ufw allow from "$SSH_ALLOW_FROM" to any port "$SSH_PORT" proto tcp
  else
    manual "SSH_ALLOW_FROM is empty; SSH port $SSH_PORT will be reachable from any source to preserve access. Restrict it to approved management networks."
    run ufw allow "$SSH_PORT/tcp"
  fi
  local spec outbound_array=()
  IFS=' ' read -r -a outbound_array <<< "$UFW_OUTBOUND_PORTS"
  for spec in "${outbound_array[@]}"; do run ufw allow out "$spec"; done
  run ufw logging on
  run ufw --force enable
  enable_now ufw.service
}

remediate_ssh_sudo_su() {
  log "Controls 35640, 35644, 35646, 35647, 35652, 35654, 35657, 35664, 35668"
  write_file /etc/issue.net 0644 "Authorized users only. Activity may be monitored and reported."
  write_file /etc/sudoers.d/60-cis-logfile 0440 "Defaults logfile=\"/var/log/sudo.log\""
  if [[ "$MODE" == "apply" ]]; then run visudo -cf /etc/sudoers; fi
  if ! getent group "$SU_GROUP" >/dev/null; then run groupadd "$SU_GROUP"; fi
  if [[ "$MODE" == "apply" ]]; then
    backup /etc/pam.d/su
    if ! grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid.*group=' /etc/pam.d/su; then
      printf '%s\n' "auth required pam_wheel.so use_uid group=$SU_GROUP" >> /etc/pam.d/su
    fi
  else log "PLAN restrict su to group $SU_GROUP"; fi
  if [[ "$APPLY_SSH" != "1" ]]; then
    manual "Controls 35640/35644/35646/35647/35652/35654/35657: set APPLY_SSH=1 with console access after confirming forwarding is not required."
    return
  fi
  local cfg="Banner /etc/issue.net
ClientAliveInterval 15
ClientAliveCountMax 3
DisableForwarding yes
LoginGraceTime 60
MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com
MaxStartups 10:30:60"
  write_file /etc/ssh/sshd_config.d/00-cis.conf 0600 "$cfg"
  run chown root:root /etc/ssh/sshd_config
  run chmod 0600 /etc/ssh/sshd_config
  if [[ "$MODE" == "apply" ]]; then
    find /etc/ssh/sshd_config.d -type f -name '*.conf' -exec chown root:root {} + -exec chmod 0600 {} +
    if sshd -t; then
      run systemctl reload ssh.service
    else
      log "ERROR: sshd validation failed; restoring SSH configuration"
      if [[ -e "$BACKUP_DIR/etc/ssh/sshd_config.d/00-cis.conf" ]]; then
        cp -a "$BACKUP_DIR/etc/ssh/sshd_config.d/00-cis.conf" /etc/ssh/sshd_config.d/00-cis.conf
      else
        rm -f /etc/ssh/sshd_config.d/00-cis.conf
      fi
      [[ -e "$BACKUP_DIR/etc/ssh/sshd_config" ]] && cp -a "$BACKUP_DIR/etc/ssh/sshd_config" /etc/ssh/sshd_config
      exit 1
    fi
  fi
}

remediate_pam_passwords() {
  log "Controls 35672-35690: PAM modules, faillock, quality, and history"
  apt_install libpam-modules libpam-runtime libpam-pwquality
  write_file /etc/security/faillock.conf 0644 "deny = 5
unlock_time = 900
even_deny_root
root_unlock_time = 60"
  write_file /etc/security/pwquality.conf 0644 "difok = 2
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
maxsequence = 3
dictcheck = 1
enforcing = 1"
  if [[ "$APPLY_PAM" != "1" ]]; then
    manual "Controls 35672/35673/35675 and enforcement controls: PAM policy files are staged, but set APPLY_PAM=1 only with console recovery after testing local and directory-backed authentication."
    return
  fi
  write_file /usr/share/pam-configs/faillock 0644 "Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail"
  write_file /usr/share/pam-configs/faillock_notify 0644 "Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth
Account-Type: Primary
Account:
 required pam_faillock.so"
  write_file /usr/share/pam-configs/pwhistory 0644 "Name: Password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
 requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok"
  if [[ "$MODE" == "apply" ]]; then
    backup /usr/share/pam-configs/unix
    local pam_file
    for pam_file in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do backup "$pam_file"; done
    sed -ri 's/(pam_unix\.so[^#\n]*)\bnullok\b/\1/g' /usr/share/pam-configs/unix
    local profile
    for profile in unix faillock faillock_notify pwhistory pwquality; do
      env DEBIAN_FRONTEND=noninteractive pam-auth-update --enable "$profile"
    done
    if grep -RHE '^[^#].*pam_unix\.so.*\bnullok\b' /etc/pam.d/common-*; then
      log "ERROR: nullok remains in common PAM files; manual review required"
      exit 1
    fi
  else log "PLAN enable unix, faillock, faillock_notify, pwhistory, and pwquality with pam-auth-update"; fi
}

remediate_accounts_shell() {
  log "Controls 35694, 35695, 35698, 35703, 35705: aging, inactivity, umask, timeout"
  set_key_value /etc/login.defs PASS_MAX_DAYS 365 ' '
  set_key_value /etc/login.defs PASS_MIN_DAYS 7 ' '
  run useradd -D -f 30
  if [[ "$APPLY_EXISTING_USERS" == "1" ]]; then
    local user
    while IFS=: read -r user _ uid _; do
      [[ "$uid" -ge 1000 && "$user" != "nobody" ]] || continue
      run chage --maxdays 365 --mindays 7 --inactive 30 "$user"
    done < /etc/passwd
  else
    manual "Controls 35694/35695/35698: defaults are fixed; set APPLY_EXISTING_USERS=1 after reviewing human and service accounts."
  fi
  write_file /etc/profile.d/99-cis-root-umask.sh 0644 "if [ \"\$(id -u)\" -eq 0 ]; then umask 027; fi"
  write_file /etc/profile.d/99-cis-timeout.sh 0644 "readonly TMOUT=900
export TMOUT"
}

remediate_logging() {
  log "Controls 35708-35722: journal rotation/upload, rsyslog forwarding, logfile access"
  apt_install systemd-journal-remote rsyslog rsyslog-gnutls
  write_file /etc/systemd/journald.conf.d/60-cis.conf 0644 "[Journal]
SystemMaxUse=1G
SystemKeepFree=500M
RuntimeMaxUse=200M
RuntimeKeepFree=50M
MaxFileSec=1month
Compress=yes
Storage=persistent"
  if [[ -n "$JOURNAL_UPLOAD_URL" && -n "$JOURNAL_UPLOAD_CA" && -n "$JOURNAL_UPLOAD_CERT" && -n "$JOURNAL_UPLOAD_KEY" ]]; then
    for file in "$JOURNAL_UPLOAD_CA" "$JOURNAL_UPLOAD_CERT" "$JOURNAL_UPLOAD_KEY"; do [[ -r "$file" ]] || { log "Journal upload TLS file is not readable: $file"; exit 2; }; done
    write_file /etc/systemd/journal-upload.conf.d/60-cis.conf 0600 "[Upload]
URL=$JOURNAL_UPLOAD_URL
ServerKeyFile=$JOURNAL_UPLOAD_KEY
ServerCertificateFile=$JOURNAL_UPLOAD_CERT
TrustedCertificateFile=$JOURNAL_UPLOAD_CA"
    enable_now systemd-journal-upload.service
  else
    manual "Controls 35710/35711: set JOURNAL_UPLOAD_URL, JOURNAL_UPLOAD_CA, JOURNAL_UPLOAD_CERT, and JOURNAL_UPLOAD_KEY to approved values before enabling journal upload."
  fi
  enable_now rsyslog.service
  if [[ -n "$REMOTE_LOG_HOST" && -n "$REMOTE_LOG_CA_FILE" ]]; then
    [[ -r "$REMOTE_LOG_CA_FILE" ]] || { log "Rsyslog CA file is not readable: $REMOTE_LOG_CA_FILE"; exit 2; }
    [[ -z "$REMOTE_LOG_CERT_FILE" || -r "$REMOTE_LOG_CERT_FILE" ]] || { log "Rsyslog certificate is not readable: $REMOTE_LOG_CERT_FILE"; exit 2; }
    [[ -z "$REMOTE_LOG_KEY_FILE" || -r "$REMOTE_LOG_KEY_FILE" ]] || { log "Rsyslog key is not readable: $REMOTE_LOG_KEY_FILE"; exit 2; }
    local tls="global(DefaultNetstreamDriverCAFile=\"$REMOTE_LOG_CA_FILE\")"
    [[ -n "$REMOTE_LOG_CERT_FILE" ]] && tls+=$'\n'"global(DefaultNetstreamDriverCertFile=\"$REMOTE_LOG_CERT_FILE\")"
    [[ -n "$REMOTE_LOG_KEY_FILE" ]] && tls+=$'\n'"global(DefaultNetstreamDriverKeyFile=\"$REMOTE_LOG_KEY_FILE\")"
    write_file /etc/rsyslog.d/60-cis-remote.conf 0640 "$tls
*.* action(type=\"omfwd\" target=\"$REMOTE_LOG_HOST\" port=\"$REMOTE_LOG_PORT\" protocol=\"tcp\" StreamDriver=\"gtls\" StreamDriverMode=\"1\" StreamDriverAuthMode=\"x509/name\" StreamDriverPermittedPeers=\"$REMOTE_LOG_HOST\" action.resumeRetryCount=\"-1\" queue.type=\"linkedList\" queue.filename=\"cis_fwd\")"
  else
    manual "Control 35720: set REMOTE_LOG_HOST and REMOTE_LOG_CA_FILE for authenticated TLS rsyslog forwarding."
  fi
  if [[ "$APPLY_RSYSLOG_RECEIVER_DISABLE" == "1" && "$MODE" == "apply" ]]; then
    local file tmp
    while IFS= read -r -d '' file; do
      grep -Eq '(^|[[:space:]])(module\(load="im(tcp|udp)"|input\(type="im(tcp|udp)"|\$ModLoad[[:space:]]+im(tcp|udp)|\$(InputTCPServerRun|UDPServerRun))' "$file" || continue
      backup "$file"; tmp="$(mktemp "${file}.XXXXXX")"
      sed -E '/(^|[[:space:]])(module\(load="im(tcp|udp)"|input\(type="im(tcp|udp)"|\$ModLoad[[:space:]]+im(tcp|udp)|\$(InputTCPServerRun|UDPServerRun))/ s/^/# disabled by Sentinel CIS: /' "$file" > "$tmp"
      chmod --reference="$file" "$tmp"; chown --reference="$file" "$tmp"; mv -f "$tmp" "$file"
    done < <(find /etc -maxdepth 3 -type f \( -path '/etc/rsyslog.conf' -o -path '/etc/rsyslog.d/*.conf' \) -print0)
  else
    manual "Control 35721: confirm this host is not an approved log receiver, then set APPLY_RSYSLOG_RECEIVER_DISABLE=1 to disable inbound rsyslog listeners."
  fi
  if [[ "$MODE" == "apply" ]]; then
    run rsyslogd -N1
    run systemctl restart systemd-journald rsyslog
    find /var/log -xdev -type f -perm /0137 -print -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
  else
    log "PLAN validate rsyslog and remove excessive group-write/execute and all other permissions from regular log files"
  fi
}

add_audit_rule() {
  local rule="$1"
  grep -Fqx -- "$rule" <<<"$AUDIT_RULES" || AUDIT_RULES+=$'\n'"$rule"
}
remediate_audit() {
  log "Controls 35725-35760: audit boot, retention, event rules, tool modes, AIDE integrity"
  apt_install auditd audispd-plugins aide
  write_file /etc/default/grub.d/60-cis-audit.cfg 0644 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1 audit_backlog_limit=8192"'
  run update-grub
  set_key_value /etc/audit/auditd.conf max_log_file_action keep_logs ' = '
  set_key_value /etc/audit/auditd.conf space_left_action email ' = '
  set_key_value /etc/audit/auditd.conf action_mail_acct root ' = '
  set_key_value /etc/audit/auditd.conf admin_space_left_action halt ' = '
  set_key_value /etc/audit/auditd.conf disk_full_action halt ' = '
  set_key_value /etc/audit/auditd.conf disk_error_action halt ' = '
  [[ -d /run/faillock ]] || run install -d -o root -g root -m 0755 /run/faillock
  [[ -d /etc/netplan ]] || run install -d -o root -g root -m 0755 /etc/netplan
  [[ -e /var/log/sudo.log ]] || run install -o root -g adm -m 0640 /dev/null /var/log/sudo.log
  [[ -e /etc/security/opasswd ]] || run install -o root -g root -m 0600 /dev/null /etc/security/opasswd
  local uid_min; uid_min="$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/{print $2;exit}' /etc/login.defs)"; uid_min="${uid_min:-1000}"
  AUDIT_RULES="# Managed by Sentinel-AI Ubuntu 24.04 CIS remediation
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k sudo_log_file
-w /etc/localtime -p wa -k time-change
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy"
  local arch arches=(b64)
  [[ "$(uname -m)" == "x86_64" ]] && arches+=(b32)
  for arch in "${arches[@]}"; do
    add_audit_rule "-a always,exit -F arch=$arch -C euid!=uid -F auid!=4294967295 -S execve -k user_emulation"
    add_audit_rule "-a always,exit -F arch=$arch -S adjtimex,settimeofday,clock_settime -k time-change"
    add_audit_rule "-a always,exit -F arch=$arch -S sethostname,setdomainname -k system-locale"
    add_audit_rule "-a always,exit -F arch=$arch -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$uid_min -F auid!=4294967295 -k access"
    add_audit_rule "-a always,exit -F arch=$arch -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$uid_min -F auid!=4294967295 -k access"
    add_audit_rule "-a always,exit -F arch=$arch -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$uid_min -F auid!=4294967295 -k perm_mod"
    add_audit_rule "-a always,exit -F arch=$arch -S mount -F auid>=$uid_min -F auid!=4294967295 -k mounts"
    add_audit_rule "-a always,exit -F arch=$arch -S unlink,unlinkat,rename,renameat -F auid>=$uid_min -F auid!=4294967295 -k delete"
    add_audit_rule "-a always,exit -F arch=$arch -S init_module,finit_module,delete_module -F auid>=$uid_min -F auid!=4294967295 -k modules"
  done
  local cmd key path
  while IFS=' ' read -r cmd key; do
    path="$(command -v "$cmd" 2>/dev/null || true)"
    [[ -n "$path" ]] && add_audit_rule "-a always,exit -F path=$path -F perm=x -F auid>=$uid_min -F auid!=4294967295 -k $key"
  done <<'COMMANDS'
chcon perm_chng
setfacl perm_chng
chacl perm_chng
usermod usermod
kmod modules
COMMANDS
  write_file /etc/audit/rules.d/60-cis.rules 0600 "$AUDIT_RULES"
  enable_now auditd.service
  if [[ "$MODE" == "apply" ]]; then run augenrules --load; run augenrules --check; fi
  local tool aide_lines="" real
  for tool in auditctl auditd ausearch aureport autrace augenrules; do
    path="$(command -v "$tool" 2>/dev/null || true)"
    [[ -n "$path" ]] || continue
    real="$(readlink -f "$path")"
    run chmod go-w "$real"
    aide_lines+="$real p+i+n+u+g+s+b+acl+xattrs+sha512"$'\n'
  done
  append_managed_block /etc/aide/aide.conf AUDIT_TOOLS "$aide_lines"
  if [[ "$APPLY_AIDE_INIT" == "1" ]]; then
    run aideinit
  else
    manual "Control 35760: AIDE rules are installed. Set APPLY_AIDE_INIT=1 during a maintenance window to rebuild the integrity baseline after validating all authorized changes."
  fi
}

remediate_sensitive_files() {
  log "Controls 35765-35770: shadow, gshadow, and password history file permissions"
  local file
  for file in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-; do
    [[ -e "$file" ]] || { manual "$file is absent; verify expected package behavior."; continue; }
    run chown root:shadow "$file"
    run chmod 0640 "$file"
  done
  for file in /etc/security/opasswd /etc/security/opasswd.old; do
    [[ -e "$file" ]] || continue
    run chown root:root "$file"
    run chmod 0600 "$file"
  done
}

control_status() {
  cat <<'MAP'
35506,35509,35604-35607: guarded by APPLY_MODULE_DENYLIST
35513,35518-35535: separate storage is manual; existing mount options use APPLY_STORAGE_OPTIONS
35538-35539: guarded by APPLY_APPARMOR_ENFORCE
35540: conditional on APPLY_GRUB_PASSWORD and supplied PBKDF2 credentials
35543-35545: automated
35552: guarded by APPLY_PACKAGE_REMOVAL
35573,35585,35587: automated
35588,35591,35592: chrony selected; approved NTP_SERVERS required; timesyncd branch becomes N/A
35600,35616: automated
35623-35639: UFW selected; guarded by APPLY_FIREWALL; nftables/iptables branches become N/A
35640,35644,35646,35647,35652,35654,35657: guarded by APPLY_SSH
35664,35668: automated
35672-35690: policy files automated; PAM stack activation guarded by APPLY_PAM
35694,35695,35698: defaults automated; existing users guarded by APPLY_EXISTING_USERS
35703,35705,35708,35709,35714,35715,35722: automated
35710-35711: conditional on journal upload URL and TLS files
35720: conditional on remote log host and CA file
35721: guarded by APPLY_RSYSLOG_RECEIVER_DISABLE
35725-35755: automated; reboot required for kernel audit arguments
35760: AIDE configuration automated; baseline initialization guarded by APPLY_AIDE_INIT
35765-35770: automated
MAP
}

main() {
  preflight
  control_status
  confirm_apply
  remediate_modules
  remediate_mounts
  remediate_apparmor_grub_core
  remediate_packages_time_cron
  remediate_network_firewall
  remediate_ssh_sudo_su
  remediate_pam_passwords
  remediate_accounts_shell
  remediate_logging
  remediate_audit
  remediate_sensitive_files
  log "Completed mode=$MODE. Review $MANUAL_FILE, reboot requirements, and the execution log, then rerun the original scanner."
}

main "$@"
