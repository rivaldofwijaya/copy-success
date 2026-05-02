#!/usr/bin/env bash
# =============================================================================
# CVE-2026-31431 Defensive Mitigation Script
# Targets: AEAD splice LPE via splice() offset mismanagement + AF_AEAD sockets
# Run as root on potentially vulnerable endpoints (Linux >= 6.11 with AF_AEAD)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ---- Paths ------------------------------------------------------------------
LOG_DIR="/var/log/cve-2026-31431"
BASELINE_FILE="/var/lib/cve-2026-31431/suid-baseline.sha256"
BASELINE_TMP=""                                     # set in preflight
IMMUTABLE_LIST="/var/lib/cve-2026-31431/immutable-files.list"
MONITOR_SCRIPT="/usr/local/sbin/cve-2026-31431-monitor"
AUDIT_RULES="/etc/audit/rules.d/cve-2026-31431.rules"
MODPROBE_CONF="/etc/modprobe.d/cve-2026-31431.conf"
SYSCTL_CONF="/etc/sysctl.d/99-cve-2026-31431.conf"
CRON_FILE="/etc/cron.d/cve-2026-31431"
REPORT_FILE="$LOG_DIR/mitigation-report-$(date +%Y%m%d-%H%M%S).txt"
LOG_FILE="$LOG_DIR/mitigation.log"

# ---- Counters ---------------------------------------------------------------
PASS=0; WARN=0; FAIL=0

# ---- Colours ----------------------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BOLD='\033[1m'; NC='\033[0m'

# ---- Logging ----------------------------------------------------------------
_log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf '%s [%-5s] %s\n' "$ts" "$level" "$msg" >> "$LOG_FILE"
    case "$level" in
        # Use $((var+1)) assignment — $((...)) always exits 0, unlike ((var++))
        # which exits 1 when var is 0 (post-increment returns old value) and
        # would abort the script under set -e.
        OK)    printf "${GREEN}[✓]${NC} %s\n" "$msg"; PASS=$((PASS+1)) ;;
        WARN)  printf "${YELLOW}[!]${NC} %s\n" "$msg"; WARN=$((WARN+1)) ;;
        FAIL)  printf "${RED}[-]${NC} %s\n" "$msg"; FAIL=$((FAIL+1)) ;;
        INFO)  printf "${BOLD}[*]${NC} %s\n" "$msg" ;;
    esac
}
ok()   { _log OK   "$@"; }
warn() { _log WARN "$@"; }
fail() { _log FAIL "$@"; }
info() { _log INFO "$@"; }

section() { printf '\n%s\n%s\n' "$(printf '=%.0s' {1..60})" "  $*"; }

# ---- Preflight --------------------------------------------------------------
preflight() {
    [[ $EUID -eq 0 ]] || { echo "Must run as root"; exit 1; }
    mkdir -p "$LOG_DIR" "$(dirname "$BASELINE_FILE")"
    touch "$LOG_FILE"
    # Write to a temp file first; atomically committed at end of protect_suid_binaries.
    # Never truncate the baseline at script start — a partial run would leave an
    # empty baseline and silently neuter all integrity monitoring.
    BASELINE_TMP="$(dirname "$BASELINE_FILE")/suid-baseline.sha256.tmp.$$"
    > "$BASELINE_TMP"
    > "$IMMUTABLE_LIST"
}

# ---- 1. Kernel version assessment -------------------------------------------
assess_kernel() {
    section "1/7 — Kernel Assessment"
    local ver; ver=$(uname -r)
    local major; major=$(cut -d. -f1 <<< "$ver")
    # Strip any distro suffix (e.g. "11-25-generic" → "11") before numeric compare.
    local minor; minor=$(cut -d. -f2 <<< "$ver" | tr -dc '0-9')
    info "Kernel: $ver"

    # AF_AEAD was merged in 6.11; exploit requires it
    if [[ $major -gt 6 || ( $major -eq 6 && $minor -ge 11 ) ]]; then
        warn "Kernel $ver is in the vulnerable range (>=6.11). Apply mitigations below."
    else
        ok "Kernel $ver predates AF_AEAD (added 6.11). Exploit's AEAD socket step cannot run."
    fi

    # Check if CONFIG_NET_AEAD was compiled in (not modular)
    local cfg="/boot/config-$(uname -r)"
    if [[ -f "$cfg" ]]; then
        if grep -q "^CONFIG_NET_AEAD=y" "$cfg"; then
            warn "CONFIG_NET_AEAD=y (built-in) — module blacklist won't help; kernel patch required."
        elif grep -q "^CONFIG_NET_AEAD=m" "$cfg"; then
            ok "CONFIG_NET_AEAD=m (loadable module) — blacklist will be effective."
        else
            ok "CONFIG_NET_AEAD not present in kernel config."
        fi
    else
        warn "Kernel config not found at $cfg — cannot verify AEAD compile-time status."
    fi
}

# ---- 2. Block AF_AEAD kernel module -----------------------------------------
# The AF_AEAD socket-family module follows the kernel naming convention
# "af_<family>" (e.g. af_packet, af_key). The existing crypto/aead.c module
# is named "aead" and provides the generic AEAD transform interface used by
# IPsec, WireGuard, and WiFi — blacklisting that module would break those
# subsystems without blocking the exploit at all.
disable_aead_module() {
    section "2/7 — Block AF_AEAD Kernel Module (socket family 38)"

    # Skip if AF_AEAD is compiled in — a modprobe blacklist has no effect
    # on built-in code; only a kernel patch can address that case.
    local cfg="/boot/config-$(uname -r)"
    if [[ -f "$cfg" ]] && grep -q "^CONFIG_NET_AEAD=y" "$cfg"; then
        warn "CONFIG_NET_AEAD=y (built-in) — skipping modprobe blacklist (ineffective)."
        warn "Kernel patch is the only fix for this configuration."
        return
    fi

    # Determine the actual socket-family module name.
    local mod_name=""
    if modinfo af_aead &>/dev/null 2>&1; then
        mod_name="af_aead"
    elif modinfo aead_socket &>/dev/null 2>&1; then
        mod_name="aead_socket"
    else
        # Fall back to the likely name; log a warning so operators can verify.
        mod_name="af_aead"
        warn "Cannot confirm AF_AEAD module name via modinfo — using '$mod_name' (verify with: modinfo $mod_name)"
    fi

    cat > "$MODPROBE_CONF" << EOF
# CVE-2026-31431 — Disable AF_AEAD socket family (family 38).
# Without this module, socket(38,...) returns EAFNOSUPPORT and the
# exploit cannot initialise its AEAD crypto context.
# Module name: $mod_name (the socket-family module, NOT crypto/aead.c)
install $mod_name /bin/false
blacklist $mod_name
EOF
    ok "Blacklist written: $MODPROBE_CONF (module: $mod_name)"

    # Rebuild initramfs for ALL installed kernels so the blacklist survives
    # reboots into any kernel, not just the one currently running.
    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u -k all &>/dev/null \
            && ok "initramfs updated for all kernels (Debian/Ubuntu)" \
            || warn "update-initramfs -u -k all failed — blacklist may not persist after reboot"
    elif command -v dracut &>/dev/null; then
        dracut --regenerate-all --force &>/dev/null \
            && ok "initramfs regenerated for all kernels (RHEL/Fedora/SUSE)" \
            || warn "dracut --regenerate-all failed — blacklist may not persist after reboot"
    else
        warn "No initramfs tool found — blacklist may not survive reboots"
    fi

    # Evict the module from the running kernel if currently loaded
    if lsmod 2>/dev/null | grep -q "^${mod_name} "; then
        if rmmod "$mod_name" 2>/dev/null; then
            ok "Module '$mod_name' unloaded from running kernel"
        else
            warn "Could not unload '$mod_name' live (may have active users). Reboot to complete."
        fi
    else
        ok "Module '$mod_name' not currently loaded"
    fi
}

# ---- 3. Protect SUID binaries with immutable flag ---------------------------
# chattr +i sets FS_IMMUTABLE_FL; the VFS layer refuses all writes
# (including those originating from kernel splice paths) before reaching
# the filesystem. Scope is restricted to the binaries the exploit directly
# targets (/usr/bin/su, /bin/su) — not all SUID binaries — to avoid
# breaking package managers (apt/dnf/rpm) which cannot upgrade immutable files.
protect_suid_binaries() {
    section "3/7 — Protect SUID Binaries (chattr +i)"

    local -a targets=()
    for p in /usr/bin/su /bin/su; do
        [[ -f "$p" ]] && targets+=("$p")
    done

    # Deduplicate (handles /bin → /usr/bin symlink on usrmerge systems)
    local -A seen=()
    local -a unique_targets=()
    for t in "${targets[@]}"; do
        local real; real=$(realpath "$t" 2>/dev/null || echo "$t")
        if [[ -z "${seen[$real]:-}" ]]; then
            seen[$real]=1
            unique_targets+=("$real")
        fi
    done

    if [[ ${#unique_targets[@]} -eq 0 ]]; then
        warn "No su binary found in /usr/bin or /bin"
        return
    fi

    for bin in "${unique_targets[@]}"; do
        local hash; hash=$(sha256sum "$bin" | awk '{print $1}')
        echo "$hash  $bin" >> "$BASELINE_TMP"

        if chattr +i "$bin" 2>/dev/null; then
            echo "$bin" >> "$IMMUTABLE_LIST"
            ok "Immutable: $bin (sha256=$hash)"
        else
            warn "Cannot set immutable on $bin (filesystem may not support FS_IMMUTABLE_FL)"
        fi
    done

    # Atomically commit the baseline only after all entries are written.
    # This prevents a partial run from leaving an empty baseline that would
    # make the integrity monitor silently pass every check.
    if mv "$BASELINE_TMP" "$BASELINE_FILE" 2>/dev/null; then
        ok "Baseline committed: $BASELINE_FILE ($(wc -l < "$BASELINE_FILE") entries)"
    else
        fail "Failed to commit baseline — integrity monitor will not function"
    fi

    info "Locked file list: $IMMUTABLE_LIST"
    info "Before applying the kernel patch, run: xargs chattr -i < $IMMUTABLE_LIST"
}

# ---- 4. Auditd detection rules ----------------------------------------------
configure_auditd() {
    section "4/7 — Auditd Detection Rules"

    if ! command -v auditctl &>/dev/null; then
        warn "auditd not installed. Install with: apt install auditd  OR  dnf install audit"
        return
    fi

    cat > "$AUDIT_RULES" << 'EOF'
## CVE-2026-31431 detection rules

# Alert on any socket() call requesting AF_AEAD (family 38) from unprivileged users
-a always,exit -F arch=b64 -S socket -F a0=38 -F uid>=1000 -k cve31431_aead_socket
-a always,exit -F arch=b32 -S socket -F a0=38 -F uid>=1000 -k cve31431_aead_socket

# Alert on splice() from unprivileged users (normal user-space rarely calls splice directly).
# NOTE: on busy systems with rsync/sendfile-heavy workloads this rule may generate
# significant log volume. Monitor audit log size and adjust if needed.
-a always,exit -F arch=b64 -S splice -F uid>=1000 -k cve31431_splice
-a always,exit -F arch=b32 -S splice -F uid>=1000 -k cve31431_splice

# Watch /usr/bin/su for write/attribute/execute events
# (On usrmerge systems /bin/su is a symlink to /usr/bin/su — one watch suffices)
-w /usr/bin/su -p wxa -k cve31431_su_tamper

# Alert when su is executed (catch post-exploitation step)
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k cve31431_su_exec
EOF

    # Load rules into the running kernel
    if augenrules --load &>/dev/null; then
        ok "Audit rules loaded (augenrules)"
    elif auditctl -R "$AUDIT_RULES" &>/dev/null; then
        ok "Audit rules loaded (auditctl -R)"
    else
        warn "Audit rules written but could not be loaded into running kernel (apply on restart)"
    fi

    info "Query events with:  ausearch -k cve31431_aead_socket"
}

# ---- 5. Sysctl hardening ----------------------------------------------------
# Reduces auxiliary attack surface (user namespaces, BPF pivoting, info leaks).
apply_sysctl() {
    section "5/7 — Sysctl Hardening"

    # user.max_user_namespaces=0 breaks Docker rootless, Podman, LXD, Flatpak,
    # and browser sandboxing. Detect running container engines before applying.
    local skip_userns=0
    for svc in docker containerd podman lxd lxc; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            warn "Container service '$svc' is active — skipping user.max_user_namespaces=0 to avoid breaking it"
            skip_userns=1
        fi
    done

    {
        cat << 'EOF'
# CVE-2026-31431 sysctl hardening

# Disable unprivileged user namespaces — limits kernel attack surface for LPE pivots
kernel.unprivileged_userns_clone = 0

# Disable unprivileged eBPF — prevents auxiliary kernel introspection
kernel.unprivileged_bpf_disabled = 1

# Restrict kernel pointer leaks via dmesg and perf
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3

# Restrict /proc/kallsyms (limits ROP gadget discovery)
kernel.kptr_restrict = 2
EOF
        # Only add user namespace hard limit when no container engine is running
        if [[ $skip_userns -eq 0 ]]; then
            echo "user.max_user_namespaces = 0"
        fi
    } > "$SYSCTL_CONF"

    if sysctl -p "$SYSCTL_CONF" &>/dev/null; then
        ok "Sysctl parameters applied from $SYSCTL_CONF"
    else
        # Apply each parameter individually, tolerating unknowns on older kernels.
        # sysctl -w requires "key=value" with no spaces; normalise before passing.
        local applied=0
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            local normalized; normalized=$(sed 's/[[:space:]]*=[[:space:]]*/=/' <<< "$line")
            if sysctl -w "$normalized" >> "$LOG_FILE" 2>&1; then
                applied=$((applied+1))
            else
                warn "sysctl -w '$normalized' failed — see $LOG_FILE"
            fi
        done < "$SYSCTL_CONF"
        warn "Partial sysctl apply ($applied params) — some may require a newer kernel"
    fi
}

# ---- 6. Integrity monitor cron job ------------------------------------------
deploy_monitor() {
    section "6/7 — Integrity Monitor (cron/5 min)"

    cat > "$MONITOR_SCRIPT" << 'MONITOR'
#!/usr/bin/env bash
# CVE-2026-31431 SUID integrity monitor — runs via cron every 5 minutes
BASELINE="/var/lib/cve-2026-31431/suid-baseline.sha256"
ALERT_LOG="/var/log/cve-2026-31431/alerts.log"
LOCK="/var/run/cve-2026-31431-monitor.lock"
ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Prevent overlapping executions under slow I/O or large file sets
exec 9>"$LOCK"
flock -n 9 || exit 0

[[ -f "$BASELINE" ]] || exit 0
mkdir -p "$(dirname "$ALERT_LOG")"

# Use sha256sum's own --check mode rather than manual field parsing.
# This handles all path formats correctly (including spaces) and is the
# authoritative format for sha256sum's two-space output.
if ! sha256sum --quiet --check "$BASELINE" 2>/dev/null; then
    sha256sum --check "$BASELINE" 2>&1 | grep -v ': OK$' | while IFS= read -r result; do
        printf '[%s] TAMPERED: %s\n' "$(ts)" "$result" | tee -a "$ALERT_LOG"
        logger -p security.crit "CVE-2026-31431 monitor: $result"
    done
fi

# Also check for deleted files (sha256sum --check silently skips missing paths)
while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    filepath="${entry#*  }"      # everything after the two-space separator
    if [[ ! -f "$filepath" ]]; then
        printf '[%s] MISSING  %s\n' "$(ts)" "$filepath" | tee -a "$ALERT_LOG"
        logger -p security.crit "CVE-2026-31431 monitor: $filepath is MISSING — possible exploitation"
    fi
done < "$BASELINE"
# NOTE: Do NOT re-apply chattr +i on detected modifications. Locking a tampered
# file makes attacker-controlled content immutable and prevents package managers
# and incident responders from restoring the original binary.
MONITOR

    chmod 700 "$MONITOR_SCRIPT"
    ok "Monitor script: $MONITOR_SCRIPT"

    printf '*/5 * * * * root %s\n' "$MONITOR_SCRIPT" > "$CRON_FILE"
    chmod 644 "$CRON_FILE"
    ok "Cron job installed: $CRON_FILE (every 5 minutes)"
    info "Alert log: /var/log/cve-2026-31431/alerts.log"
}

# ---- 7. Kernel update advisory ----------------------------------------------
advise_patch() {
    section "7/7 — Kernel Patch Advisory"

    info "The only complete fix is a patched kernel. Vendor status:"
    if command -v apt-get &>/dev/null; then
        info "Debian/Ubuntu:  apt-get update && apt-get install --only-upgrade linux-image-\$(uname -r)"
        local inst; inst=$(apt-cache policy "linux-image-$(uname -r)" 2>/dev/null | awk '/Installed:/{print $2}')
        local cand; cand=$(apt-cache policy "linux-image-$(uname -r)" 2>/dev/null | awk '/Candidate:/{print $2}')
        [[ -n "$cand" && "$inst" != "$cand" ]] \
            && warn "Update available: $inst → $cand" \
            || ok "No pending kernel update found in APT cache (verify with apt-get update)"
    elif command -v dnf &>/dev/null; then
        info "RHEL/Fedora:    dnf update kernel"
    elif command -v yum &>/dev/null; then
        info "RHEL/CentOS:    yum update kernel"
    elif command -v zypper &>/dev/null; then
        info "SUSE:           zypper update kernel-default"
    fi

    info "Track (NVD):    https://nvd.nist.gov/vuln/detail/CVE-2026-31431"
    info "Track (RedHat): https://access.redhat.com/security/cve/CVE-2026-31431"
    info "Track (Ubuntu): https://ubuntu.com/security/CVE-2026-31431"
}

# ---- Report -----------------------------------------------------------------
generate_report() {
    section "Summary Report"

    local status="INCOMPLETE"
    [[ $FAIL -eq 0 && $WARN -eq 0 ]] && status="CLEAN"
    [[ $FAIL -eq 0 && $WARN -gt 0 ]] && status="PARTIAL"
    [[ $FAIL -gt 0 ]] && status="ATTENTION REQUIRED"

    {
        echo "CVE-2026-31431 Mitigation Report"
        echo "Generated : $(date)"
        echo "Host      : $(hostname -f 2>/dev/null || hostname)"
        echo "Kernel    : $(uname -r)"
        echo "Status    : $status"
        echo "  PASS=$PASS  WARN=$WARN  FAIL=$FAIL"
        echo ""
        echo "Mitigations applied:"
        echo "  [1] AF_AEAD module blacklisted  ($MODPROBE_CONF)"
        echo "  [2] /usr/bin/su set immutable   (chattr +i) — locked list: $IMMUTABLE_LIST"
        echo "  [3] Auditd detection rules      ($AUDIT_RULES)"
        echo "  [4] Sysctl hardening            ($SYSCTL_CONF)"
        echo "  [5] Integrity monitor cron      ($CRON_FILE)"
        echo ""
        echo "Detection queries:"
        echo "  ausearch -k cve31431_aead_socket    # AF_AEAD socket attempts"
        echo "  ausearch -k cve31431_su_tamper       # writes to /usr/bin/su"
        echo "  ausearch -k cve31431_splice          # splice() from unpriv users"
        echo ""
        echo "Undo (MUST run before applying the kernel patch or package upgrades):"
        echo "  1. Remove immutable flags from ALL locked files:"
        echo "     xargs chattr -i < $IMMUTABLE_LIST"
        echo "  2. Remove mitigation configs:"
        echo "     rm -f $MODPROBE_CONF $SYSCTL_CONF $AUDIT_RULES $CRON_FILE $MONITOR_SCRIPT"
        echo "  3. Reload audit rules and sysctl defaults:"
        echo "     augenrules --load"
        echo "     sysctl --system"
        echo "  4. Rebuild initramfs (removes module blacklist):"
        echo "     update-initramfs -u -k all  OR  dracut --regenerate-all --force"
        echo "  5. Reboot to fully activate changes."
        echo ""
        echo "IMPORTANT: Reboot to fully activate module blacklist + initramfs changes."
    } | tee "$REPORT_FILE"

    printf '\n%bLog:%b %s\n%bReport:%b %s\n' \
        "$BOLD" "$NC" "$LOG_FILE" \
        "$BOLD" "$NC" "$REPORT_FILE"
}

# ---- Entry point ------------------------------------------------------------
main() {
    preflight

    printf '%b%s%b\n' "$BOLD" \
        "============================================================
  CVE-2026-31431 Defensive Mitigation  |  $(date '+%Y-%m-%d')
  AEAD splice() LPE — AF_AEAD + splice offset mismanagement
============================================================" "$NC"

    assess_kernel
    disable_aead_module
    protect_suid_binaries
    configure_auditd
    apply_sysctl
    deploy_monitor
    advise_patch
    generate_report

    printf '\n%bReboot recommended%b to complete module blacklist + initramfs changes.\n' \
        "$YELLOW" "$NC"
}

main "$@"
