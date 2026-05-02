# copy-success — CVE-2026-31431 Compensating Control

A defensive mitigation script for **CVE-2026-31431**, a local privilege escalation (LPE) vulnerability in the Linux kernel (`splice()` + AF_AEAD sockets, kernel ≥ 6.11). Intended as a **virtual patch / compensating control** for environments where official kernel updates cannot be applied immediately.

---

## What It Does

Applies six layered mitigations targeting every step of the CVE-2026-31431 exploit chain:

| Mitigation | Effect |
|---|---|
| **AF_AEAD module blacklist** | Prevents the vulnerable socket family from loading (effective when built as a module) |
| **`chattr +i` on SUID binaries** | Marks `/usr/bin/su` and other SUID binaries immutable at the VFS layer — blocks the splice-based overwrite regardless of kernel version |
| **SUID baseline + integrity monitor** | SHA-256 baseline of all SUID/SGID binaries; cron-driven monitor alerts on tampering or missing files |
| **`auditd` detection rules** | Logs `socket(AF_AEAD)`, `splice()` on SUID targets, SUID binary writes, and post-exploitation `execve` |
| **Kernel hardening sysctls** | Disables unprivileged user namespaces, restricts BPF, tightens `dmesg`/kptr access |
| **Initramfs rebuild** | Persists the module blacklist across reboots |

---

## Intended Purpose

- **Target environment**: Linux endpoints running kernel ≥ 6.11 that cannot yet apply an official kernel patch for CVE-2026-31431
- **Threat model**: Local unprivileged attacker attempting privilege escalation via the splice/AF_AEAD exploit chain
- **Deployment scope**: Servers, workstations, container hosts — requires root

---

## Key Considerations

**Before deploying:**

1. **Test on a non-production system first.** The script makes persistent changes including immutable file flags, sysctl settings, initramfs rebuilds, and audit rules.

2. **`chattr +i` blocks package manager updates.** After deployment, `apt`/`dnf`/`zypper` cannot update `su` or other immutable SUID binaries. Run `chattr -i /usr/bin/su` (and other flagged binaries) before applying OS updates, then re-run this script afterward.

3. **Initramfs rebuild is slow.** On systems with multiple installed kernels, `update-initramfs -u -k all` or `dracut --regenerate-all` can take 2–10 minutes. The script is not hung — it will complete.

4. **Container hosts (Docker/Podman rootless):** The script detects running container services and conditionally skips `user.max_user_namespaces = 0`, but **still applies `kernel.unprivileged_userns_clone = 0`** unconditionally. Rootless containers depend on this sysctl — verify compatibility before deploying on container hosts. You may need to manually set `kernel.unprivileged_userns_clone = 1` after running.

5. **High-throughput servers:** The `splice()` audit rule can generate significant log volume on systems with heavy rsync, backup, or database I/O. Monitor `/var/log/audit/audit.log` growth after deployment.

6. **Module blacklist may be ineffective** if your kernel has `CONFIG_NET_AEAD=y` (built-in rather than loadable module). The `chattr +i` immutability control remains fully effective regardless and is the primary defensive layer.

---

## Usage

```bash
# Must be run as root
sudo bash copy-success.sh
```

The script is idempotent — safe to re-run after OS updates or manual rollback.

**To reverse all mitigations:**
```bash
# Remove immutable flags
while IFS= read -r f; do chattr -i "$f"; done < /var/lib/cve-2026-31431/immutable-files.list

# Remove configuration files
rm -f /etc/modprobe.d/cve-2026-31431.conf \
      /etc/sysctl.d/99-cve-2026-31431.conf \
      /etc/audit/rules.d/cve-2026-31431.rules \
      /etc/cron.d/cve-2026-31431 \
      /usr/local/sbin/cve-2026-31431-monitor

# Reload
sysctl --system
auditctl -R /etc/audit/audit.rules 2>/dev/null || true
update-initramfs -u -k all   # or: dracut --regenerate-all --force
```

---

## Disclaimer

> **This script is a compensating control, not a permanent fix.**
>
> It reduces exploitability of CVE-2026-31431 but does not patch the underlying kernel vulnerability. Apply the official kernel patch as soon as it is available for your distribution.
>
> This script is provided as-is. Security administrators are responsible for validating its effects in their specific environment before production deployment. The authors assume no liability for service disruption, data loss, or security incidents resulting from its use.
>
> By using this script, you acknowledge that you have read and understood all the reminders, disclaimers, and considerations outlined in this document. The author takes no responsibility for any issues, damages, or problems — direct or indirect — that arise from using, deploying, or modifying this script. Use it at your own risk.

---

## Recommendations for Security Admins

- **Deploy in stages**: test host → staging → production
- **Keep an audit trail**: log the deployment date and affected hosts
- **Set a remediation deadline**: track when official kernel patches become available via your distro's security advisory feed ([Ubuntu USN](https://ubuntu.com/security/notices), [RHEL Errata](https://access.redhat.com/errata/), [Debian DSA](https://www.debian.org/security/))
- **Monitor alerts**: check `/var/log/cve-2026-31431/` and syslog for `CVE-2026-31431 monitor` entries
- **Remove this script's mitigations after patching**: the immutable flags and sysctl changes are not needed once the official patch is applied
