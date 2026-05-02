# copy-success

copy-success is a compensating control script for **CVE-2026-31431**, a local privilege escalation vulnerability in the Linux kernel (`splice()` + AF_AEAD sockets, kernel ≥ 6.11). Intended for environments where applying the official kernel patch is not yet possible.

---

## What It Does

| Mitigation | Effect |
|---|---|
| **AF_AEAD module blacklist** | Blocks the vulnerable kernel module from loading so the exploit cannot start |
| **`chattr +i` on SUID binaries** | Write-protects `/usr/bin/su` and other privileged binaries at the OS level, blocking the file overwrite the exploit depends on |
| **Integrity monitor** | Records checksums of all privileged system binaries and runs on a schedule to alert on any changes or missing files |
| **`auditd` detection rules** | Logs suspicious activity: exploit-related socket calls, writes to privileged binaries, and execution of modified files |
| **Kernel hardening** | Restricts kernel features commonly used to set up or escalate the exploit |
| **Initramfs rebuild** | Ensures the module block stays active after a reboot |

---

## Key Considerations

1. **Test on a non-production system first.** The script makes permanent changes to system files, kernel settings, boot configuration, and audit rules.

2. **Write-protected files cannot be updated by the package manager.** After deployment, `apt`/`dnf`/`zypper` cannot update `su` or other protected binaries. Run `chattr -i /usr/bin/su` (and other flagged binaries) before applying OS updates, then re-run this script afterward.

3. **The initramfs rebuild step is slow.** On systems with multiple installed kernels, `update-initramfs -u -k all` or `dracut --regenerate-all` can take 2-10 minutes. The script is not hung. It will complete.

4. **Container hosts (Docker/Podman rootless):** The script detects running container services and conditionally skips `user.max_user_namespaces = 0`, but still applies `kernel.unprivileged_userns_clone = 0` unconditionally. Verify compatibility before deploying on container hosts. You may need to manually restore that setting afterward.

5. **High-throughput servers:** The audit rule for `splice()` can generate a high volume of log entries on systems with heavy rsync, backup, or database activity. Monitor `/var/log/audit/audit.log` growth after deployment.

6. **The module block may not work on all systems** if your kernel has `CONFIG_NET_AEAD=y` (meaning the module is built into the kernel rather than loaded separately). The write-protection on privileged binaries remains fully effective regardless and is the primary defensive layer.

---

## Usage

```bash
# Must be run as root
sudo bash copy-success.sh
```

Safe to re-run after OS updates or manual rollback.

**To reverse all mitigations:**
```bash
# Remove write protection
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

This script is a compensating control, not a permanent fix. It reduces exploitability but does not patch the underlying kernel vulnerability. Apply the official patch as soon as it is available for your distribution.

This script is provided as-is. By using it, you acknowledge that you have read and understood all the considerations outlined above. The author takes no responsibility for any issues, damages, or problems, direct or indirect, that arise from using, deploying, or modifying this script. Use it at your own risk.

---

## Recommendations

- Deploy in stages: test host -> staging -> production
- Log the deployment date and affected hosts
- Track when the official patch becomes available via your distro's security advisory feed ([Ubuntu USN](https://ubuntu.com/security/notices), [RHEL Errata](https://access.redhat.com/errata/), [Debian DSA](https://www.debian.org/security/))
- Monitor `/var/log/cve-2026-31431/` and syslog for `CVE-2026-31431 monitor` entries
- Remove these mitigations once the official patch is applied
