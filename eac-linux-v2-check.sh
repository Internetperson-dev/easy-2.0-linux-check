
    
  
#!/usr/bin/env bash
# eac-linux-v2-check.sh — read-only diagnostic checks for EAC Linux v2.
# Does not change system settings. Run as your normal user; sudo is not required.
set -u
export LC_ALL=C

PASS=0
FAIL=0
WARN=0

result() {
    local status="$1" title="$2" detail="$3"
    printf '\n[%s] %s\n  %s\n' "$status" "$title" "$detail"
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        WARN) WARN=$((WARN + 1)) ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }

read_cmdline() {
    tr ' ' '\n' </proc/cmdline
}

echo "EAC Linux v2 — local diagnostic (read-only)"
echo "Kernel: $(uname -r)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "Distro: ${PRETTY_NAME:-unknown}"; fi
echo "Note: results indicate local evidence, not official EAC certification."

# 1. Kernel and modules signing
kernel_sig=""
if [ -r /sys/module/module/parameters/sig_enforce ]; then
    kernel_sig="$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || true)"
fi
if [ "$kernel_sig" = "Y" ] || [ "$kernel_sig" = "1" ]; then
    result PASS "1. Kernel/module signature enforcement" "Kernel reports module signature enforcement enabled (sig_enforce=$kernel_sig). This does not establish that the kernel or every module is signed by an EAC-trusted organization."
elif [ -r /proc/sys/kernel/tainted ] && [ "$(cat /proc/sys/kernel/tainted)" -ne 0 ] 2>/dev/null; then
    result WARN "1. Kernel/module signing" "No positive signature-enforcement signal found; kernel taint=$(cat /proc/sys/kernel/tainted). Taint is only a clue, not a definitive signature test."
else
    result WARN "1. Kernel/module signing" "Could not confirm enforced module signatures from exposed kernel parameters. Trusted signer identity and kernel binary signature cannot be verified generically."
fi

# 2. TPM 2.0
tpm_ok=0
if [ -d /sys/class/tpm ] || compgen -G '/sys/class/tpm/tpm*' >/dev/null; then
    for tpm in /sys/class/tpm/tpm*; do
        [ -e "$tpm" ] || continue
        ver="$(cat "$tpm/tpm_version_major" 2>/dev/null || true)"
        if [ "$ver" = "2" ]; then tpm_ok=1; fi
    done
fi
if [ "$tpm_ok" -eq 1 ]; then
    result PASS "2. TPM 2.0 presence" "A TPM device reports version 2.0. Firmware configuration and usability by EAC still need validation."
elif [ -d /sys/class/tpm ] || compgen -G '/sys/class/tpm/tpm*' >/dev/null; then
    result WARN "2. TPM 2.0 presence" "TPM device node exists, but a TPM 2.0 version could not be confirmed."
else
    result FAIL "2. TPM 2.0 presence" "No TPM device found under /sys/class/tpm. It may be disabled, unavailable, or hidden by the environment."
fi

# 3. Secure Boot
sb_state=""
if have mokutil; then
    sb_state="$(mokutil --sb-state 2>/dev/null || true)"
fi
if printf '%s' "$sb_state" | grep -qi 'SecureBoot enabled'; then
    result PASS "3. Secure Boot" "mokutil reports SecureBoot enabled. This does not prove only approved/well-known keys are enrolled."
elif printf '%s' "$sb_state" | grep -qi 'SecureBoot disabled'; then
    result FAIL "3. Secure Boot" "mokutil reports SecureBoot disabled."
elif [ -r /sys/firmware/efi/efivars ]; then
    result WARN "3. Secure Boot" "System appears to have EFI variables, but state could not be determined. Install/use mokutil for a clearer check."
else
    result WARN "3. Secure Boot" "No EFI variable interface detected; system may be booted in legacy mode or EFI variables may be unavailable."
fi

# 4. Measured boot
if [ -r /sys/kernel/security/tpm0/binary_bios_measurements ] || [ -r /sys/kernel/security/tpm0/ascii_bios_measurements ]; then
    result PASS "4. Measured boot evidence" "TPM event-log file is exposed by sysfs/securityfs. This alone does not validate all required measurements or their integrity."
elif [ -r /sys/kernel/security/tpm0/binary_bios_measurements ] || [ -r /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    result WARN "4. Measured boot evidence" "TPM event log could not be confirmed."
else
    result WARN "4. Measured boot evidence" "No standard TPM event-log path found. Mount/security permissions, firmware, or bootloader support may affect visibility."
fi

# 5. IOMMU enabled, passthrough disabled
iommu_seen=0
if dmesg 2>/dev/null | grep -Eqi 'DMAR: IOMMU enabled|AMD-Vi:.*(enabled|IOMMU)|IOMMU enabled|Default domain type: Translated'; then
    iommu_seen=1
fi
cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
if printf '%s\n' "$cmdline" | grep -Eq '(^| )(intel_iommu=off|amd_iommu=off|iommu=off)( |$)'; then
    result FAIL "5. IOMMU" "Kernel command line explicitly disables IOMMU."
elif printf '%s\n' "$cmdline" | grep -Eq '(^| )(iommu=pt|amd_iommu=pt)( |$)'; then
    result WARN "5. IOMMU" "Passthrough mode appears in kernel command line; this may not meet the stated requirement."
elif [ "$iommu_seen" -eq 1 ]; then
    result PASS "5. IOMMU" "Kernel log indicates IOMMU/translated mode enabled. Check BIOS configuration and device-specific passthrough separately."
else
    result WARN "5. IOMMU" "Could not confirm IOMMU from accessible kernel logs. dmesg may be restricted; hardware/firmware and kernel settings vary."
fi

# 6. Kernel lockdown integrity
lockdown=""
if [ -r /sys/kernel/security/lockdown ]; then
    lockdown="$(cat /sys/kernel/security/lockdown 2>/dev/null || true)"
fi
if printf '%s' "$lockdown" | grep -q '\[integrity\]'; then
    result PASS "6. Kernel lockdown integrity mode" "Kernel reports integrity selected: $lockdown"
elif [ -n "$lockdown" ]; then
    result FAIL "6. Kernel lockdown integrity mode" "Integrity mode is not selected: $lockdown"
else
    result WARN "6. Kernel lockdown integrity mode" "Lockdown status unavailable; securityfs may not be mounted or kernel may not expose this interface."
fi

# 7. Kexec disabled
kexec_disabled=""
if [ -r /proc/sys/kernel/kexec_load_disabled ]; then
    kexec_disabled="$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null || true)"
fi
cmd_kexec="$(read_cmdline | grep -E '^kexec_load_disabled=' | tail -n1 | cut -d= -f2 || true)"
if [ "$kexec_disabled" = "1" ]; then
    result PASS "7. Kexec disabled" "kernel.kexec_load_disabled=1"
elif [ "$kexec_disabled" = "0" ]; then
    result FAIL "7. Kexec disabled" "kernel.kexec_load_disabled=0; kexec loading is not locked out by this sysctl."
elif [ "$cmd_kexec" = "1" ]; then
    result WARN "7. Kexec disabled" "Kernel command line requests kexec_load_disabled=1, but the runtime sysctl could not be read."
else
    result WARN "7. Kexec disabled" "Could not confirm kexec disabled. Runtime sysctl and kernel command line were inconclusive."
fi

# 8. BPF LSM active
lsm=""
if [ -r /sys/kernel/security/lsm ]; then lsm="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"; fi
if printf ',%s,' "$lsm" | grep -q ',bpf,'; then
    result PASS "8. BPF LSM" "bpf appears in active LSM list: $lsm"
elif [ -n "$lsm" ]; then
    result FAIL "8. BPF LSM" "bpf is not listed among active LSMs: $lsm"
else
    result WARN "8. BPF LSM" "Active LSM list unavailable; securityfs may not be mounted or kernel support may be absent."
fi

printf '\n---------------- Summary ----------------\n'
printf 'PASS: %d   FAIL: %d   WARN: %d\n' "$PASS" "$FAIL" "$WARN"
echo "WARN means inconclusive or needs manual verification; it is not a pass."
echo "This script cannot validate EAC's trusted-key policy or certify compatibility."

