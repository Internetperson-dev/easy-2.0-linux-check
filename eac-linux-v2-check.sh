#!/usr/bin/env bash
# eac-linux-v2-check.sh
# Read-only, best-effort EAC Linux v2 requirement diagnostics.
# Supports Limine, GRUB, systemd-boot and other EFI/Linux boot arrangements.
# No settings are changed. Run as a normal user; sudo is optional for extra dmesg visibility.
set -u
export LC_ALL=C

PASS=0; FAIL=0; WARN=0; INFO=0
TMPDIR_EAC="$(mktemp -d 2>/dev/null || printf '/tmp/eac-check-%s' "$$")"
mkdir -p "$TMPDIR_EAC" 2>/dev/null || true
trap 'rm -rf "$TMPDIR_EAC"' EXIT

have() { command -v "$1" >/dev/null 2>&1; }
read_file() { [ -r "$1" ] && cat "$1" 2>/dev/null || true; }
contains_word() { printf '%s' "$1" | tr ', ' '\n\n' | grep -Fxq "$2"; }

result() {
    local status="$1" title="$2" detail="$3"
    printf '\n[%s] %s\n  %s\n' "$status" "$title" "$detail"
    case "$status" in
        PASS) PASS=$((PASS+1));;
        FAIL) FAIL=$((FAIL+1));;
        WARN) WARN=$((WARN+1));;
        INFO) INFO=$((INFO+1));;
    esac
}

section() { printf '\n\n=== %s ===\n' "$1"; }

echo "EAC Linux v2 — read-only diagnostic"
echo "Kernel: $(uname -r)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "Distro: ${PRETTY_NAME:-unknown}"; fi
echo "Architecture: $(uname -m)"
echo "This is a local heuristic checker, not an EAC certification tool."
echo "A PASS means evidence was found; trusted signer identity may still require manual validation."

CMDLINE="$(read_file /proc/cmdline)"
KERNEL_TAINT="$(read_file /proc/sys/kernel/tainted)"
LSM_LIST="$(read_file /sys/kernel/security/lsm)"
LOCKDOWN="$(read_file /sys/kernel/security/lockdown)"
KEXEC_DISABLED="$(read_file /proc/sys/kernel/kexec_load_disabled)"
SIG_ENFORCE="$(read_file /sys/module/module/parameters/sig_enforce)"

# Gather kernel messages once. dmesg may be restricted.
DMESG=""
if have dmesg; then DMESG="$(dmesg 2>/dev/null || true)"; fi
if [ -z "$DMESG" ] && have journalctl; then
    DMESG="$(journalctl -k -b --no-pager 2>/dev/null || true)"
fi

section "Boot environment"
BOOT_MODE="unknown"
if [ -d /sys/firmware/efi ]; then BOOT_MODE="UEFI"; else BOOT_MODE="Legacy/unknown"; fi
echo "Firmware boot mode: $BOOT_MODE"
echo "Kernel command line: ${CMDLINE:-unavailable}"

BOOTLOADERS=""
[ -d /boot/limine ] && BOOTLOADERS="${BOOTLOADERS} Limine"
[ -e /boot/limine.conf ] || [ -e /etc/limine.conf ] || [ -e /boot/limine/limine.conf ] && BOOTLOADERS="${BOOTLOADERS} Limine-config"
[ -d /boot/grub ] || [ -d /boot/grub2 ] || [ -e /etc/default/grub ] && BOOTLOADERS="${BOOTLOADERS} GRUB-files"
if have bootctl; then
    BOOTCTL_STATUS="$(bootctl status --no-pager 2>/dev/null || true)"
    printf '%s' "$BOOTCTL_STATUS" | grep -Eqi 'systemd-boot|Product:.*systemd-boot|Current Boot Loader:.*systemd-boot' && BOOTLOADERS="${BOOTLOADERS} systemd-boot"
else BOOTCTL_STATUS=""; fi
if [ -d /sys/firmware/efi/efivars ]; then
    if have efibootmgr; then
        EFI_ENTRIES="$(efibootmgr -v 2>/dev/null || true)"
        printf '%s' "$EFI_ENTRIES" | grep -Eqi 'limine' && BOOTLOADERS="${BOOTLOADERS} Limine-EFI-entry"
        printf '%s' "$EFI_ENTRIES" | grep -Eqi 'grub' && BOOTLOADERS="${BOOTLOADERS} GRUB-EFI-entry"
        printf '%s' "$EFI_ENTRIES" | grep -Eqi 'Linux Boot Manager|systemd-boot' && BOOTLOADERS="${BOOTLOADERS} systemd-boot-EFI-entry"
    fi
fi
if [ -n "$BOOTLOADERS" ]; then
    # De-duplicate labels while preserving enough diagnostic context.
    echo "Bootloader evidence:$BOOTLOADERS"
else
    echo "Bootloader evidence: not identified (configuration may be on another EFI/system partition)."
fi
echo "Note: installed files or EFI entries show evidence, not necessarily which loader launched this exact boot."

section "1. Signed kernel and kernel modules"
if [ "$SIG_ENFORCE" = "Y" ] || [ "$SIG_ENFORCE" = "1" ]; then
    result PASS "Module signature enforcement" "Kernel parameter sig_enforce=$SIG_ENFORCE."
elif [ -n "$SIG_ENFORCE" ]; then
    result WARN "Module signature enforcement" "sig_enforce=$SIG_ENFORCE; signature enforcement does not appear enabled."
else
    result WARN "Module signature enforcement" "Kernel does not expose /sys/module/module/parameters/sig_enforce, or it is not readable."
fi

# Linux taint bits: bit 12 (4096) = out-of-tree module; bit 13 = unsigned module.
if [[ "$KERNEL_TAINT" =~ ^[0-9]+$ ]]; then
    if (( (KERNEL_TAINT & 8192) != 0 )); then
        result WARN "Kernel taint flags" "Taint=$KERNEL_TAINT includes the unsigned-module bit (13). This is strong evidence an unsigned module was loaded at some point."
    elif (( (KERNEL_TAINT & 4096) != 0 )); then
        result WARN "Kernel taint flags" "Taint=$KERNEL_TAINT includes the out-of-tree-module bit (12), but not the unsigned-module bit. Out-of-tree modules can be signed."
    else
        result INFO "Kernel taint flags" "Taint=$KERNEL_TAINT; neither the out-of-tree nor unsigned-module taint bit is set. This does not prove all code is trusted."
    fi
else
    result WARN "Kernel taint flags" "Could not read numeric kernel taint state."
fi

if have lsmod; then
    lsmod | awk 'NR>1 {print $1}' >"$TMPDIR_EAC/modules" 2>/dev/null || true
    if [ -s "$TMPDIR_EAC/modules" ]; then
        echo "Loaded modules: $(wc -l < "$TMPDIR_EAC/modules" | tr -d ' ') (names listed with: lsmod)"
        if have modinfo; then
            echo "Sample module signer metadata (first 8 loaded modules):"
            head -n 8 "$TMPDIR_EAC/modules" | while read -r mod; do
                signer="$(modinfo -F signer "$mod" 2>/dev/null | head -n1)"
                filename="$(modinfo -F filename "$mod" 2>/dev/null | head -n1)"
                [ -n "$signer" ] || signer="(no signer metadata reported)"
                printf '  %-24s signer=%s\n' "$mod" "$signer"
                [ -n "$filename" ] && printf '    file=%s\n' "$filename"
            done
        else
            echo "modinfo is unavailable; install kmod for per-module metadata."
        fi
    fi
fi
result WARN "Trusted kernel/module signing policy" "Generic local checks cannot determine whether the kernel binary and every required out-of-tree module were signed by an organization/key trusted by EAC. Verify distro key policy and module signers."

section "2. TPM 2.0"
TPM2=0; TPM_FOUND=0
for tpm in /sys/class/tpm/tpm*; do
    [ -e "$tpm" ] || continue
    TPM_FOUND=1
    ver="$(read_file "$tpm/tpm_version_major")"
    if [ "$ver" = "2" ]; then TPM2=1; fi
    echo "TPM device: $tpm; version_major=${ver:-unknown}"
done
if [ "$TPM2" -eq 1 ]; then
    result PASS "TPM 2.0 device" "A TPM device reports version 2.0."
elif [ "$TPM_FOUND" -eq 1 ]; then
    result WARN "TPM device" "A TPM device exists, but version 2.0 could not be confirmed from sysfs."
else
    result FAIL "TPM device" "No TPM device found under /sys/class/tpm; it may be disabled, unavailable, or hidden from this environment."
fi

section "3. Secure Boot"
SB_STATE="unknown"
if have mokutil; then
    MOK_OUT="$(mokutil --sb-state 2>&1 || true)"
    echo "mokutil: $MOK_OUT"
    if printf '%s' "$MOK_OUT" | grep -qi 'SecureBoot enabled'; then SB_STATE="enabled"
    elif printf '%s' "$MOK_OUT" | grep -qi 'SecureBoot disabled'; then SB_STATE="disabled"
    fi
else
    echo "mokutil: not installed"
fi
# Read EFI SecureBoot variable if accessible. First byte 1 means enabled.
SB_VAR=""
for f in /sys/firmware/efi/efivars/SecureBoot-*; do
    [ -r "$f" ] || continue
    SB_VAR="$(od -An -t u1 -j 4 -N 1 "$f" 2>/dev/null | tr -d ' ')"
    break
done
if [ "$SB_STATE" = "unknown" ] && [ "$SB_VAR" = "1" ]; then SB_STATE="enabled"
elif [ "$SB_STATE" = "unknown" ] && [ "$SB_VAR" = "0" ]; then SB_STATE="disabled"; fi

case "$SB_STATE" in
    enabled) result PASS "Secure Boot state" "Secure Boot is reported enabled. Enrolled-key trust policy still needs verification.";;
    disabled) result FAIL "Secure Boot state" "Secure Boot is reported disabled; this does not meet the stated requirement.";;
    *) result WARN "Secure Boot state" "Could not read state from mokutil or the EFI SecureBoot variable. EFI mode alone does not establish Secure Boot status.";;
esac

if have mokutil; then
    ENROLLED="$(mokutil --list-enrolled 2>/dev/null | grep -E 'Subject:|Issuer:|SHA1 Fingerprint:|SHA256 Fingerprint:' | head -n 12 || true)"
    [ -n "$ENROLLED" ] && printf 'Enrolled MOK certificate metadata (sample):\n%s\n' "$ENROLLED"
fi
result WARN "Secure Boot trusted keys" "Even when enabled, a generic script cannot reliably decide whether all enrolled firmware/MOK keys qualify as EAC well-known keys."

section "4. Measured boot"
EVENT_LOG_FOUND=0
for f in /sys/kernel/security/tpm0/binary_bios_measurements \
         /sys/kernel/security/tpm0/ascii_bios_measurements \
         /sys/kernel/security/tpm1/binary_bios_measurements \
         /sys/kernel/security/tpm1/ascii_bios_measurements \
         /sys/kernel/security/tpm0/binary_bios_measurements; do
    if [ -r "$f" ]; then
        EVENT_LOG_FOUND=1
        echo "Readable TPM event log: $f ($(wc -c < "$f" 2>/dev/null | tr -d ' ') bytes)"
    fi
done
if [ "$EVENT_LOG_FOUND" -eq 1 ]; then
    result PASS "TPM event-log interface" "At least one standard TPM event-log path is readable. The contents still need parsing/validation to prove all expected measurements occurred."
else
    result WARN "TPM event-log interface" "No readable standard TPM event-log path found. This may be due to securityfs not being mounted, firmware/kernel exposure, or missing measurements."
fi
if printf '%s' "$BOOTCTL_STATUS" | grep -Eqi 'TPM2|measured|PCR'; then
    echo "systemd boot status mentions TPM/measured-boot information."
fi
if printf '%s' "$DMESG" | grep -Eqi 'ima:|TPM.*event log|efi.*measurement|measured boot'; then
    echo "Kernel log contains measurement-related lines:"
    printf '%s\n' "$DMESG" | grep -Ei 'ima:|TPM.*event log|efi.*measurement|measured boot' | tail -n 8
fi
result WARN "Measured boot completeness" "Presence of an event-log interface does not prove the running kernel and configuration were measured as EAC expects. Validate the event log and bootloader-specific measurement support."

section "5. IOMMU"
IOMMU_OFF=0; IOMMU_PT=0
if printf '%s\n' "$CMDLINE" | grep -Eq '(^| )(intel_iommu=off|amd_iommu=off|iommu=off)( |$)'; then IOMMU_OFF=1; fi
if printf '%s\n' "$CMDLINE" | grep -Eq '(^| )(iommu=pt|amd_iommu=pt|intel_iommu=on,igfx_off)( |$)'; then IOMMU_PT=1; fi
if [ "$IOMMU_OFF" -eq 1 ]; then
    result FAIL "IOMMU kernel parameters" "Kernel command line explicitly disables IOMMU."
elif [ "$IOMMU_PT" -eq 1 ]; then
    result WARN "IOMMU kernel parameters" "A passthrough-related parameter is present. Verify actual default domain and device isolation."
else
    echo "No explicit iommu=off / vendor_iommu=off or common iommu=pt parameter found in /proc/cmdline."
fi
if [ -n "$DMESG" ]; then
    IOMMU_LINES="$(printf '%s\n' "$DMESG" | grep -Ei 'DMAR: IOMMU enabled|AMD-Vi:|IOMMU.*(enabled|enabled by|Default domain type)|Default domain type:|remapping' | tail -n 12 || true)"
else IOMMU_LINES=""; fi
if [ -n "$IOMMU_LINES" ]; then
    printf 'Relevant kernel log lines:\n%s\n' "$IOMMU_LINES"
    if printf '%s' "$IOMMU_LINES" | grep -Eqi 'Default domain type: Translated|IOMMU enabled|AMD-Vi:.*(enabled|IOMMU)'; then
        result PASS "IOMMU initialization evidence" "Kernel log indicates IOMMU enabled or translated domains. This is not a full device-isolation audit."
    else
        result WARN "IOMMU initialization evidence" "IOMMU-related log lines found, but activation/default domain is not conclusive."
    fi
else
    result WARN "IOMMU initialization evidence" "No decisive IOMMU lines found in readable kernel logs. dmesg restrictions and platform-specific log wording can cause false negatives."
fi
if [ -d /sys/kernel/iommu_groups ]; then
    GROUP_COUNT="$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    echo "Visible IOMMU groups: $GROUP_COUNT"
    if [ "$GROUP_COUNT" -gt 0 ] 2>/dev/null; then
        result INFO "IOMMU group interface" "IOMMU groups are exposed. Check that all relevant devices are isolated and no unwanted passthrough is configured."
    fi
else
    result WARN "IOMMU groups" "No /sys/kernel/iommu_groups directory; IOMMU may be disabled, unsupported, or not exposed."
fi

section "6. Kernel lockdown integrity mode"
if [ -n "$LOCKDOWN" ]; then
    echo "Lockdown state: $LOCKDOWN"
    if printf '%s' "$LOCKDOWN" | grep -q '\[integrity\]'; then
        result PASS "Lockdown integrity" "Integrity is the selected lockdown mode."
    elif printf '%s' "$LOCKDOWN" | grep -q '\[confidentiality\]'; then
        result WARN "Lockdown integrity" "Confidentiality mode is selected, which is stronger in some respects but is not the explicitly requested integrity mode. Confirm EAC policy."
    elif printf '%s' "$LOCKDOWN" | grep -q '\[none\]'; then
        result FAIL "Lockdown integrity" "The kernel reports mode none selected."
    else
        result WARN "Lockdown integrity" "Could not interpret selected mode: $LOCKDOWN"
    fi
else
    result WARN "Lockdown integrity" "Lockdown sysfs interface unavailable; kernel support/status could not be confirmed."
fi
if printf '%s\n' "$CMDLINE" | grep -Eq '(^| )lockdown='; then
    echo "Lockdown-related command-line argument: $(printf '%s\n' "$CMDLINE" | tr ' ' '\n' | grep '^lockdown=' | paste -sd ' ' -)"
else
    echo "No explicit lockdown= argument detected in the running kernel command line."
fi

section "7. Kexec disabled"
echo "kernel.kexec_load_disabled=${KEXEC_DISABLED:-unavailable}"
if [ "$KEXEC_DISABLED" = "1" ]; then
    result PASS "Kexec load lockout" "Runtime kernel sysctl reports kexec_load_disabled=1."
elif [ "$KEXEC_DISABLED" = "0" ]; then
    result FAIL "Kexec load lockout" "Runtime kernel sysctl reports 0; kexec loading has not been locked out through this control."
else
    result WARN "Kexec load lockout" "Runtime sysctl unavailable."
fi
if printf '%s\n' "$CMDLINE" | grep -Eq '(^| )kexec_load_disabled=1( |$)'; then
    echo "Kernel command line requests kexec_load_disabled=1."
else
    echo "No kexec_load_disabled=1 parameter detected in the running command line."
fi
if have systemctl; then
    KEXEC_UNITS="$(systemctl is-enabled kexec-load.service kexec.service 2>/dev/null || true)"
    [ -n "$KEXEC_UNITS" ] && echo "Kexec-related unit enablement (informational): $KEXEC_UNITS"
fi
echo "Note: package/service presence or absence does not prove the kernel syscall is locked out."

section "8. BPF LSM"
if [ -n "$LSM_LIST" ]; then
    echo "Active LSMs: $LSM_LIST"
    if contains_word "$LSM_LIST" bpf; then
        result PASS "BPF LSM active" "bpf is present in /sys/kernel/security/lsm."
    else
        result FAIL "BPF LSM active" "bpf is absent from the active LSM list."
    fi
else
    result WARN "BPF LSM active" "Active LSM list unavailable; securityfs may not be mounted or kernel support may be absent."
fi
if [ -r /proc/config.gz ]; then
    zgrep -E '^CONFIG_BPF_LSM=' /proc/config.gz 2>/dev/null || true
elif [ -r "/boot/config-$(uname -r)" ]; then
    grep -E '^CONFIG_BPF_LSM=' "/boot/config-$(uname -r)" 2>/dev/null || true
fi

printf '\n\n================ Summary ================\n'
printf 'PASS: %d   FAIL: %d   WARN: %d   INFO: %d\n' "$PASS" "$FAIL" "$WARN" "$INFO"
echo "FAIL = evidence conflicts with the stated requirement."
echo "WARN = not proven or needs manual validation; not necessarily a failure."
echo "INFO = useful context, not a pass/fail judgment."
echo "This script does not alter the system or certify EAC compatibility."
