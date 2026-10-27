#!/usr/bin/env bash
# EAC Linux v2 / CachyOS preflight (diagnostic only)
# Based on Epic's EAC Linux v2 requirements and the CachyOS EAC *draft*.
# No installations, configuration edits, reboots, key enrollment, or remote code.
# On a FAIL, invokes locally installed eac-status (with sudo as needed).
# Intended for a normal user; restricted reads produce WARN, not invented PASS.
# This is NOT an EAC compatibility certification. Tested syntactically and in a
# non-CachyOS environment; validate on real CachyOS hardware before publishing.

set -u
export LC_ALL=C

PASS=0
FAIL=0
WARN=0
INFO=0

have() { command -v "$1" >/dev/null 2>&1; }
read_file() { [[ -r "$1" ]] && cat -- "$1" 2>/dev/null || true; }
result() {
    local status="$1" title="$2" detail="$3"
    printf '\n[%s] %s\n  %s\n' "$status" "$title" "$detail"
    case "$status" in
        PASS) ((PASS+=1)) ;;
        FAIL) ((FAIL+=1)) ;;
        WARN) ((WARN+=1)) ;;
        INFO) ((INFO+=1)) ;;
    esac
}
section() { printf '\n=== %s ===\n' "$1"; }

# Check the LAST instance: Linux uses the last value for these named arguments.
CMDLINE="$(read_file /proc/cmdline)"
read -r -a CMD_TOKENS <<< "$CMDLINE"
last_arg() {
    local name="$1" token value=""
    for token in "${CMD_TOKENS[@]}"; do
        [[ "$token" == "$name="* ]] && value="${token#*=}"
    done
    printf '%s' "$value"
}

# EFI variable files start with four bytes of efivarfs attributes.
efi_byte() {
    local name="$1" file
    for file in /sys/firmware/efi/efivars/"$name"-*; do
        [[ -r "$file" ]] || continue
        od -An -t u1 -j 4 -N 1 "$file" 2>/dev/null | tr -d '[:space:]'
        return
    done
}

printf 'EAC Linux v2 / CachyOS read-only preflight\n'
printf 'Kernel: %s\n' "$(uname -r)"
printf 'Architecture: %s\n' "$(uname -m)"
printf 'No configuration changes will be made. PASS is local evidence, not EAC approval.\n'
printf 'If checks fail, a locally installed eac-status will be run (sudo may prompt).\n'

section '1. Firmware and current boot entry'
if [[ -d /sys/firmware/efi ]]; then
    result PASS 'UEFI boot' 'System booted using UEFI.'
else
    result FAIL 'UEFI boot' 'UEFI not detected; Secure Boot EAC setup requires UEFI.'
fi

EFI_CURRENT=''
if have efibootmgr && [[ -d /sys/firmware/efi ]]; then
    EFI_ENTRIES="$(efibootmgr -v 2>/dev/null || true)"
    BOOT_NUM="$(printf '%s\n' "$EFI_ENTRIES" | sed -n 's/^BootCurrent:[[:space:]]*//p' | head -n 1)"
    if [[ -n "$BOOT_NUM" ]]; then
        EFI_CURRENT="$(printf '%s\n' "$EFI_ENTRIES" | grep -Ei "^Boot${BOOT_NUM}\\*?[[:space:]]" | head -n 1 || true)"
    fi
fi
if [[ -n "$EFI_CURRENT" ]]; then
    printf 'UEFI BootCurrent entry: %s\n' "$EFI_CURRENT"
    if printf '%s\n' "$EFI_CURRENT" | grep -Eqi 'CachyOS EAC|[\\/]EFI[\\/]cachyos-eac[\\/]'; then
        result INFO 'CachyOS EAC boot entry' 'BootCurrent points to the dedicated EAC entry. This does not by itself verify signatures or measurements.'
    elif printf '%s\n' "$EFI_CURRENT" | grep -Eqi 'Limine'; then
        result WARN 'Current boot path' 'BootCurrent is Limine. The CachyOS EAC draft requires the separate signed systemd-boot EAC entry, NOT the Limine kernel menu entry.'
    elif printf '%s\n' "$EFI_CURRENT" | grep -Eqi 'GRUB'; then
        result WARN 'Current boot path' 'BootCurrent is GRUB. The current CachyOS EAC draft documents systemd-boot and Limine-to-systemd-boot, not a GRUB EAC setup.'
    else
        result INFO 'Current boot path' 'BootCurrent is shown above. Confirm the active loader and measured boot independently.'
    fi
else
    result WARN 'Current boot entry' 'Could not identify BootCurrent. Try efibootmgr -v manually; file presence is not proof of the active loader.'
fi

section '2. CachyOS EAC kernel'
OS_ID=''
if [[ -r /etc/os-release ]]; then
    # ID is data from local OS metadata; do not execute it as arbitrary shell.
    OS_ID="$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '\"')"
fi
if [[ "$OS_ID" == 'cachyos' ]]; then
    if [[ "$(uname -r)" == *-cachyos-eac ]]; then
        result PASS 'EAC kernel booted' 'Running kernel name ends in -cachyos-eac.'
    else
        result FAIL 'EAC kernel booted' 'Not running linux-cachyos-eac. The draft uses a dedicated kernel and boot entry.'
    fi
    if have pacman && pacman -Q linux-cachyos-eac >/dev/null 2>&1; then
        result INFO 'EAC kernel package' 'linux-cachyos-eac is installed according to pacman.'
    else
        result INFO 'EAC kernel package' 'linux-cachyos-eac was not found in the local pacman database; package availability may change.'
    fi
else
    result INFO 'CachyOS-specific kernel' 'Not a confirmed CachyOS system; the dedicated package/boot-flow check is not applicable.'
fi

section '3. Secure Boot and trusted signatures'
SB_RAW="$(efi_byte SecureBoot)"
SETUP_RAW="$(efi_byte SetupMode)"
SBCTL_OUTPUT=''
if have sbctl; then
    SBCTL_OUTPUT="$(sbctl status 2>/dev/null || true)"
    if [[ -n "$SBCTL_OUTPUT" ]]; then
        printf 'sbctl status:\n%s\n' "$SBCTL_OUTPUT"
    else
        printf 'sbctl status unavailable to this user (you can inspect with sudo sbctl status).\n'
    fi
else
    printf 'sbctl is not installed.\n'
fi
if [[ -z "$SB_RAW" ]]; then
    if printf '%s\n' "$SBCTL_OUTPUT" | grep -Eqi 'Secure Boot:.*Enabled'; then
        SB_RAW=1
    elif printf '%s\n' "$SBCTL_OUTPUT" | grep -Eqi 'Secure Boot:.*Disabled'; then
        SB_RAW=0
    fi
fi
if [[ -z "$SETUP_RAW" ]]; then
    if printf '%s\n' "$SBCTL_OUTPUT" | grep -Eqi 'Setup Mode:.*Enabled'; then
        SETUP_RAW=1
    elif printf '%s\n' "$SBCTL_OUTPUT" | grep -Eqi 'Setup Mode:.*Disabled'; then
        SETUP_RAW=0
    fi
fi
case "$SB_RAW" in
    1) result PASS 'Secure Boot enabled' 'Firmware reports Secure Boot on.' ;;
    0) result FAIL 'Secure Boot enabled' 'Firmware reports Secure Boot off.' ;;
    *) result WARN 'Secure Boot enabled' 'Firmware state unreadable; cannot determine Secure Boot status.' ;;
esac
case "$SETUP_RAW" in
    0) result PASS 'Secure Boot Setup Mode off' 'Firmware is not in Setup Mode.' ;;
    1) result FAIL 'Secure Boot Setup Mode off' 'Firmware is in Setup Mode; Secure Boot verification is not in normal enforced mode.' ;;
    *) result WARN 'Secure Boot Setup Mode off' 'Could not verify Setup Mode status.' ;;
esac
result WARN 'EAC well-known signing key' 'Secure Boot ON is insufficient: EAC requires the boot-chain and module signing keys it trusts. Check the official CachyOS guide and inspect TPM boot authorities.'

# Inventory signature counts only. One signature does NOT prove it belongs to EAC's trusted CA.
if have sbverify; then
    ESP=''
    if have bootctl; then ESP="$(bootctl --print-esp-path 2>/dev/null || true)"; fi
    SIGNED_FILES=(/boot/vmlinuz-linux-cachyos-eac)
    if [[ -n "$ESP" && -r /etc/machine-id ]]; then
        MACHINE_ID="$(read_file /etc/machine-id)"
        if [[ "$MACHINE_ID" =~ ^[[:xdigit:]]{32}$ ]]; then
            SIGNED_FILES+=("$ESP/$MACHINE_ID/linux-cachyos-eac/vmlinuz")
        fi
        SIGNED_FILES+=("$ESP/EFI/systemd/systemd-bootx64.efi" "$ESP/EFI/cachyos-eac/systemd-bootx64.efi")
    fi
    FILES_CHECKED=0
    for file in "${SIGNED_FILES[@]}"; do
        [[ -f "$file" && -r "$file" ]] || continue
        ((FILES_CHECKED+=1))
        OUTPUT="$(sbverify --list "$file" 2>/dev/null || true)"
        SIGS="$(printf '%s\n' "$OUTPUT" | grep -c '^signature' || true)"
        if [[ "$SIGS" =~ ^[0-9]+$ ]] && ((SIGS == 1)); then
            result INFO "Signature inventory: $file" 'Exactly one signature reported; issuer/trust still unverified.'
        else
            result WARN "Signature inventory: $file" "sbverify reported ${SIGS:-unknown} signatures (expected exactly one CachyOS signature in the draft)."
        fi
    done
    if ((FILES_CHECKED == 0)); then
        result WARN 'Signature inventory' 'No expected EAC EFI/kernel images could be read from this environment.'
    fi
else
    result WARN 'Signature inventory' 'sbverify is not installed (provided by sbsigntools); skipped signature counts.'
fi

section '4. TPM 2.0 and measured boot'
TPM_OK=0
TPM_FOUND=0
for dev in /sys/class/tpm/tpm*; do
    [[ -d "$dev" ]] || continue
    ((TPM_FOUND+=1))
    VERSION="$(read_file "$dev/tpm_version_major")"
    printf 'TPM: %s (major version %s)\n' "$dev" "${VERSION:-unknown}"
    [[ "$VERSION" == 2 ]] && TPM_OK=1
done
if ((TPM_OK == 1)); then
    result PASS 'TPM 2.0' 'Linux exposes a TPM 2.0 device.'
elif ((TPM_FOUND > 0)); then
    result WARN 'TPM 2.0' 'A TPM exists but version 2.0 was not confirmed.'
else
    result FAIL 'TPM 2.0' 'Linux does not expose a TPM; check firmware fTPM/PTT settings.'
fi
LOG_PATH=''
for file in /sys/kernel/security/tpm0/binary_bios_measurements /sys/kernel/security/tpm1/binary_bios_measurements; do
    if [[ -r "$file" ]]; then LOG_PATH="$file"; break; fi
done
if [[ -n "$LOG_PATH" ]]; then
    result PASS 'TPM event-log interface' "Readable log at $LOG_PATH. Presence does not prove complete trusted measurements."
    if have tpm2_eventlog; then
        EVENT_COUNT="$(tpm2_eventlog "$LOG_PATH" 2>/dev/null | grep -c 'EventNum:' || true)"
        if [[ "$EVENT_COUNT" =~ ^[0-9]+$ ]] && ((EVENT_COUNT > 0)); then
            result INFO 'TPM event-log parse' "Decoded $EVENT_COUNT events. Boot certificate/PCR identity still require verification."
        else
            result WARN 'TPM event-log parse' 'tpm2_eventlog could not decode measurement events.'
        fi
    else
        result WARN 'TPM event-log parse' 'tpm2_eventlog unavailable (tpm2-tools); could not decode boot authorities.'
    fi
elif [[ -e /sys/kernel/security/tpm0/binary_bios_measurements || -e /sys/kernel/security/tpm1/binary_bios_measurements ]]; then
    result WARN 'TPM event-log interface' 'TPM log exists but is unreadable as this user. You can inspect it with sudo.'
else
    result WARN 'TPM event-log interface' 'No standard binary event log exposed. Measured boot cannot be confirmed.'
fi
result WARN 'Measured boot trust chain' 'A generic local scan cannot prove the EAC-signed systemd-boot and kernel were both verified and measured as required.'

section '5. IOMMU (non-handheld requirement)'
IOMMU_OFF="$(last_arg iommu)"
INTEL_IOMMU="$(last_arg intel_iommu)"
AMD_IOMMU="$(last_arg amd_iommu)"
IOMMU_PT="$(last_arg iommu.passthrough)"
if [[ "$IOMMU_OFF" == off || "$INTEL_IOMMU" == off || "$AMD_IOMMU" == off ]]; then
    result FAIL 'IOMMU enabled' 'Kernel command line explicitly disables IOMMU.'
elif [[ "$IOMMU_OFF" == pt || "$IOMMU_PT" == 1 ]]; then
    result FAIL 'IOMMU translation' 'Kernel command line requests IOMMU passthrough.'
elif [[ "$IOMMU_PT" == 0 ]]; then
    result PASS 'IOMMU passthrough boot option' 'iommu.passthrough=0 is explicitly specified.'
else
    result WARN 'IOMMU passthrough boot option' 'Missing explicit iommu.passthrough=0; the EAC draft requires it.'
fi
GROUPS=0
IDENTITY=0
DMA=0
for group in /sys/kernel/iommu_groups/*; do
    [[ -d "$group" ]] || continue
    ((GROUPS+=1))
    T="$(read_file "$group/type")"
    [[ "$T" == identity ]] && ((IDENTITY+=1))
    [[ "$T" == DMA || "$T" == DMA-FQ ]] && ((DMA+=1))
done
printf 'IOMMU groups: %d; translated (DMA): %d; identity: %d\n' "$GROUPS" "$DMA" "$IDENTITY"
if ((IDENTITY > 0)); then
    result FAIL 'IOMMU group default types' "$IDENTITY visible group(s) are identity/passthrough domains."
elif ((GROUPS > 0 && DMA > 0)); then
    result INFO 'IOMMU group default types' 'Translated domains are visible, but this is not a full all-device DMA isolation audit.'
else
    result WARN 'IOMMU group default types' 'No translated IOMMU groups confirmed. Firmware, hardware and handheld exceptions need checking.'
fi

section '6. Lockdown, signed modules, kexec, BPF LSM'
LOCKDOWN="$(read_file /sys/kernel/security/lockdown)"
if [[ "$LOCKDOWN" == *'[integrity]'* && "$(last_arg lockdown)" == integrity ]]; then
    result PASS 'Lockdown integrity at boot' 'lockdown=integrity is explicit and active.'
elif [[ "$LOCKDOWN" == *'[integrity]'* ]]; then
    result WARN 'Lockdown integrity at boot' 'Integrity is active, but an explicit lockdown=integrity boot argument was not confirmed.'
elif [[ "$LOCKDOWN" == *'[confidentiality]'* ]]; then
    result WARN 'Lockdown integrity at boot' 'Confidentiality is active rather than the explicitly requested integrity mode.'
elif [[ "$LOCKDOWN" == *'[none]'* ]]; then
    result FAIL 'Lockdown integrity at boot' 'Kernel lockdown is inactive.'
else
    result WARN 'Lockdown integrity at boot' 'Kernel lockdown state not readable.'
fi
TAINT="$(read_file /proc/sys/kernel/tainted)"
if [[ "$TAINT" =~ ^[0-9]+$ ]]; then
    if (( (TAINT & 8192) != 0 )); then
        result WARN 'Kernel unsigned-module taint' 'Unsigned-module taint bit is set; an unsigned module was loaded.'
    elif (( (TAINT & 4096) != 0 )); then
        result WARN 'Kernel out-of-tree-module taint' 'An out-of-tree module was loaded. Its EAC-trusted signing identity requires inspection.'
    else
        result INFO 'Kernel module taint' 'No unsigned/out-of-tree module taint bit set; this does not establish trusted module signing.'
    fi
else
    result WARN 'Kernel module taint' 'Could not read kernel taint value.'
fi
SIG_ENFORCE="$(read_file /sys/module/module/parameters/sig_enforce)"
if [[ "$SIG_ENFORCE" == Y || "$SIG_ENFORCE" == 1 ]]; then
    if [[ "$(last_arg module.sig_enforce)" == 1 ]]; then
        result PASS 'Module signature enforcement' 'Module signatures are enforced and explicitly requested at boot.'
    else
        result WARN 'Module signature enforcement' 'Enforced at runtime, but module.sig_enforce=1 not present in cmdline.'
    fi
elif [[ "$SIG_ENFORCE" == N || "$SIG_ENFORCE" == 0 ]]; then
    result FAIL 'Module signature enforcement' 'Kernel reports no enforcement of module signatures.'
else
    result WARN 'Module signature enforcement' 'Could not read module signature enforcement state.'
fi
KEXEC="$(read_file /proc/sys/kernel/kexec_load_disabled)"
KEXEC_BOOT="$(last_arg sysctl.kernel.kexec_load_disabled)"
if [[ "$KEXEC" == 1 && "$KEXEC_BOOT" == 1 ]]; then
    result PASS 'kexec disabled at boot' 'Explicit EAC boot option and runtime lockout both observed.'
elif [[ "$KEXEC" == 1 ]]; then
    result WARN 'kexec disabled at boot' 'Runtime lockout is on, but the EAC boot argument was not confirmed.'
elif [[ "$KEXEC" == 0 ]]; then
    result FAIL 'kexec disabled at boot' 'Runtime kernel permits kexec loading through this control.'
else
    result WARN 'kexec disabled at boot' 'Runtime kexec lockout sysctl unreadable.'
fi
LSM="$(read_file /sys/kernel/security/lsm)"
case ",$LSM," in
    *,bpf,*)
        if [[ ",$(last_arg lsm)," == *',bpf,'* ]]; then
            result PASS 'BPF LSM enabled at boot' 'BPF appears in the active LSM list and explicit lsm= argument.'
        else
            result WARN 'BPF LSM enabled at boot' 'BPF is active, but explicit lsm=...bpf is unconfirmed.'
        fi
        ;;
    *)
        if [[ -n "$LSM" ]]; then
            result FAIL 'BPF LSM enabled at boot' 'BPF is absent from the active security modules.'
        else
            result WARN 'BPF LSM enabled at boot' 'No readable LSM list; securityfs or kernel support may be missing.'
        fi
        ;;
esac

section '7. Assessment and manual next steps'
printf '\nPASS %d | FAIL %d | WARN %d | INFO %d\n' "$PASS" "$FAIL" "$WARN" "$INFO"
printf 'FAIL: conflicting evidence. WARN: incomplete evidence, not necessarily a failure.\n'
printf 'For Limine installations, use the dedicated signed systemd-boot EAC EFI entry.\n'
printf 'Do not change Secure Boot keys or run bootctl install from Limine without\n'
printf 'following a finalized distro-specific procedure and preparing recovery.\n'
printf 'Draft: https://github.com/CachyOS/wiki/pull/650\n'
printf 'Epic: https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2\n'
printf 'This script DOES NOT certify EAC compatibility or modify configuration.\n'

# A failing preflight triggers a SECOND, local-only status check. This program
# does not download code or install packages. eac-status currently requires
# root privileges; sudo uses its configured executable lookup path.
if ((FAIL > 0)); then
    section '8. Local eac-status follow-up (preflight failed)'
    printf 'Preflight reported %d failed check(s).\n' "$FAIL"

    if have eac-status; then
        printf 'Running locally installed eac-status (no download or remote execution).\n'
        EAC_STATUS_RC=0
        if ((EUID == 0)); then
            eac-status || EAC_STATUS_RC=$?
        elif have sudo; then
            printf 'eac-status requires root; sudo may request your password.\n'
            sudo -- eac-status || EAC_STATUS_RC=$?
        else
            EAC_STATUS_RC=127
            printf 'sudo is not available; cannot run local eac-status with the required privileges.\n'
        fi

        if ((EAC_STATUS_RC != 0)); then
            printf '\n[FAIL] Local eac-status failed (exit code %d).\n' "$EAC_STATUS_RC"
            printf 'Update CachyOS with: sudo pacman -Syu\n'
            printf 'Reboot into the dedicated CachyOS EAC entry and re-run the checks.\n'
            printf 'An update may not resolve this until EAC support is officially packaged.\n'
        else
            printf '\n[INFO] Local eac-status passed, but this preflight still reported %d failure(s).\n' "$FAIL"
            printf 'Review the preflight findings. If packages are outdated, update CachyOS: sudo pacman -Syu\n'
        fi
    else
        printf '[WARN] eac-status is not installed or not available in PATH.\n'
        printf 'Update CachyOS with: sudo pacman -Syu\n'
        printf 'Then reboot and re-run this checker. eac-status may not be packaged yet.\n'
    fi
fi

# Preserve non-zero status whenever this preflight found hard failures.
((FAIL == 0))

# End of complete script: EAC_PREFLIGHT_END
