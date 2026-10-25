#!/usr/bin/env bash
# eac-linux-v2-check.sh
# Best-effort EAC Linux v2 requirement diagnostics.
# Supports Limine, GRUB, systemd-boot and other EFI/Linux boot arrangements.
# The checks are read-only. Run as a normal user; sudo is optional for extra dmesg
# visibility. At the end an *opt-in* fix step is offered for Limine only, and it
# never runs without an explicit confirmation at the prompt.
#
# Different instructions for grub and limine - see https://wiki.cachyos.org/configuration/secure_boot_setup/
# Ensure sudo sbctl status is 1) installed 2) reports setup mode.
# If setup mode is not reported, ask user to press enter to reboot into bios and ask to clear secure boot keys on (report motherboard with sudo dmidecode -s baseboard-manufacturer
# sudo dmidecode -s baseboard-product-name and then try again)
#
#
# The flow should go like ensure sbctl is installed, do checks, for secure boot check with sudo, tell user to clear keys, reboot, run script again -> setup mode -> add keys -> reboot again and enable windows uefi mode
#
# The user should have to specific fixes, stuff should be backed up first.
# sudo cp -a /etc/default/limine /etc/default/limine.backup 2>/dev/null || true
# sudo cp -a /boot/limine.conf /boot/limine.conf.backup 2>/dev/null || true
#
# cat /etc/default/limine 2>/dev/null
# sudo grep -E '^(comment|cmdline|protocol):' /boot/limine.conf
#
# Also do for grub and systemd boot, but do not apply fixes for them. I do not want to publish not only mostly AI generated code, but untested AI generated code.
#
# This is subject to change. I just want day 0 support for Fortnite.
#
#
# sudo limine-mkinitcpio
#
# sudo grep 'cmdline:' /boot/limine.conf | head -4
#
# Enable lockdown now
# echo integrity | sudo tee /sys/kernel/security/lockdown
# cat /sys/kernel/security/lockdown
# Disable kexec
# sudo sysctl -w kernel.kexec_load_disabled=1
# Disable kexec on future boots
# echo 'kernel.kexec_load_disabled = 1' | sudo tee /etc/sysctl.d/99-eac-hardening.conf
# check
# cat /proc/sys/kernel/kexec_load_disabled
# add lockdown=integrity to future boots
# sudo sed -i '/^KERNEL_CMDLINE\[default\]/ s/"$/ lockdown=integrity"/' /etc/default/limine
# sudo limine-mkinitcpio
#
#
# The CachyOS people will likely sort kernel signing later.
# For now laugh at this. https://www.youtube.com/watch?v=UnktCDi-BVs
#
set -u
export LC_ALL=C

PASS=0; FAIL=0; WARN=0; INFO=0
FIX_LOCKDOWN=0; FIX_KEXEC=0; FIX_BPF=0; FIX_IOMMU=0
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

# Determine the primary bootloader that likely booted this system.
# Match the BootCurrent entry itself: the line looks like "Boot0000* Limine" or
# "Boot0000  Limine", so make the "*" optional and the label match case-insensitive.
PRIMARY_BOOTLOADER="unknown"
if have efibootmgr; then
    BOOT_CURRENT="$(efibootmgr 2>/dev/null | sed -n 's/^BootCurrent: *//p' | head -1)"
    if [ -n "$BOOT_CURRENT" ]; then
        EFI_BOOT_ENTRY="$(efibootmgr 2>/dev/null | grep -E "^Boot${BOOT_CURRENT}\*?[[:space:]]" | head -1)"
        if printf '%s' "$EFI_BOOT_ENTRY" | grep -Eqi 'limine'; then
            PRIMARY_BOOTLOADER="limine"
        elif printf '%s' "$EFI_BOOT_ENTRY" | grep -Eqi 'grub'; then
            PRIMARY_BOOTLOADER="grub"
        elif printf '%s' "$EFI_BOOT_ENTRY" | grep -Eqi 'Linux Boot Manager|systemd-boot'; then
            PRIMARY_BOOTLOADER="systemd-boot"
        fi
    fi
fi
if [ "$PRIMARY_BOOTLOADER" = "unknown" ]; then
    if [ -e /boot/limine.conf ] || [ -e /etc/limine.conf ] || [ -e /boot/limine/limine.conf ]; then
        PRIMARY_BOOTLOADER="limine"
    elif [ -d /boot/grub ] || [ -d /boot/grub2 ] || [ -e /etc/default/grub ]; then
        PRIMARY_BOOTLOADER="grub"
    elif [ -d /boot/systemd-boot ] || [ -d /boot/loader ]; then
        PRIMARY_BOOTLOADER="systemd-boot"
    fi
fi
# Last resort: infer from any collected bootloader evidence. /boot is often not
# readable as a normal user, so EFI-entry evidence may be all we have.
if [ "$PRIMARY_BOOTLOADER" = "unknown" ] && [ -n "$BOOTLOADERS" ]; then
    BL_LC="$(printf '%s' "$BOOTLOADERS" | tr '[:upper:]' '[:lower:]')"
    case "$BL_LC" in
        *limine*) PRIMARY_BOOTLOADER="limine";;
        *systemd-boot*|*"linux boot manager"*) PRIMARY_BOOTLOADER="systemd-boot";;
        *grub*) PRIMARY_BOOTLOADER="grub";;
    esac
fi
echo "Detected primary bootloader: $PRIMARY_BOOTLOADER"

section "0. CachyOS EAC kernel (linux-cachyos-eac)"
# Reference for this check / the dedicated EAC kernel & boot entry:
# https://github.com/CachyOS/wiki/pull/650/changes/cea244a7712a6e1248d0afdd51e6b95a729a801c
# NOTE: linux-cachyos-eac does not exist yet as a CachyOS package, so this
# check cannot pass until that package is published. It is kept here so that
# support lights up automatically once the package ships.
EAC_KERNEL_RUNNING=0
if printf '%s' "$(uname -r)" | grep -Eq 'cachyos-eac'; then EAC_KERNEL_RUNNING=1; fi
EAC_PKG_INSTALLED=0
if have pacman; then
    if pacman -Q linux-cachyos-eac >/dev/null 2>&1; then EAC_PKG_INSTALLED=1; fi
fi
EAC_KERNEL_IMAGE=0
[ -e /boot/vmlinuz-linux-cachyos-eac ] && EAC_KERNEL_IMAGE=1
echo "Running kernel: $(uname -r)"
echo "linux-cachyos-eac package installed: $([ "$EAC_PKG_INSTALLED" -eq 1 ] && echo yes || echo no)"
echo "EAC kernel image present: $([ "$EAC_KERNEL_IMAGE" -eq 1 ] && echo yes || echo no)"
if [ "$EAC_KERNEL_RUNNING" -eq 1 ]; then
    result PASS "CachyOS EAC kernel" "Running kernel is linux-cachyos-eac."
elif [ "$EAC_PKG_INSTALLED" -eq 1 ] || [ "$EAC_KERNEL_IMAGE" -eq 1 ]; then
    result WARN "CachyOS EAC kernel" "linux-cachyos-eac is present but not the running kernel; reboot into the EAC boot entry to use it."
else
    result WARN "CachyOS EAC kernel" "linux-cachyos-eac is not installed/running. This package does not exist yet as a CachyOS package, so this check cannot pass until it is published. See https://github.com/CachyOS/wiki/pull/650/changes/cea244a7712a6e1248d0afdd51e6b95a729a801c"
fi

# Check for the CachyOS eac-status helper script. It is not implemented yet, so
# this check is expected to FAIL until CachyOS-Settings ships it.
# Reference: https://github.com/CachyOS/CachyOS-Settings/pull/283
if have eac-status; then
    result PASS "eac-status script" "eac-status is installed and available."
else
    result FAIL "eac-status script" "eac-status is not available; it has not been implemented yet. See https://github.com/CachyOS/CachyOS-Settings/pull/283"
fi

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
SB_VENDOR_KEYS=""
# sbctl is the tool the CachyOS/Secure Boot workflow is built around; it reports
# state and vendor keys without root.
if have sbctl; then
    SBCTL_OUT="$(sbctl status 2>/dev/null || true)"
    if [ -n "$SBCTL_OUT" ]; then
        echo "sbctl:"
        printf '%s\n' "$SBCTL_OUT" | sed 's/^/  /'
        if printf '%s' "$SBCTL_OUT" | grep -Eqi 'Secure Boot:.*Enabled'; then SB_STATE="enabled"
        elif printf '%s' "$SBCTL_OUT" | grep -Eqi 'Secure Boot:.*Disabled'; then SB_STATE="disabled"; fi
        SB_VENDOR_KEYS="$(printf '%s' "$SBCTL_OUT" | sed -n 's/^Vendor Keys:[[:space:]]*//p' | head -1)"
    fi
else
    echo "sbctl: not installed"
fi
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
if [ -n "$SB_VENDOR_KEYS" ]; then
    echo "Firmware vendor keys reported by sbctl: $SB_VENDOR_KEYS"
fi
result WARN "Secure Boot trusted keys" "Even when enabled, a generic script cannot reliably decide whether all enrolled firmware/MOK keys qualify as EAC well-known keys.${SB_VENDOR_KEYS:+ sbctl reports vendor keys: $SB_VENDOR_KEYS.}"

section "4. Measured boot"
EVENT_LOG_FOUND=0
EVENT_LOG_PATH=""
EVENT_LOG_UNREADABLE=""
for f in /sys/kernel/security/tpm0/binary_bios_measurements \
          /sys/kernel/security/tpm0/ascii_bios_measurements \
          /sys/kernel/security/tpm1/binary_bios_measurements \
          /sys/kernel/security/tpm1/ascii_bios_measurements; do
    if [ -r "$f" ]; then
        EVENT_LOG_FOUND=1
        EVENT_LOG_PATH="$f"
        echo "Readable TPM event log: $f ($(wc -c < "$f" 2>/dev/null | tr -d ' ') bytes)"
    elif [ -e "$f" ]; then
        # Present but not readable by this user (typically root:tss, 0640).
        EVENT_LOG_UNREADABLE="$f"
    fi
done
# A present-but-unreadable log is usually a permissions issue, not a missing
# measurement. Try a non-interactive sudo read so we do not prompt here.
if [ "$EVENT_LOG_FOUND" -eq 0 ] && [ -n "$EVENT_LOG_UNREADABLE" ] && have sudo; then
    SUDO_WC="$(sudo -n wc -c "$EVENT_LOG_UNREADABLE" 2>/dev/null | awk '{print $1}' | head -1)"
    if [[ "$SUDO_WC" =~ ^[0-9]+$ ]]; then
        EVENT_LOG_FOUND=1
        EVENT_LOG_PATH="$EVENT_LOG_UNREADABLE"
        echo "TPM event log present and read via sudo: $EVENT_LOG_UNREADABLE ($SUDO_WC bytes)"
    fi
fi
if [ "$EVENT_LOG_FOUND" -eq 1 ]; then
    result PASS "TPM event-log interface" "A TPM event log is present and readable. The contents still need parsing/validation to prove all expected measurements occurred."
elif [ -n "$EVENT_LOG_UNREADABLE" ]; then
    result WARN "TPM event-log interface" "A TPM event log exists at $EVENT_LOG_UNREADABLE but is not readable by this user (root:tss). Re-run with sudo to confirm its contents."
else
    result WARN "TPM event-log interface" "No standard TPM event-log path found. This may be due to securityfs not being mounted, firmware/kernel exposure, or missing measurements."
fi

# Deeper validation with tpm2-tools, when installed. These are optional: the sysfs
# interface above remains the primary signal, but PCR values and a parsed event log
# are stronger evidence that measurements were actually performed.
if have tpm2_pcrread; then
    PCR_OUT="$(tpm2_pcrread sha256:0,1,2,3,4,5,6,7 2>/dev/null || true)"
    if [ -n "$PCR_OUT" ]; then
        echo "TPM2 PCR values (sha256, PCR 0-7):"
        printf '%s\n' "$PCR_OUT" | sed 's/^/  /'
        # tpm2_pcrread prints "<index>  : <hex>"; a PCR of all zeros means that
        # boot stage extended nothing (often a missing measurement).
        ZERO_PCRS="$(printf '%s\n' "$PCR_OUT" \
            | awk -F: '/^[[:space:]]*[0-9]+[[:space:]]*:/ { v=$NF; gsub(/[[:space:]xX]/,"",v); i=$1; gsub(/[[:space:]]/,"",i); if (v ~ /^0+$/) z = z (z ? ", " : "") i } END { print z }')"
        if [ -n "$ZERO_PCRS" ]; then
            result WARN "TPM PCR population" "PCR(s) $ZERO_PCRS read as all-zero, suggesting those boot stages were not measured."
        else
            result PASS "TPM PCR population" "TPM2 PCRs 0-7 report non-zero values, consistent with firmware and boot measurement (PCR7 reflects the Secure Boot policy)."
        fi
    else
        result WARN "TPM PCR population" "tpm2_pcrread is installed but returned no data; the TPM may be inaccessible or tss group permissions may be missing."
    fi
else
    echo "tpm2_pcrread (tpm2-tools) not installed; skipping PCR value validation."
fi

if have tpm2_eventlog; then
    if [ -n "$EVENT_LOG_PATH" ] && [ -r "$EVENT_LOG_PATH" ]; then
        EVENT_COUNT="$(tpm2_eventlog "$EVENT_LOG_PATH" 2>/dev/null | grep -c 'EventNum:' || true)"
        if [[ "$EVENT_COUNT" =~ ^[0-9]+$ ]] && [ "$EVENT_COUNT" -gt 0 ]; then
            result PASS "TPM event-log parse" "tpm2_eventlog parsed $EVENT_COUNT measurement events from $EVENT_LOG_PATH."
        else
            result WARN "TPM event-log parse" "tpm2_eventlog could not parse measurement events from $EVENT_LOG_PATH."
        fi
    else
        echo "tpm2_eventlog is installed but no readable event log is available; skipping parse."
    fi
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
if printf '%s\n' "$CMDLINE" | grep -Eq '(^| )(iommu=pt|intel_iommu=pt|amd_iommu=pt)( |$)'; then IOMMU_PT=1; fi
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
# Track whether IOMMU fix is needed (only if explicitly disabled or no evidence of activation)
if [ "$IOMMU_OFF" -eq 1 ]; then
    FIX_IOMMU=1
elif [ -z "$IOMMU_LINES" ] && [ ! -d /sys/kernel/iommu_groups ]; then
    FIX_IOMMU=1
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
if ! printf '%s' "$LOCKDOWN" | grep -q '\[integrity\]'; then
    FIX_LOCKDOWN=1
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
if [ "$KEXEC_DISABLED" != "1" ]; then
    FIX_KEXEC=1
fi
# kexec is locked out through the kernel.kexec_load_disabled sysctl, not through a
# kernel command-line option, so look for a persistent sysctl setting instead.
if grep -Rqs '^[[:space:]]*kernel\.kexec_load_disabled[[:space:]]*=[[:space:]]*1' /etc/sysctl.conf /etc/sysctl.d 2>/dev/null; then
    echo "kexec appears to be disabled persistently via sysctl configuration."
else
    echo "No persistent kernel.kexec_load_disabled=1 found in /etc/sysctl.conf or /etc/sysctl.d."
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
# Track whether BPF LSM fix is needed
if [ -n "$LSM_LIST" ] && ! contains_word "$LSM_LIST" bpf; then
    FIX_BPF=1
elif [ -z "$LSM_LIST" ]; then
    FIX_BPF=1
fi

printf '\n\n================ Summary ================\n'
printf 'PASS: %d   FAIL: %d   WARN: %d   INFO: %d\n' "$PASS" "$FAIL" "$WARN" "$INFO"
echo "FAIL = evidence conflicts with the stated requirement."
echo "WARN = not proven or needs manual validation; not necessarily a failure."
echo "INFO = useful context, not a pass/fail judgment."
echo "The checks are read-only; an opt-in Limine fix step (with backups) may follow."
echo "This script does not certify EAC compatibility."

# Report every actionable gap so nothing is silently dropped.
if [ "$FIX_LOCKDOWN" -eq 1 ] || [ "$FIX_KEXEC" -eq 1 ] || [ "$FIX_BPF" -eq 1 ] || [ "$FIX_IOMMU" -eq 1 ]; then
    echo ""
    echo "=== Detected gaps ==="
    [ "$FIX_LOCKDOWN" -eq 1 ] && echo "  - Kernel lockdown integrity mode is not active."
    [ "$FIX_KEXEC" -eq 1 ] && echo "  - kexec is not locked out (kernel.kexec_load_disabled != 1)."
    [ "$FIX_BPF" -eq 1 ] && echo "  - BPF LSM is not confirmed active (kernel CONFIG_BPF_LSM and 'bpf' in the lsm= parameter)."
    [ "$FIX_IOMMU" -eq 1 ] && echo "  - IOMMU activation is not confirmed (firmware VT-d/AMD-Vi plus kernel IOMMU support)."
fi

# Offer automatic fixes only when something is actually actionable, and only for Limine.
if [ "$FIX_LOCKDOWN" -eq 1 ] || [ "$FIX_KEXEC" -eq 1 ]; then
    if [ "$PRIMARY_BOOTLOADER" != "limine" ]; then
        echo ""
        echo "Detected primary bootloader: $PRIMARY_BOOTLOADER"
        echo "Automatic fixes are only offered for Limine; configure $PRIMARY_BOOTLOADER manually."
    else
        echo ""
        echo "=== Suggested fixes for Limine ==="
        [ "$FIX_LOCKDOWN" -eq 1 ] && echo "  [ ] Add lockdown=integrity to the kernel cmdline in /etc/default/limine"
        [ "$FIX_KEXEC" -eq 1 ] && echo "  [ ] Disable kexec: set kernel.kexec_load_disabled=1"
        echo ""
        if ! have sudo; then
            echo "sudo is not available; cannot apply fixes."
        elif [ -t 0 ]; then
            APPLY_FIXES="n"
            read -rp "Apply these fixes? [y/N] " APPLY_FIXES || APPLY_FIXES="n"
        else
            APPLY_FIXES="n"
            echo "(Non-interactive mode; no changes applied.)"
        fi
        case "$APPLY_FIXES" in
            [Yy]*)
                # Back up everything first; abort the whole fix if any backup fails.
                BACKUP_OK=1
                STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || printf manual)"
                for cfg in /etc/default/limine /boot/limine.conf; do
                    [ -e "$cfg" ] || continue
                    if sudo cp -a "$cfg" "$cfg.eac-backup-$STAMP"; then
                        echo "  + Backed up $cfg -> $cfg.eac-backup-$STAMP"
                    else
                        echo "  ! Failed to back up $cfg; refusing to modify anything."
                        BACKUP_OK=0
                        break
                    fi
                done
                if [ "$BACKUP_OK" -eq 1 ]; then
                    echo "Applying fixes..."
                    if [ "$FIX_LOCKDOWN" -eq 1 ]; then
                        if [ -e /etc/default/limine ]; then
                            if grep -Eq '^KERNEL_CMDLINE\[default\]=.*lockdown=integrity' /etc/default/limine; then
                                echo "  = lockdown=integrity already present in /etc/default/limine"
                            else
                                sudo sed -i '/^KERNEL_CMDLINE\[default\]/ s/"$/ lockdown=integrity"/' /etc/default/limine
                                echo "  + Added lockdown=integrity to /etc/default/limine"
                            fi
                        else
                            echo "  ! /etc/default/limine not found; cannot add lockdown=integrity"
                        fi
                    fi
                    if [ "$FIX_KEXEC" -eq 1 ]; then
                        printf 'kernel.kexec_load_disabled = 1\n' | sudo tee /etc/sysctl.d/99-eac-hardening.conf >/dev/null
                        sudo sysctl -w kernel.kexec_load_disabled=1 >/dev/null 2>&1 || true
                        echo "  + Disabled kexec (runtime and /etc/sysctl.d/99-eac-hardening.conf)"
                    fi
                    if [ "$FIX_LOCKDOWN" -eq 1 ]; then
                        if have limine-mkinitcpio; then
                            echo "  + Regenerating initramfs..."
                            sudo limine-mkinitcpio
                        else
                            echo "  ! limine-mkinitcpio not found; regenerate the initramfs manually"
                        fi
                    fi
                    echo "Done. Reboot to apply changes."
                fi
                ;;
            *)
                echo "No changes applied."
                ;;
        esac
    fi
fi

# Non-zero exit when a hard requirement is missing, so callers can script against it.
[ "$FAIL" -gt 0 ] && exit 1
exit 0
