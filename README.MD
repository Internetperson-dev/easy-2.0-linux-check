Linux anti-cheats have been rough since the start time.

Epic Games seek to improve their Easy Anti Cheat (or Epic Anti Cheat) for Fortnite coming to Linux. 

They have said these requirements are subject to change, but this script should check for them. 

It uses [beta](https://github.com/CachyOS/CachyOS-Settings/blob/5d07459935997c33252a59c06b022de20d071a27/usr/bin/eac-status) [CatchyOS](https://github.com/CachyOS/wiki/pull/650) scripts right now.

## Usage

```sh
chmod +x eac-linux-v2-check.sh
./eac-linux-v2-check.sh
```


```
> Let’s go through the system requirements for EAC Linux v2 one by one. We expect to iterate on these requirements over time, and we appreciate feedback from developers and distribution maintainers to help refine them.
> 1. Signed Kernel & Kernel Modules
> 
> A custom kernel can easily be modified to bypass integrity checks and return false data to anti-cheat. That’s why we require that the kernel binary in use during anti-cheat protected gameplay is signed with a well-known key.
> 
> Unlike Windows, most Linux device drivers are part of the kernel source code directly (in-tree) and will be compiled and signed by your distribution alongside the kernel. There are some exceptions that are maintained separately from the kernel (out-of-tree), notably NVIDIA GPU drivers. If you need to load kernel modules, we require that they meet the same requirements as the kernel—being built by an organization and signed with a well-known key.
> 
> 2. TPM 2.0
> 
> The TPM is a hardware feature that provides security primitives like extend-only Platform Configuration Registers (PCRs) which enable a tamper-resistant boot log to be produced and verified. During boot, each piece of the boot sequence (firmware, boot manager, Linux kernel) can record metadata about the code that will run next and update the extend-only registers. This is extremely valuable, because when properly used, it enables an application like anti-cheat to know what code ran at boot without running at boot itself.
> 
> TPM 2.0 is standard on modern consumer hardware, and software support is built into the Linux kernel. We require that systems have TPM 2.0 support and that it is enabled in the BIOS.
> 
> 3. Secure Boot
> 
> Secure Boot authenticates the boot chain. Firmware will only execute a boot manager that verifies against a key in its UEFI key database, and the boot manager is expected to validate the signature of the kernel it loads. This prevents EFI-based cheats or others that run during the boot chain. We require that Secure Boot is enabled in the BIOS and only well-known keys are used to boot.
> 
> 4. Measured Boot
> 
> Measured boot is the process of actually recording metadata about the system configuration and code that will run next, then updating the extend-only registers accordingly. Linux boot managers like systemd-boot and GRUB typically perform these measurements automatically by default. Other boot managers may not support them at all or only perform them if a special configuration is applied. We require these measurements to be present.
> 
> 5. Input-Output Memory Management Unit (IOMMU)
> 
> IOMMU is a hardware technology that controls access between DMA-capable hardware devices and physical memory. When fully activated, it prevents hardware cards designed for cheating from accessing a protected game process. For non-handheld devices, we require that IOMMU is enabled in your system's BIOS and the Linux kernel is configured with IOMMU enabled and passthrough disabled.
> 
> 6. Kernel Lockdown Integrity Mode
> 
> Kernel lockdown is a built-in security feature designed to prevent root from tampering with the kernel. In integrity mode, it blocks root from performing many operations that could be abused for cheating or bypassing integrity checks, like loading unsigned kernel modules, writing to physical memory, or writing to CPU MSRs. We require that lockdown integrity mode is explicitly enabled at boot time.
> 
> 7. Kexec Disabled
> 
> Kexec is a Linux kernel feature that loads a new kernel into a running system without a full reboot cycle. Because parts of the normal boot flow are skipped, measured boot outputs no longer reflect the running kernel or its configuration. This could be abused to load a modified kernel—or change kernel options—to enable cheating without leaving traces in the measured boot log. We require that kexec is explicitly disabled at boot time.
> 
> 8. Linux Security Module BPF
>> 
> The LSM BPF feature enables eBPF programs to use Linux Security Module hooks for granular access control and monitoring. This enables anti-cheat to restrict other processes from reading or writing protected game process memory without needing a kernel module, as well as monitor for cheats loaded in different ways. We require the BPF LSM to be loaded and active.
```

- [Awesome Gaming on Linux Without Cheating, Epic Games](https://onlineservices.epicgames.com/news/introducing-easy-anti-cheat-linux-v2)


This script should detect if these features are in use.


