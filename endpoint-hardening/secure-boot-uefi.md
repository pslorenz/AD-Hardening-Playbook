# Secure Boot / UEFI Not Enforced

**Category:** Endpoint Hardening
**Operational Risk of Remediation:** Low (on modern hardware)
**Attacker Skill Required to Exploit:** Medium (bootkits, physical access)

## What it is

Secure Boot is a UEFI firmware feature that validates every component of the boot chain, from the firmware itself through the bootloader and kernel, against a whitelist of trusted signatures before execution. Without Secure Boot, an attacker with physical access (or a kernel-level exploit) can install a bootkit that runs below the OS, invisible to antivirus, EDR, and even the OS kernel.

Two related issues:

1. **Legacy BIOS boot mode** - the system uses CSM (Compatibility Support Module) instead of native UEFI. Secure Boot is impossible in CSM mode. All modern OS and hardware support native UEFI.
2. **UEFI with Secure Boot disabled** - the system boots in UEFI mode but doesn't validate the boot chain. This is often the state when "someone disabled Secure Boot to install Linux" or when an OEM shipped with it off.

Secure Boot is also a prerequisite for Credential Guard, HVCI (Hypervisor-enforced Code Integrity), and full UEFI-locked LSA Protection. Without it, those features either don't work or operate in a degraded mode.

## What attack it enables (without the fix)

- **Bootkits** - malware that loads before the OS kernel, controlling everything from the earliest stage. Examples: BlackLotus (CVE-2023-24932), ESPecter, FinSpy bootkit.
- **Evil maid attacks** - physical access to modify the bootloader.
- Disqualifies Credential Guard, HVCI, and UEFI-locked RunAsPPL.

MITRE ATT&CK: T1542.003 (Bootkit), T1542.001 (System Firmware)

## How to confirm the current state

```powershell
# Is Secure Boot enabled?
Confirm-SecureBootUEFI
# True = good, False = disabled or legacy BIOS

# More detail
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object BootupState
msinfo32  # Look at "BIOS Mode: UEFI" and "Secure Boot State: On"

# Check via registry
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue
# 1 = enabled
```

At scale, many endpoint management tools (Intune, SCCM, Tanium, most RMMs) report Secure Boot status fleet-wide.

## What to audit before remediation

**Hardware compatibility:**
- All business-class hardware since ~2012 supports UEFI and Secure Boot.
- If a machine is running in legacy BIOS mode, converting to UEFI requires converting the disk from MBR to GPT partition scheme. Microsoft provides `MBR2GPT.exe` for in-place conversion on Windows 10+.
- If a machine has UEFI but Secure Boot is off, enabling it is a BIOS setting change.

**Software compatibility:**
- Some Linux dual-boot configurations require Secure Boot exceptions (adding the distro's signing key to the UEFI db, or using a signed shim bootloader like the one Ubuntu provides).
- Some very old boot-time drivers (pre-2012 vintage) aren't signed for Secure Boot. These should have been updated years ago.
- Custom boot environments (PXE, WinPE for imaging) must use signed bootloaders. Modern SCCM/MDT task sequences handle this.

**Conversion from MBR to GPT (if needed):**
```cmd
:: Validate that the disk can be converted (non-destructive check)
mbr2gpt /validate /disk:0 /allowFullOS
:: Convert (in-place, no data loss on Windows 10 1703+)
mbr2gpt /convert /disk:0 /allowFullOS
```
After conversion, change the BIOS setting from CSM/Legacy to UEFI and enable Secure Boot.

## Remediation

**Step 1: Convert legacy BIOS systems to UEFI** (if applicable):
```cmd
mbr2gpt /convert /disk:0 /allowFullOS
```
Then in BIOS/firmware setup: disable CSM, set boot mode to UEFI only.

**Step 2: Enable Secure Boot in firmware setup:**
- Enter BIOS/UEFI settings (typically F2, F10, Del, or F12 at boot).
- Navigate to Security or Boot.
- Set Secure Boot to Enabled.
- Set Secure Boot Mode to "Standard" (uses Microsoft's UEFI CA and Third-Party UEFI CA).
- Save and exit.

**Step 3: Enforce via organizational policy:**
- Document that all new hardware must ship with UEFI and Secure Boot enabled.
- Add Secure Boot to compliance checks in Intune/SCCM.
- Block non-compliant devices from corporate network access via conditional access.

**Step 4: Apply the BlackLotus mitigation** (KB5025885):
Microsoft released Secure Boot revocations for the BlackLotus bootkit. These require a staged deployment:
1. Apply the security update.
2. Verify boot media and recovery partitions are updated.
3. Enable the revocation.

Follow Microsoft's guidance exactly — improper application of the revocation can render the system unbootable.

## What might break

- **Legacy BIOS to UEFI conversion**: if `MBR2GPT` validation fails, the disk cannot be converted in-place. Reimage with GPT partition scheme instead.
- **Dual-boot Linux**: ensure the Linux bootloader is signed or add the signing key to Secure Boot's trusted database.
- **Old boot-time hardware**: unsigned Option ROMs on very old RAID controllers, network boot ROMs, etc. Update firmware or replace hardware.
- **Custom PXE/WDS**: ensure the boot image is signed. Modern WDS/SCCM handles this automatically.

## Rollback

Disable Secure Boot in firmware setup. Immediate effect. Re-enable CSM if reverting to legacy BIOS (not recommended).

## Validate the fix

```powershell
Confirm-SecureBootUEFI
# True

(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled
# 1

msinfo32
# BIOS Mode: UEFI
# Secure Boot State: On
```

Confirm Credential Guard prerequisites are now met:
```powershell
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).AvailableSecurityProperties
# Should include 1 (Hypervisor) and 2 (Secure Boot)
```

## References

- Microsoft: [Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot)
- Microsoft: [MBR2GPT](https://learn.microsoft.com/en-us/windows/deployment/mbr-to-gpt)
- Microsoft: [KB5025885 — BlackLotus / Secure Boot revocation](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- MITRE ATT&CK: T1542.003, T1542.001
