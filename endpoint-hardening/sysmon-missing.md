# Sysmon Not Deployed

**Category:** Endpoint Hardening (Visibility)
**Operational Risk of Remediation:** Very Low
**Attacker Skill Required to Exploit:** N/A, this is a detection gap, not a vulnerability

## What it is

Windows native event logging is good for authentication events (4624/4625) and some security-relevant operations, but it has significant blind spots: no process creation with full command lines by default, no network connection telemetry, no DNS query logging, no file creation audit, and limited driver/image load visibility.

System Monitor (Sysmon), a free Microsoft Sysinternals tool, fills every one of these gaps. It installs as a lightweight kernel driver and service, generates high-fidelity telemetry as Windows Event Log entries, and supports granular filtering to keep volume manageable. It's the single highest-value visibility improvement you can make on endpoints.

If you have an EDR, Sysmon is still valuable since most (ALL) EDRs have gaps in specific telemetry categories that Sysmon covers, and having an independent log source is insurance against EDR bypass or uninstallation.

## What blind spots exist without it

Without Sysmon you miss:
- **Event ID 1 (Process Create)**: full command line, parent process, user, hashes. This is how you see `mimikatz.exe`, `powershell -enc <base64>`, `cmd /c whoami`, etc.
- **Event ID 3 (Network Connect)**: source/dest IP:port, process making the connection. Detect C2 beacons, lateral movement.
- **Event ID 7 (Image Loaded)**: DLL loading. Detect DLL sideloading, reflective injection.
- **Event ID 8 (CreateRemoteThread)**: process injection. Detect code injection attacks.
- **Event ID 10 (ProcessAccess)**: LSASS access attempts. Detect credential dumping.
- **Event ID 11 (FileCreate)**: file creation with path. Detect payloads dropped to disk.
- **Event ID 13 (RegistryEvent)**: persistence via registry modifications.
- **Event ID 22 (DNSEvent)**: DNS query from process. Detect C2 over DNS, DNS tunneling.
- **Event ID 25 (ProcessTampering)**: detect process hollowing and herpaderping.

## How to confirm if Sysmon is already deployed

```powershell
Get-Service sysmon* -ErrorAction SilentlyContinue
# No results = not installed

fltmc instances
# Sysmon's minifilter should appear as "SysmonDrv" if installed
```

## What to audit before deployment

Sysmon is read-only. It doesn't block anything, only logs events. There is essentially no breakage risk outside of filling a drive. The audit considerations are operational:

1. **Log volume planning.** With a well-tuned config, Sysmon generates roughly 1–5 GB/day per endpoint (raw, before SIEM compression). Size the `Microsoft-Windows-Sysmon/Operational` event log to at least 256 MB per endpoint, or (strongly preferred) forward to a SIEM.
2. **Config selection.** Don't run Sysmon with no config (logs everything, extremely noisy) or with the default config (too sparse). Use a community config as a starting point and tune for your environment.
3. **Kernel driver compatibility.** Sysmon is a kernel minifilter driver. In very rare cases it conflicts with other minifilter drivers (usually other security products). Test on a pilot group first.
4. **Performance.** On modern hardware, Sysmon's CPU and disk overhead is negligible (typically <1% CPU, unmeasurable disk). On very old or constrained hardware (thin clients, old VDI hosts), measure before fleet deployment.

## Remediation

**Step 1 — Choose a community config:**

Recommended starting configs:
- **SwiftOnSecurity/sysmon-config**: https://github.com/SwiftOnSecurity/sysmon-config - good general-purpose, well-commented, widely used. (I generally recommend Swift first but more often deploy Sysmon-modular)
- **olafhartong/sysmon-modular**: https://github.com/olafhartong/sysmon-modular - modular approach, easy to customize per environment.

Download the config and review it. Customize:
- Add exclusions for known-good noisy processes in your environment (e.g., your EDR's service, backup agents).
- Ensure ProcessAccess rules specifically watch for LSASS access (TargetImage contains `lsass.exe`).

**Step 2 — Deploy:**

```cmd
:: Install Sysmon with config
sysmon64 -accepteula -i sysmonconfig.xml

:: Update config on an existing install
sysmon64 -c sysmonconfig.xml
```

Deploy at scale via:
- GPO startup script.
- SCCM / Intune application deployment.
- PDQ Deploy or similar.

**Step 3 — Forward logs to SIEM:**

Forward `Microsoft-Windows-Sysmon/Operational` via:
- Windows Event Forwarding (WEF) to a collector.
- SIEM agent (Splunk UF, Elastic Agent, Sentinel AMA, etc.).
- Direct Sysmon → SIEM integration.

**Step 4 — Set log size:**
```powershell
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456
# 256 MB
```

**Step 5 — Build detections.** Common starter rules:
- Sysmon Event ID 1: process name = `mimikatz.exe`, `procdump.exe`, or command line contains `-ma lsass`.
- Sysmon Event ID 10: TargetImage = `lsass.exe` and GrantedAccess includes `0x1010` or `0x1FFFFF`.
- Sysmon Event ID 3: process making outbound connection to known-bad IPs or unusual ports.
- Sysmon Event ID 1: PowerShell with encoded command (`-enc`, `-e`, `-encodedcommand`).

## What might break

Nothing. Sysmon is entirely passive. The only operational impact is disk space for logs and (if forwarding) network bandwidth.

In extremely rare cases, the Sysmon kernel driver conflicts with another security product's kernel driver. Symptom: BSOD at boot. Test on pilot machines first. If this happens, boot to Safe Mode and uninstall: `sysmon64 -u`.

## Rollback

```cmd
sysmon64 -u
:: Completely uninstalls the driver and service
```

## Validate the fix

```powershell
Get-Service Sysmon* | Select-Object Name, Status, StartType
# Running, Automatic

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
# Should return recent events
```

Generate a test event:
```powershell
# This should produce a Sysmon Event ID 1 (Process Create)
Start-Process whoami -Wait
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" -MaxEvents 1
# CommandLine should show "whoami"
```

## References

- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- SwiftOnSecurity config: https://github.com/SwiftOnSecurity/sysmon-config
- Olaf Hartong modular config: https://github.com/olafhartong/sysmon-modular
- Microsoft: [Sysmon schema](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events)
- TrustedSec Sysmon Community Guide: https://github.com/trustedsec/SysmonCommunityGuide
