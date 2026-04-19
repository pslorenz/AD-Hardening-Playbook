# Insufficient Audit Policy on Endpoints

**Category:** Endpoint Hardening (Visibility)
**Operational Risk of Remediation:** Very Low
**Attacker Skill Required to Exploit:** N/A — this is a detection gap

## What it is

Most organizations configure advanced audit policy on Domain Controllers but leave workstations and member servers at the Windows defaults. The defaults are threadbare; they don't log process creation command lines, logon details for service accounts, registry changes, or many other events that defenders need for incident response and threat hunting.

Without endpoint audit policy, an attacker who compromises a workstation operates in a visibility dead zone. You won't know what commands they ran, what files they accessed, what services they installed, or what credentials they used, at least until the impact hits something that *is* monitored (usually the DC, by which point the attacker has already pivoted).

This finding complements [Sysmon](sysmon-not-deployed.md) - both should be deployed. Native Windows audit policy and Sysmon have overlapping but different coverage. Together they provide defense-in-depth for visibility.

## What blind spots exist without it

Default Windows audit policy on workstations misses:
- **Process creation (4688)** with command line - the single most useful event for detecting attacker activity.
- **Logon events (4624/4625)** - logged on DCs but often not on the workstation itself, making it hard to see which accounts were used locally.
- **Service installs (7045)** - persistence via new services.
- **Scheduled task creation (4698)** - persistence via scheduled tasks.
- **Registry modification** - persistence via Run keys, services, COM hijacking.
- **Removable media access** - data exfiltration via USB.
- **PowerShell execution (4104)** - covered in [`powershell-hardening.md`](powershell-hardening.md) but listed here for completeness.
- **Token manipulation (4672, 4673)** - privilege escalation indicators.

## How to confirm the gap exists

```powershell
# Show current audit policy on any host
auditpol /get /category:*
# Most categories will show "No Auditing" or "Success" only on default workstation installs
```

Key categories to check:
```powershell
auditpol /get /subcategory:"Process Creation"
# Should be "Success" at minimum. "No Auditing" = blind.

auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"Special Logon"
auditpol /get /subcategory:"Other Object Access Events"
```

Also check whether command-line logging is enabled for process creation:
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
# 1 = enabled (good), 0 or absent = disabled
```

## What to audit before remediation

This is an increase in logging, not a behavioral change. The only audit considerations are:

1. **Log volume and storage.** Enabling full audit policy on workstations increases event log volume significantly. Plan for:
   - Increase the Security event log from the default 20 MB to at least **256 MB** per endpoint.
   - Forward to a SIEM local-only logs are useless if the attacker clears them.
2. **Performance.** On modern hardware, the CPU and disk overhead of audit logging is negligible. On very constrained systems (thin clients, old VDI), measure.
3. **Privacy/compliance.** Process creation with command lines can capture sensitive data (passwords passed on command lines, URLs, file paths). Ensure your log retention and access policies align with privacy requirements.

## Remediation

Deploy via GPO to all workstations and member servers:

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`

### Recommended audit subcategories

**Account Logon:**
- Credential Validation: Success, Failure
- Kerberos Authentication Service: Success, Failure
- Kerberos Service Ticket Operations: Success, Failure

**Account Management:**
- Security Group Management: Success
- User Account Management: Success, Failure

**Detailed Tracking:**
- Process Creation: **Success** (this is the most important one)
- Process Termination: Success (optional — useful for timeline reconstruction)
- Plug and Play Events: Success

**Logon/Logoff:**
- Logon: Success, Failure
- Logoff: Success
- Special Logon: Success
- Other Logon/Logoff Events: Success, Failure

**Object Access:**
- Removable Storage: Success, Failure
- Central Policy Staging: Success, Failure
- Other Object Access Events: Success, Failure

**Policy Change:**
- Audit Policy Change: Success, Failure
- Authentication Policy Change: Success
- Authorization Policy Change: Success

**Privilege Use:**
- Sensitive Privilege Use: Success, Failure

**System:**
- Security State Change: Success
- Security System Extension: Success (service installs, auth package loads)
- System Integrity: Success, Failure

### Enable command-line logging for Event 4688

GPO:
`Computer Configuration → Policies → Administrative Templates → System → Audit Process Creation`
- `Include command line in process creation events = Enabled`

Or registry:
```powershell
New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force
```

### Increase Security log size

GPO:
`Computer Configuration → Policies → Windows Settings → Security Settings → Event Log`
- Maximum Security Log Size: **262144** KB (256 MB)
- Retention method: Overwrite events as needed

Or via wevtutil:
```powershell
wevtutil sl Security /ms:268435456
```

### Forward logs to SIEM

Use Windows Event Forwarding (WEF) or your SIEM agent (Splunk UF, Elastic Agent, Sentinel AMA) to forward at minimum:
- Security: 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4720, 4726, 4732, 4756, 7045
- PowerShell: 4103, 4104
- Sysmon (if deployed): all configured events
- System: 7045 (service install)

## What might break

Nothing breaks. This only increases logging. The only operational impact is log storage and forwarding bandwidth. Plan for it, but there's no functional risk.

## Rollback

Set GPO audit subcategories to "Not Configured" or "No Auditing" and `gpupdate /force`.

## Validate the fix

```powershell
auditpol /get /subcategory:"Process Creation"
# Success

# Generate a test event
whoami
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 1
# Should show the whoami execution with CommandLine field populated
```

Confirm command-line logging:
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 1 |
    Select-Object @{N='CommandLine';E={$_.Properties[8].Value}}
# Should show the full command line, not blank
```

## References

- Microsoft: [Advanced Security Audit Policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- Microsoft: [Audit process creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- Microsoft: [Command line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- NSA / CISA: [Windows Event Logging Guidance](https://media.defense.gov/2022/Aug/18/2003062740/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) (Windows-specific guidance in the broader CTR series)
- Palantir: [Windows Event Forwarding guidance](https://github.com/palantir/windows-event-forwarding) — excellent starter WEF subscription set
