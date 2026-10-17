# Insufficient audit policy and logging

| | |
|---|---|
| **Category** | Detection and logging |
| **Likelihood of operational impact** | Low (log volume and SIEM cost are the real risks) |
| **Time to remediate** | 1–2 weeks including a pilot |
| **Applies to** | Domain controllers, member servers, workstations, AD CS servers |

---

## What it is

Windows records very little security-relevant activity out of the box. The default audit settings miss most of what matters for detecting AD attacks, the default 20 MB Security log on a busy domain controller can roll over in minutes, and PowerShell activity and process command lines aren't logged at all.

A second, very common problem is a policy that *looks* configured but isn't effective. If someone set the legacy "Audit Policy" categories (often in the Default Domain Controllers Policy) and nobody enabled **"Audit: Force audit policy subcategory settings to override audit policy category settings"**, the legacy settings can silently overwrite your Advanced Audit Policy.

### What it enables

This finding doesn't enable an attack directly. It lets every other attack in this repo happen without a trace. Without proper auditing you can't detect or investigate:

- Kerberoasting and AS-REP roasting (4769, 4768)
- Password spraying and brute force (4625, 4771, 4776)
- DCSync and AD ACL abuse (4662, 5136)
- Privileged group changes (4728, 4732, 4756)
- Lateral movement and Domain Admin logons on workstations (4624, 4672)
- Persistence via services and scheduled tasks (4697, 4698)
- Malicious PowerShell (4104)
- ESC1-style certificate abuse (4886, 4887)
- An attacker disabling auditing or clearing logs (4719, 1102)

It also means that after an incident, your investigation starts from nothing.

---

## How to confirm it's present

**1. Check the effective audit policy** on a sample DC, member server, and workstation. Run from an elevated prompt:

```powershell
auditpol /get /category:*
```

If most subcategories show `No Auditing`, or key ones from the baseline table below are missing, the finding is confirmed.

**2. Check effective policy across all DCs at once:**

```powershell
$dcs = (Get-ADDomainController -Filter *).HostName
Invoke-Command -ComputerName $dcs -ScriptBlock {
    auditpol /get /category:* /r | ConvertFrom-Csv |
        Where-Object { $_.'Inclusion Setting' -eq 'No Auditing' } |
        Select-Object 'Machine Name', Subcategory
} | Format-Table -AutoSize
```

**3. Check whether the subcategory override is enabled.** A value of `1` means enabled; missing or `0` means legacy categories can override your settings.

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue
```

**4. Check Security log size and retention.** If the oldest event on a DC is only hours old, you can't investigate anything that happened yesterday.

```powershell
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, FileSize, RecordCount
(Get-WinEvent -LogName Security -MaxEvents 1 -Oldest).TimeCreated
```

**5. Check command-line and PowerShell logging:**

```powershell
# Process command line in 4688 (1 = enabled)
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue

# PowerShell script block logging (1 = enabled)
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
```

PingCastle and Purple Knight both report on DC audit policy and are a quick way to confirm this at scale.

---

## What to audit before changing anything

Auditing rarely breaks applications. What it breaks is budgets, disks, and SIEM licenses. Do this homework first.

**1. Back up the current effective policy** on a representative DC, server, and workstation so you have something to compare against:

```powershell
auditpol /backup /file:C:\Temp\auditpol-backup-$env:COMPUTERNAME.csv
```

**2. Find every GPO that sets audit policy.** Look for both the legacy "Audit Policy" node and "Advanced Audit Policy Configuration." Conflicting GPOs are the most common reason audit settings don't stick.

```powershell
gpresult /h C:\Temp\gpresult.html
```

Pay particular attention to the **Default Domain Controllers Policy**, which often has legacy audit settings from years ago.

**3. Check for local scripts or tools** that run `auditpol /set` at startup (old hardening scripts, vendor agents). They'll fight your GPO.

**4. Measure current log volume.** Note Security log events per hour on a DC, a busy file server, and a workstation. You'll compare this against the pilot.

**5. Talk to whoever owns the SIEM.** Ask what the ingestion license allows and whether Windows Event Forwarding (WEF) or an agent is collecting logs today. Expect Security log volume on DCs to rise noticeably. Kerberos Service Ticket Operations (4769) and Logon (4624) are the biggest contributors.

**6. Check free disk space** on the system drive of DCs and servers before raising log sizes.

**7. Decide who can read PowerShell logs.** Script block logging records the full content of scripts that run, so any script with a hardcoded password will put that password in the log. Before enabling it, make sure access to `Microsoft-Windows-PowerShell/Operational` and its SIEM index is restricted.

---

## Remediation

Use **Advanced Audit Policy Configuration**, not the legacy nine audit categories. Create two GPOs:

- **`SEC - Audit Policy - Domain Controllers`** linked to the Domain Controllers OU
- **`SEC - Audit Policy - Members`** linked to OUs containing servers and workstations

Pilot the Members GPO on a test OU for a week before linking it broadly.

### Step 1: Enable the subcategory override

In both GPOs:

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`

- **Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings** = **Enabled**

Then remove legacy audit settings from any other GPO (including the Default Domain Controllers Policy), setting each back to "Not Defined."

### Step 2: Configure Advanced Audit Policy

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`

S = Success, F = Failure, blank = leave at Not Configured.

| Category | Subcategory | DCs | Members | Key events | Why it matters |
|---|---|---|---|---|---|
| Account Logon | Credential Validation | S/F | S/F | 4776 | NTLM use, password spray |
| Account Logon | Kerberos Authentication Service | S/F | | 4768, 4771 | AS-REP roasting, spray |
| Account Logon | Kerberos Service Ticket Operations | S/F | | 4769 | Kerberoasting, honey SPNs |
| Account Management | Computer Account Management | S | | 4741, 4742 | MachineAccountQuota abuse, RBCD |
| Account Management | Security Group Management | S | S | 4728, 4732, 4756 | Privileged group changes |
| Account Management | User Account Management | S/F | S/F | 4720, 4724, 4738, 4740 | New accounts, resets, lockouts |
| Account Management | Other Account Management Events | S | S | 4782 | Password hash access |
| Detailed Tracking | Process Creation | S | S | 4688 | Command execution |
| Detailed Tracking | Plug and Play Events | S | S | 6416 | USB devices (optional) |
| DS Access | Directory Service Access | S/F | | 4662 | DCSync, honey object reads |
| DS Access | Directory Service Changes | S | | 5136, 5137, 5141 | ACL, GPO, delegation changes |
| Logon/Logoff | Logon | S/F | S/F | 4624, 4625 | Lateral movement, failed logons |
| Logon/Logoff | Logoff | S | S | 4634 | Session tracking |
| Logon/Logoff | Account Lockout | F | F | 4625 | Brute force |
| Logon/Logoff | Special Logon | S | S | 4672 | Privileged logons |
| Logon/Logoff | Other Logon/Logoff Events | S/F | S/F | 4778, 4779 | RDP session reconnects |
| Logon/Logoff | Group Membership | S | S | 4627 | Group membership at logon |
| Object Access | Certification Services | S/F (CAs only) | | 4886, 4887 | Certificate requests and issuance |
| Object Access | File Share | S/F | S/F | 5140 | Share access, SYSVOL hunting |
| Object Access | Other Object Access Events | S/F | S/F | 4698, 4702 | Scheduled task persistence |
| Object Access | Removable Storage | | S/F | 4663 | USB exfiltration |
| Policy Change | Audit Policy Change | S/F | S/F | 4719 | Attacker disabling auditing |
| Policy Change | Authentication Policy Change | S | S | 4706, 4713 | Trust and Kerberos policy changes |
| Policy Change | Authorization Policy Change | S | S | 4704 | User rights assignment changes |
| Privilege Use | Sensitive Privilege Use | S/F | S/F | 4673, 4674 | Privilege abuse |
| System | Security State Change | S | S | 4608, 4616 | Startup, time changes |
| System | Security System Extension | S | S | 4697 | New services installed |
| System | System Integrity | S/F | S/F | 4612 | Tampering, dropped audit events |
| System | Other System Events | S/F | S/F | 5024, 5025 | Firewall service changes |

Event **1102** (Security log cleared) is always logged regardless of policy. Alert on it everywhere.

**Deliberately left out of the baseline:**

- **Filtering Platform Connection** (5156/5157) produces an enormous volume of events. Enable only for specific investigations.
- **Detailed File Share** (5145) is very noisy on DCs and file servers. Enable temporarily when hunting.
- **File System** and **Registry** do nothing without SACLs on specific objects. Handle them per use case rather than in a baseline.

**For lab or one-off testing only**, the same settings can be applied locally with `auditpol`. In production, always use GPO, because a local change is overwritten at the next policy refresh.

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

### Step 3: Turn on command-line logging for process creation

In both GPOs:

`Computer Configuration → Policies → Administrative Templates → System → Audit Process Creation`

- **Include command line in process creation events** = **Enabled**

Without this, 4688 tells you `powershell.exe` ran but not what it ran.

### Step 4: Turn on PowerShell logging

In both GPOs:

`Computer Configuration → Policies → Administrative Templates → Windows Components → Windows PowerShell`

- **Turn on PowerShell Script Block Logging** = **Enabled** (event 4104). Leave "Log script block invocation start/stop events" unchecked; it adds lots of volume for little value.
- **Turn on Module Logging** = **Enabled**, with module name `*` (event 4103).

Events land in `Applications and Services Logs → Microsoft → Windows → PowerShell → Operational`. Script block logging captures deobfuscated code, which makes it one of the highest-value settings in this finding.

### Step 5: Size the event logs

`Computer Configuration → Policies → Administrative Templates → Windows Components → Event Log Service → Security`

- **Specify the maximum log file size (KB)**:
  - Domain controllers: 1048576–4194240 (1–4 GB)
  - Member servers: 524288–1048576 (512 MB–1 GB)
  - Workstations: 262144–524288 (256–512 MB)

Leave **"Control Event Log behavior when the log file reaches its maximum size"** at its default (overwrite as needed). See "What it might break" for why.

For the PowerShell Operational log, there's no built-in Administrative Template, so set it with a GPO Preference registry item or run this once per machine:

```powershell
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456
```

Local logs are only a buffer. Forward them to a SIEM or Windows Event Collector so that retention doesn't depend on log size and an attacker clearing a log doesn't destroy your evidence.

### Step 6: Add SACLs so DS Access events actually fire

Directory Service Changes (5136) and Directory Service Access (4662) only generate events for objects with auditing entries (SACLs). This script adds an audit entry for Everyone on three high-value objects: the domain root, AdminSDHolder, and the Domain Controllers OU.

```powershell
Import-Module ActiveDirectory
$domainDN = (Get-ADDomain).DistinguishedName
$targets  = @(
    $domainDN,
    "CN=AdminSDHolder,CN=System,$domainDN",
    "OU=Domain Controllers,$domainDN"
)

$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights   = [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty, WriteDacl, WriteOwner, ExtendedRight'
$rule     = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyone,
    $rights,
    [System.Security.AccessControl.AuditFlags]::Success,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

foreach ($t in $targets) {
    $acl = Get-Acl -Path "AD:\$t" -Audit
    $acl.AddAuditRule($rule)
    Set-Acl -Path "AD:\$t" -AclObject $acl
    Write-Host "Added audit rule to $t"
}
```

Including `ExtendedRight` on the domain root is what lets 4662 catch DCSync (look for replication GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` and `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` requested by an account that isn't a DC). Normal DC-to-DC replication will also generate these events, so filter out DC computer accounts in your detection rule.

Honey accounts need their own read SACL. See the [honey accounts finding](honey-accounts-and-spns.md).

### Step 7: Enable auditing on AD CS servers

The Certification Services subcategory only produces events once auditing is also enabled on the CA itself. On each CA:

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
```

---

## What it might break

**Operational impact is low.** Auditing doesn't change how authentication or applications behave. The risks are:

- **SIEM ingestion cost.** This is the most likely "breakage." The pilot week tells you the real number before you commit.
- **Disk space.** Larger logs need space on the system drive. Confirm free space first, especially on older DCs with small C: drives.
- **Secrets in PowerShell logs.** Script block logging will capture any credentials hardcoded in scripts. Restrict log access, and treat anything it surfaces as a finding to fix in the script. For extra protection, look into Protected Event Logging, which encrypts 4104 content with a certificate.
- **Do not enable "Audit: Shut down system immediately if unable to log security audits"** or set the Security log to "Do not overwrite events." Either one can halt a domain controller when the log fills up. They show up in some compliance checklists; ignore them unless you have a specific regulatory requirement and a plan to manage it.
- **Conflicting GPOs.** If a legacy audit setting somewhere still applies, you may see settings flip back after policy refresh. That's a symptom of skipping the "audit before changing" step, not of the policy itself.

### Rollback

1. Unlink the audit GPO (or set it to "Not Configured" for the problem subcategory).
2. Run `gpupdate /force` on affected systems.
3. If needed, restore the pre-change baseline captured earlier:

```powershell
auditpol /restore /file:C:\Temp\auditpol-backup-$env:COMPUTERNAME.csv
```

4. To remove the SACLs from Step 6, run the same script with `$acl.RemoveAuditRule($rule)` in place of `AddAuditRule`.

---

## How to validate the fix worked

**1. Confirm the effective policy** on a DC, a server, and a workstation. Every subcategory in the baseline table should show the expected setting:

```powershell
gpupdate /force
auditpol /get /category:*
```

**2. Generate test events and confirm they appear locally.** Use a dedicated test account and test group, never a real privileged group.

| Action | Expected event |
|---|---|
| Failed logon: `net use \\localhost\IPC$ /user:testuser WrongPassword` | 4625 |
| Create a test user: `New-ADUser -Name audit-test-user` | 4720 |
| Add it to a test group: `Add-ADGroupMember -Identity audit-test-group -Members audit-test-user` | 4728 or 4732 |
| Create a scheduled task: `schtasks /create /tn AuditTest /tr notepad.exe /sc once /st 23:59` | 4698 |
| Run a command: `whoami /groups` | 4688 with full command line |
| Run PowerShell: `Write-Output 'audit test'` | 4104 in PowerShell/Operational |
| Modify an attribute on the Domain Controllers OU (e.g. its description) | 5136 on a DC |

Check for them:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4688, 4698, 4720 } -MaxEvents 20 |
    Select-Object TimeCreated, Id, Message | Format-List

Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 5 |
    Select-Object TimeCreated, Message | Format-List
```

**3. Confirm the events reached the SIEM.** This is the step people skip. A log that only exists on the endpoint doesn't help when the endpoint is compromised.

**4. Re-check retention after a week.** Confirm the oldest event in the Security log on a DC goes back far enough to be useful (several days at minimum), and compare SIEM volume to your pre-change measurements.

**5. Clean up** the test user, test group, and scheduled task.

---

## Related findings

Once this is in place, the detections for these findings become possible:

- [Kerberoasting](../kerberos/kerberoasting.md): 4769 with RC4 encryption type (0x17)
- [AS-REP roasting](../kerberos/asreproasting.md): 4768 with pre-auth type 0
- [Weak account lockout / password spray](../accounts-policies/weak-account-lockout-and-spray.md): 4625, 4771, 4776 spread across many accounts
- [AD ACL misconfigurations](../privileged-access/ad-acl-misconfigurations.md): 5136 on sensitive objects
- [Domain Admins on workstations](../privileged-access/domain-admins-on-workstations.md): 4624 and 4672 for Tier 0 accounts on non-Tier 0 hosts
- [ESC1 misconfigured templates](../adcs/esc1-misconfigured-templates.md): 4886, 4887 with a mismatched subject
- [Honey accounts and SPNs](honey-accounts-and-spns.md): 4769 or 4662 for any honey object

## Next steps

Native Windows auditing covers the basics. For deeper endpoint visibility (network connections per process, image loads, registry persistence), add **Sysmon** with a maintained community configuration and forward its log alongside the Security log.

## References

- Microsoft: Advanced security audit policy settings
- Microsoft: Audit Policy Recommendations
- Microsoft Security Compliance Toolkit (baseline GPOs)
- Microsoft: About Logging Windows (PowerShell)

