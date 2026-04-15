# MachineAccountQuota = 10 (Default)

**Category:** Accounts & Policies
**Operational Risk of Remediation:** Low (in modern environments)
**Attacker Skill Required to Exploit:** Low (powermad / impacket)

## What it is

`ms-DS-MachineAccountQuota` is a domain-wide attribute that controls how many computer accounts a non-admin user can create. The default value is **10**. Yes, every regular domain user can join 10 computers to the domain and create 10 corresponding machine accounts they "own."

This was useful in 2003 when domain join was a self-service operation. In 2026, domain join is almost always done by IT or via Autopilot/Intune, and this default has become a key enabler of multiple modern AD attacks.

## What attack it enables

- **Resource-Based Constrained Delegation (RBCD) abuse**: an attacker creates a computer account, configures it as a delegation target on a victim machine, then impersonates any user (including DA) to that machine. Pivot to local SYSTEM.
- **noPac / sAMAccountName spoofing** (CVE-2021-42278/42287): create a computer account, rename it to spoof a DC, request a TGT, eventually obtain DC privileges. Patched, but the ability for users to create accounts at all is the precondition.
- **Shadow Credentials abuse**: attacker uses their ability to create accounts to set up persistence.

## How to confirm it's present in your environment

```powershell
Get-ADDomain | Select-Object DistinguishedName,
    @{N='MachineAccountQuota';E={(Get-ADObject $_.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'}}
# Default = 10. Anything > 0 is exploitable.
```

Test as a regular user:
```powershell
# As a normal domain user, with no special rights:
$pw = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-ADComputer -Name 'TestPwn' -AccountPassword $pw -SAMAccountName 'TestPwn$'
# If this succeeds, you have the problem.
# Clean up: Remove-ADComputer TestPwn -Confirm:$false
```

## What to audit before remediation

The audit question: does anyone in your org legitimately rely on regular users joining computers to the domain? In 99% of modern environments, no, joins are done by IT or by an automation account (e.g., Autopilot's account, an MDT account, an SCCM account).

To find historical computer account creators:
```powershell
# Event ID 4741 = Computer account created. Look at the SubjectUserName field.
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4741]]" -MaxEvents 1000 |
    Select-Object TimeCreated, @{N='Creator';E={$_.Properties[4].Value}}, @{N='ComputerCreated';E={$_.Properties[0].Value}} |
    Group-Object Creator | Sort-Object Count -Descending
```

If the only device creators are IT staff, service accounts, and Autopilot, you're safe to set MAQ to 0.

## Remediation

```powershell
Set-ADDomain -Identity (Get-ADDomain) -Replace @{ "ms-DS-MachineAccountQuota" = 0 }
```

Then delegate the **Create Computer Objects** permission on the appropriate OU (e.g., a `Workstations` OU) to your IT staff group or Autopilot service account. This way, only authorized accounts can create computer objects, and you control where they land in AD.

```powershell
# Example using dsacls
dsacls "OU=Workstations,DC=example,DC=local" /I:T /G "EXAMPLE\IT-DomainJoin:CC;computer"
```

## What might break

- Any user-driven domain-join process that doesn't use a delegated account. If IT joins all machines, nothing breaks.
- Some self-service VDI provisioning flows (Citrix, VMware Horizon) so confirm those use a service account with explicit Create Computer rights, which is the standard config.
- Autopilot: requires a delegated account or MDM-managed join confirm with your endpoint team.

## Rollback

```powershell
Set-ADDomain -Identity (Get-ADDomain) -Replace @{ "ms-DS-MachineAccountQuota" = 10 }
```
Effective immediately.

## Validate the fix

```powershell
Get-ADObject (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota'
# Value should be 0
```

Re-run the `New-ADComputer` test as a regular user. This should fail with "Access is denied."

## References

- Kevin Robertson: [Powermad](https://github.com/Kevin-Robertson/Powermad) — the tool that popularized abuse
- Microsoft: [MS-DS-Machine-Account-Quota attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-machineaccountquota)
- harmj0y: [A Case Study in Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- MITRE ATT&CK: T1136.002
