# Domain Admins Logging Into Workstations

**Category:** Privileged Access
**Operational Risk of Remediation:** Medium (cultural change as much as technical)
**Attacker Skill Required to Exploit:** Low (mimikatz)

## What it is

When a privileged account logs into a workstation (interactive or RDP), credential material is cached in LSASS memory. Any local admin on that workstation — including malware running as the user, since most users are admin on at least one machine — can extract those credentials with `mimikatz`. Domain Admins should never log into anything except Domain Controllers and dedicated Privileged Access Workstations (PAWs).

This is the foundation of "tier 0 / tier 1 / tier 2" administrative isolation. Without it, the first phishing victim in the company is one DA login away from full domain compromise.

## What attack it enables

Credential theft from any host a DA touches → the attacker now has DA → game over.

MITRE ATT&CK: T1003

## How to confirm it's present in your environment

Find recent interactive/RDP logons of privileged users on non-DC hosts.

```powershell
# Get the list of Domain Admins (and equivalent groups)
$privGroups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators'
$privUsers = $privGroups | ForEach-Object {
    Get-ADGroupMember $_ -Recursive -ErrorAction SilentlyContinue
} | Select-Object -ExpandProperty SamAccountName -Unique

# Then on each non-DC server/workstation, query Security log for 4624 with these users:
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10']]" -MaxEvents 5000 |
    Where-Object { $privUsers -contains $_.Properties[5].Value } |
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}, @{N='Source';E={$_.Properties[18].Value}}
```

LogonType 2 = interactive console, LogonType 10 = RDP. Either one on a non-DC is the problem.

## What to audit before remediation

The "audit" here is mostly conversational:
- Who's currently using DA accounts and for what?
- Do those tasks actually require DA, or just local admin?
- Are there scheduled tasks, services, or scripts running as DA across the fleet? (Find with `Get-ScheduledTask` and `Get-Service` queries.)

You'll find that 80–95% of "DA usage" is people who have a DA account because they always have, doing tasks that don't actually require DA. Tier them out:
- **Tier 0** (DA, EA, DCs, ADCS, ADFS, PKI, AAD Connect): only used from PAWs, only against tier 0 systems.
- **Tier 1** (servers, applications): server admins, never log into workstations.
- **Tier 2** (workstations): helpdesk admins, never log into servers or DCs.

## Remediation

This is a multi-step program, not a single GPO flip.

**Step 1 — Build the policy.** Define your tier model. Document which accounts belong to which tier and what they can log into.

**Step 2 — Block tier 0 accounts from logging into tier 1/2 hosts** via GPO:

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment`:
- `Deny log on locally` — add Domain Admins, Enterprise Admins, Schema Admins
- `Deny log on through Remote Desktop Services` — same groups
- `Deny access to this computer from the network` — same groups (more restrictive; only do this once tier-1 admin tooling is converted)

Apply this GPO to **all OUs except the Domain Controllers OU and the PAW OU**.

**Step 3 — Add all privileged users to the Protected Users group** (see [`protected-users-not-used.md`](protected-users-not-used.md)). This prevents NTLM auth, prevents long-lived TGTs, and prevents credential delegation/caching for those accounts.

**Step 4 — Set "Account is sensitive and cannot be delegated" on every privileged account:**
```powershell
Get-ADGroupMember 'Domain Admins' -Recursive | Get-ADUser | ForEach-Object {
    Set-ADAccountControl -Identity $_ -AccountNotDelegated $true
}
```

**Step 5 — Enable LSA Protection (RunAsPPL)** on workstations and servers to make credential dumping harder:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -PropertyType DWord
# Reboot
```

**Step 6 — Deploy LAPS** so admins use a unique local admin password per workstation instead of a domain account (see [`laps-not-deployed.md`](../accounts-policies/laps-not-deployed.md)).

**Step 7 — Build and use Privileged Access Workstations** for tier 0 work.

## What might break

- Anything currently scheduled to run as a DA on a workstation will fail. Identify and reconfigure to use a gMSA or a tier-1 service account.
- Some legacy management tools assume the admin can RDP everywhere — replace with proper tier 1/2 admin accounts.
- Cultural pushback. "I've always logged into this server with my DA account." That habit is the problem.

## Rollback

Remove the deny-logon User Rights Assignments from the GPO and `gpupdate /force`. Effective immediately.

## Validate the fix

After deployment, attempt to RDP to a regular workstation as a Domain Admin — should be denied with "The system administrator has restricted the types of logon you may use."

Re-run the 4624 query above. There should be zero DA logons on non-DC hosts.

## References

- Microsoft: [Securing Privileged Access](https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview)
- Microsoft: [Active Directory administrative tier model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- MITRE ATT&CK: T1003.001
