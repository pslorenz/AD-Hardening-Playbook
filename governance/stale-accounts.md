# Stale Accounts (Users and Computers)

**Category:** Governance
**Operational Risk of Remediation:** Medium (always disable before deleting)
**Attacker Skill Required to Exploit:** Low

## What it is

Active Directory accumulates accounts that are no longer in use:
- Departed employees whose accounts were never disabled.
- Service accounts for retired applications.
- Computer accounts for hardware that was decommissioned years ago.
- Test accounts from migrations and pilots.

Stale accounts are attacker gold:
- Passwords are often unchanged for years (weak by today's standards).
- No one notices logon activity from them.
- They often have lingering group memberships that grant access.
- Stale computer accounts may have weak passwords (the default "computer name + last 14 chars" pattern can be weak for old machines).

## What attack it enables

- Password spraying with a higher hit rate (stale accounts have older, weaker passwords).
- Logon as a stale account goes unnoticed by anyone who would otherwise spot anomalous activity.
- Stale computer accounts can sometimes be repurposed by attackers (Shadow Credentials, RBCD).

## How to confirm it's present

```powershell
# Users not logged in for 90 days, still enabled
$threshold = (Get-Date).AddDays(-90)
Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $threshold } -Properties LastLogonDate, PasswordLastSet, Description |
    Sort-Object LastLogonDate |
    Select-Object SamAccountName, LastLogonDate, PasswordLastSet, Description

# Users with passwords never expiring AND old passwords
Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordLastSet |
    Where-Object { $_.PasswordLastSet -lt (Get-Date).AddYears(-1) } |
    Select-Object SamAccountName, PasswordLastSet

# Computers not logged on in 90 days
Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate, OperatingSystem |
    Where-Object { $_.LastLogonDate -lt $threshold } |
    Sort-Object LastLogonDate |
    Select-Object Name, OperatingSystem, LastLogonDate
```

Note: `LastLogonDate` is replicated only every ~14 days, so it can lag. For exact data, query `lastLogon` on each DC and take the most recent value.

## What to audit before remediation

This is the section that prevents tickets. **Never delete an account without first disabling it for a quarantine period.** Common gotchas:

- An account that "hasn't logged in" may be a service account whose service runs interactively rarely (quarterly batch job, year-end close).
- A computer account that hasn't logged on in 90 days may be a laptop belonging to someone on extended leave.
- Service accounts often have empty `LastLogonDate` because they authenticate via Kerberos service tickets, not interactive logons. Check for SPN activity instead.

Workflow:
1. Identify stale accounts.
2. Send a disable notice to the apparent owner (from `Description` or `ManagedBy`).
3. Disable for 30–90 days. Move to a "Disabled" OU. Watch for tickets.
4. Delete after the quarantine period.

For service accounts specifically: check Event ID 4769 on DCs to see if anyone is still requesting tickets for the SPN. If yes, it's not stale.

## Remediation

```powershell
# Disable (don't delete) stale users
Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $threshold } |
    Where-Object { $_.SamAccountName -notmatch 'krbtgt|guest|administrator' } |
    ForEach-Object {
        Set-ADUser $_ -Enabled $false -Description ("DISABLED $(Get-Date -Format yyyy-MM-dd) - stale: " + $_.Description)
        Move-ADObject $_ -TargetPath 'OU=Disabled Users,DC=example,DC=local'
    }

# Disable stale computers
Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -lt $threshold } |
    ForEach-Object {
        Set-ADComputer $_ -Enabled $false
        Move-ADObject $_ -TargetPath 'OU=Disabled Computers,DC=example,DC=local'
    }
```

After 30–90 days in the Disabled OU with no complaints, delete:

```powershell
Get-ADUser -SearchBase 'OU=Disabled Users,DC=example,DC=local' -Filter * -Properties whenChanged |
    Where-Object { $_.whenChanged -lt (Get-Date).AddDays(-90) } |
    Remove-ADUser -Confirm:$false
```

Going forward: integrate AD account lifecycle with HR offboarding so accounts are disabled the day someone leaves, not 4 years later.

## What might break

- The infrequently-used service account that you didn't realize was used. Symptom: a batch job fails next time it runs.
- A laptop coming back from long-term storage that needs to rejoin the domain.

The disable-then-delete pattern catches most of these in the disabled phase, where re-enabling is one click.

## Rollback

```powershell
Set-ADUser <user> -Enabled $true
Move-ADObject <user-DN> -TargetPath '<original-OU>'
```

If already deleted, restore from AD Recycle Bin (which **must be enabled** in advance — `Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>`).

## Validate

Re-run the stale-account queries — counts should drop dramatically. Set a quarterly recurring report so this stays clean.

## References

- Microsoft: [AD Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#bkmk_adrecyclebin)
- MITRE ATT&CK: T1078.002
