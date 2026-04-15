# Unconstrained Delegation

**Category:** Kerberos
**Operational Risk of Remediation:** Medium (depends on what the system actually does)
**Attacker Skill Required to Exploit:** Medium

## What it is

When a computer or user account has the `TRUSTED_FOR_DELEGATION` flag, any user who authenticates to that host via Kerberos sends a copy of their TGT, which is cached in memory on the host. If an attacker compromises that host, they extract every cached TGT including any privileged user's TGT, and use them to impersonate those users anywhere in the domain.

Combined with coercion bugs (PrinterBug, PetitPotam), an attacker can force a Domain Controller to authenticate to the unconstrained-delegation host, capture the DC's TGT, and immediately have full domain compromise.

## What attack it enables

- Domain takeover via credential capture from any host configured for unconstrained delegation.
- Particularly dangerous when combined with print spooler running on DCs (see [`print-spooler-on-dc.md`](../legacy/print-spooler-on-dc.md)).

MITRE ATT&CK: T1558, T1134

## How to confirm it's present in your environment

```powershell
# Computer accounts with unconstrained delegation
Get-ADComputer -Filter { TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516 } -Properties TrustedForDelegation, OperatingSystem |
    Select-Object Name, OperatingSystem, TrustedForDelegation
# (PrimaryGroupID 516 = Domain Controllers, which legitimately have this)

# User accounts with unconstrained delegation (these are extra suspicious)
Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object SamAccountName, TrustedForDelegation
```

Any non-DC computer in this list is a high-priority target. Any user in this list almost certainly should not be configured this way.

## What to audit before remediation

For each host with unconstrained delegation, find out:
- What service runs on it that "needed" delegation? (Often nothing as the checkbox was ticked years ago and never reviewed.)
- Could it use **constrained delegation** or **resource-based constrained delegation (RBCD)** instead? Both limit which services the cached ticket can access.
- Is the host owner aware?

Check Event ID 4769 on the host (Kerberos service ticket operations) to see what services it actually delegates to.

## Remediation

**For each affected host, choose one:**

**Option 1: Remove delegation entirely (best, if it isn't actually used):**
```powershell
Get-ADComputer <name> | Set-ADAccountControl -TrustedForDelegation $false
```

**Option 2L Migrate to constrained delegation:**
```powershell
# Allow this computer to delegate ONLY to specific SPNs
Set-ADComputer <name> -Clear "userAccountControl" -Add @{ "msDS-AllowedToDelegateTo" = @("HOST/target1.example.local","HOST/target2.example.local") }
# Then clear TrustedForDelegation
Set-ADAccountControl -Identity <name> -TrustedForDelegation $false
```

**Option 3: Migrate to RBCD (resource-based constrained delegation), where the *target* host controls which accounts can delegate to it.** Often cleaner administratively.

**Additionally:** Add all sensitive accounts to the **Protected Users** group (see [`protected-users-not-used.md`](../privileged-access/protected-users-not-used.md)) and set the "Account is sensitive and cannot be delegated" flag on them so their TGTs are never cached on a delegation host even if one exists.

```powershell
Get-ADUser -Filter { AdminCount -eq 1 } | ForEach-Object {
    Set-ADAccountControl -Identity $_ -AccountNotDelegated $true
}
```

## What might break

- Whatever service was relying on delegation. Most commonly: old SQL Server linked-server configs, old IIS sites with Kerberos delegation for backend SQL access, some SharePoint configurations.
- If you remove delegation and a service breaks, the symptom is usually "double-hop authentication failure" the front end works but a backend resource fails to authenticate as the user.

## Rollback

```powershell
Get-ADComputer <name> | Set-ADAccountControl -TrustedForDelegation $true
```
Effective immediately. Reboot the host to clear/refresh tickets.

## Validate the fix

```powershell
Get-ADComputer -Filter { TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516 }
# Should be empty or only contain known-required exceptions.
```

For sensitive accounts:
```powershell
Get-ADUser -Filter { AdminCount -eq 1 } -Properties AccountNotDelegated |
    Where-Object { -not $_.AccountNotDelegated }
# Should be empty.
```

## References

- Sean Metcalf: [Active Directory Security – Unconstrained Delegation](https://adsecurity.org/?p=1667)
- harmj0y: [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
- MITRE ATT&CK: T1558, T1134.003
