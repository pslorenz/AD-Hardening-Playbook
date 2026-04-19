# Dangerous AD ACLs on Sensitive Objects (GenericAll, WriteDACL, WriteOwner, GenericWrite)

**Category:** AD Objects
**Operational Risk of Remediation:** Medium (depends on what depends on the ACE)
**Attacker Skill Required to Exploit:** Low (PowerView / BloodHound surface these)

## What it is

Active Directory objects (users, groups, computers, OUs, GPOs, the domain head itself) have ACLs. A handful of ACEs grant the holder enough rights to escalate privileges:

| Right | What it lets you do |
|---|---|
| `GenericAll` | Full control over the object — change password, modify any attribute, reset account, change ACL. |
| `WriteDACL` | Modify the object's ACL — grant yourself any other right, then exploit it. |
| `WriteOwner` | Take ownership, then grant yourself WriteDACL, then exploit. |
| `GenericWrite` | Modify most attributes — for users, change `servicePrincipalName` (Kerberoast), `userAccountControl` (disable preauth → AS-REP roast), `userPrincipalName` (ESC9), `msDS-KeyCredentialLink` (Shadow Credentials). For computers, configure RBCD. |
| `WriteProperty` on specific attributes | Same as GenericWrite for the targeted attribute. |
| `AllExtendedRights` | Includes "Reset Password" — change a user's password directly. |
| `ForceChangePassword` (extended right) | Same. |
| `Self` on group with `WriteProperty: member` | Add yourself to the group. |

When a low-privileged principal holds any of these on a sensitive object — Domain Admins, krbtgt, the domain root, a DC computer object, a service account in a privileged group — it's a direct escalation primitive.

## What attack it enables

Privilege escalation, often to Domain Admin in a single step. BloodHound's "shortest path to DA" queries lean heavily on these ACEs.

MITRE ATT&CK: T1098, T1484

## How to confirm it's present

Best approach: run BloodHound. It enumerates and visualizes these ACEs across the entire domain. See [`bloodhound-attack-paths.md`](../governance/bloodhound-attack-paths.md).

PowerShell spot-checks for the highest-value targets:

```powershell
# Function to list non-default ACEs on an object
function Get-DangerousAces {
    param([string]$DistinguishedName)
    $defaults = @('Domain Admins','Enterprise Admins','SYSTEM','Administrators','SELF','Account Operators','BUILTIN\Administrators','NT AUTHORITY\SYSTEM','Enterprise Read-only Domain Controllers')
    $acl = Get-Acl "AD:$DistinguishedName"
    $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights' -and
        ($defaults -notcontains ($_.IdentityReference -replace '^.*\\','')) -and
        ($defaults -notcontains $_.IdentityReference.Value)
    } | Select-Object @{N='Object';E={$DistinguishedName}}, IdentityReference, ActiveDirectoryRights, ObjectType
}

# Check the high-value targets
Get-DangerousAces (Get-ADDomain).DistinguishedName
Get-DangerousAces (Get-ADUser krbtgt).DistinguishedName
Get-DangerousAces (Get-ADGroup 'Domain Admins').DistinguishedName
Get-DangerousAces (Get-ADGroup 'Enterprise Admins').DistinguishedName

# Each Domain Controller's computer object
Get-ADDomainController -Filter * | ForEach-Object {
    Get-DangerousAces (Get-ADComputer $_.Name).DistinguishedName
}

# Every privileged group's members (user objects)
Get-ADGroupMember 'Domain Admins' -Recursive | ForEach-Object {
    Get-DangerousAces (Get-ADUser $_).DistinguishedName
}
```

## What to audit before remediation

For every problematic ACE, find out:
1. **When was it granted?** Check Event ID 5136 (directory object modified) on DCs to find the source change event if recent.
2. **Why was it granted?** Often: someone delegated "fix passwords for our department" but used the wrong tool or scope.
3. **What still uses it?** Removing an ACE that's actively used will break automation. Look for service accounts or scheduled tasks running under the principal.

Common false-positive sources:
- Exchange (especially older versions) creates large numbers of seemingly-broad ACEs that are actually Exchange-required. Don't blindly remove ACEs granted to Exchange groups.
- AD Connect creates specific ACEs for password writeback and other features.
- Some PAM/IGA products legitimately need WriteProperty on user attributes.

When in doubt, document and ask before removing.

## Remediation

Capture the current ACL first:
```powershell
$dn = "<sensitive object DN>"
(Get-Acl "AD:$dn").Sddl | Out-File "$env:TEMP\acl-backup-$($dn -replace '[^a-zA-Z0-9]','_').txt"
```

Remove the bad ACE:
```powershell
$dn = "<DN>"
$badPrincipal = "EXAMPLE\BadGroup"
$acl = Get-Acl "AD:$dn"
$badAces = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $badPrincipal }
foreach ($ace in $badAces) {
    $acl.RemoveAccessRuleSpecific($ace) | Out-Null
}
Set-Acl "AD:$dn" -AclObject $acl
```

For inherited ACEs, the source is on a parent OU — fix it there, or block inheritance with caution.

Replace with appropriate delegation:
- If the principal needed to reset passwords for a specific OU, delegate "Reset Password" on **that OU**, not on the domain root.
- If the principal needed to add members to a specific group, delegate "Modify members" on **that group**, not GenericAll.

Use the **Delegation of Control Wizard** (right-click OU → Delegate Control) for common patterns — it scopes properly and uses extended rights instead of GenericAll.

## What might break

- Scripts and automation running as the principal you removed rights from.
- Helpdesk workflows that depended on broad rights instead of scoped delegation.
- Some IGA/PAM products if their service account is incorrectly trimmed.

## Rollback

```powershell
$acl = Get-Acl "AD:$dn"
$acl.SetSecurityDescriptorSddlForm((Get-Content "$env:TEMP\acl-backup-...txt"))
Set-Acl "AD:$dn" -AclObject $acl
```

## Validate

Re-run the `Get-DangerousAces` checks. Re-run BloodHound and confirm the previously identified path is gone.

## Bonus: monitor for new dangerous ACEs going forward

Enable Audit Directory Service Changes (Subcategory) on DCs:
```powershell
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

Watch for **Event ID 5136** changes on sensitive objects. SIEM rule: alert when any ACE is added to Domain Admins, krbtgt, the domain head, DC computer objects, or any AdminSDHolder-protected object.

## References

- BloodHound CE: https://github.com/SpecterOps/BloodHound
- harmj0y: [An ACE Up The Sleeve](https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf)
- Microsoft: [Delegating administration in Active Directory](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732524(v=ws.11))
- MITRE ATT&CK: T1098, T1484
