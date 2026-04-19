# Pre-Windows 2000 Compatible Access Group Contains Anonymous

**Category:** Domain Configuration
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Trivial

## What it is

`Pre-Windows 2000 Compatible Access` is a built-in domain local group created during AD installation to support NT 4.0 read access to AD. When the option "Permissions compatible with pre-Windows 2000 server operating systems" is selected during DCpromo (or when migrating from very old domains), the **Anonymous Logon** SID is added to this group.

The group has read access to large portions of AD via its ACL on the domain head and other containers. With Anonymous in it, unauthenticated callers can read user objects, group memberships, and other attributes that should require authentication.

## What attack it enables

Pre-authentication enumeration of AD — nearly identical impact to the [Anonymous SID enumeration](anonymous-sid-enumeration.md) finding, just via a different mechanism. Attackers harvest user lists, group memberships, and metadata for password spraying or AS-REP roasting before they have any credentials.

## How to confirm it's present

```powershell
Get-ADGroupMember 'Pre-Windows 2000 Compatible Access'
# Look for "Anonymous Logon" (SID S-1-5-7) in the membership.
```

If the membership includes `S-1-5-7`, you have the problem.

External validation:
```bash
# As anonymous, attempt to query AD via LDAP
ldapsearch -x -H ldap://<dc> -b "DC=example,DC=local" "(objectClass=user)" sAMAccountName
# If this returns users, Pre-Win2k Compatible Access is letting anonymous read.
```

## What to audit before remediation

The risk case for legitimate use is essentially zero in modern environments. NT 4.0 has not been supported since 2004. The audit question is just: is anything still relying on anonymous AD reads?

- Sample IIS logs on web servers with Integrated Windows Authentication for any anonymous LDAP fallback.
- Check appliance configs for "use anonymous bind" — replace with a service account.

## Remediation

```powershell
Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'S-1-5-7' -Confirm:$false
```

A reboot of the DC is sometimes required for the change to take full effect on long-cached LSA tokens. Schedule appropriately.

Optionally, also remove `Authenticated Users` from this group if it's present and your environment doesn't need it (some legacy apps do — test first).

## What might break

- Very old RAS servers, NT 4.0 BDCs (should not exist).
- Any application using anonymous LDAP bind to AD (uncommon and easy to fix by giving the app a service account).

## Rollback

```powershell
Add-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'S-1-5-7'
```
Reboot DC if needed.

## Validate

```powershell
Get-ADGroupMember 'Pre-Windows 2000 Compatible Access'
# Anonymous Logon should not appear.
```

Re-run the anonymous LDAP query — should now fail.

## References

- Microsoft: [Pre-Windows 2000 Compatible Access group](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#built-in-groups)
- MITRE ATT&CK: T1087.002
