# BloodHound-Driven Attack Path Remediation

**Category:** Governance (Methodology)
**Operational Risk of Remediation:** Variable (depends on what paths exist)
**Attacker Skill Required to Exploit:** Low (BloodHound shows attackers the exact path)

## What it is

BloodHound (and its successor BloodHound CE / BloodHound Enterprise from SpecterOps) ingests AD data and graphs the relationships between users, groups, computers, GPOs, and ACLs. It then computes **attack paths** — chains of legitimate-looking permissions that, when combined, let a low-privileged user reach Domain Admin (or any chosen target).

This is not a misconfiguration finding per se. It's a methodology for finding misconfigurations you'd never spot by reading individual ACLs. In every environment that has never been audited this way, BloodHound finds attack paths. Often dozens of them.

If you do nothing else from this repo, run BloodHound. The findings will tell you which specific docs in `findings/` to read first.

## What attack it enables

Whatever your graph shows. Common findings:
- "Helpdesk group has GenericWrite on a service account that's a member of Backup Operators that can DCSync."
- "Authenticated Users has WriteOwner on a GPO linked to the Domain Controllers OU." (Game over.)
- "User X is a member of 7 nested groups, one of which has Local Admin on a server that another DA logs into weekly." (Credential theft → DA.)

## How to run BloodHound (defender mode)

You can run this against your own AD with read-only credentials. No network attacks required.

**Collection (SharpHound):**
```powershell
# Download SharpHound from https://github.com/SpecterOps/SharpHound
# Run as a regular domain user (no special rights needed for default collection)
.\SharpHound.exe -c All
# Produces a zip of JSON files describing the domain.
```

**Analysis (BloodHound CE):**
- Stand up BloodHound CE locally (Docker compose, ~5 minutes).
- Import the zip from SharpHound.
- Run pre-built queries:
  - **"Shortest paths to Domain Admins"** — start here.
  - "Users with paths to high-value targets"
  - "Find principals with DCSync rights"
  - "Kerberoastable users with admin rights"
  - "Users that can RDP to high-value targets"

Each path is clickable and shows the specific ACE / group membership / configuration that enables it.

## What to audit before remediating paths

For every BloodHound-identified path, ask:

1. **Is the permission actually needed?** Often it was granted years ago for a reason no one remembers.
2. **Is it granted to the right principal?** "Domain Users has WriteDACL on server X" is almost certainly wrong; "Server Operators have WriteDACL on server X" might be intentional.
3. **What is the cleanest cut?** Sometimes removing one ACE breaks five paths. Sometimes you need to remove the principal from a group instead. Sometimes the right fix is upstream (move the high-value target, not change the ACL).

Before changing any ACE, check what depends on it:
- Run `Get-Acl` on the target object and examine inheritance.
- If the ACE is inherited from a parent OU, fix at the parent — but understand the wider effect.
- Check Event ID 4670 (permissions on object changed) recent history to see if the ACE was set recently and intentionally.

## Remediation patterns

Different path types call for different remediations. Cross-references:

| BloodHound finding | See |
|---|---|
| Kerberoastable user with privileged group membership | [`kerberoasting.md`](../kerberos/kerberoasting.md) |
| AS-REP roastable account | [`asreproasting.md`](../kerberos/asreproasting.md) |
| Unconstrained delegation host | [`unconstrained-delegation.md`](../kerberos/unconstrained-delegation.md) |
| User with GenericAll/WriteDACL/etc. on sensitive object | [`dangerous-acls.md`](../ad-objects/dangerous-acls.md) |
| Domain Admin RDP'ing to workstations | [`domain-admins-on-workstations.md`](../privileged-access/domain-admins-on-workstations.md) |
| ESC1-11 cert template / CA findings | `findings/adcs/` |
| Owned principals via shared local admin | [`laps-not-deployed.md`](../accounts-policies/laps-not-deployed.md) |

For paths that don't fit a category in this repo, the general approach:

1. Identify the choke point — the single ACE or group membership that, if removed, kills the most paths.
2. Confirm operational impact.
3. Remove during a change window.
4. Re-collect and verify the path is gone.

## What might break

Anything that depended on the permission you removed. Specific risk areas:

- ACE removals can break service automation that wasn't documented.
- Group membership removals can take effect immediately for some scenarios (Kerberos: at next ticket request) and require re-logon for others.
- GPO ACL changes can cause GPOs to stop applying to some scopes — verify with `gpresult /R` after.

## Rollback

For ACE changes, capture the SDDL before and after:
```powershell
$dn = "CN=Target,DC=example,DC=local"
$before = (Get-Acl "AD:$dn").Sddl
$before | Out-File backup-acl.txt
# ... make changes ...
# To rollback:
$acl = Get-Acl "AD:$dn"
$acl.SetSecurityDescriptorSddlForm((Get-Content backup-acl.txt))
Set-Acl "AD:$dn" $acl
```

## Validate

Re-run SharpHound and re-import. The previously identified paths should be gone, no new paths should appear.

Track the number of unprivileged-user-to-DA paths over time as a metric. The goal is **zero**.

## References

- BloodHound CE: https://github.com/SpecterOps/BloodHound
- SharpHound docs: https://bloodhound.readthedocs.io/
- SpecterOps blog (extensive case studies on path remediation): https://posts.specterops.io/
- PingCastle: https://www.pingcastle.com/ — alternative AD audit tool, complementary to BloodHound, less graph-focused but excellent at scoring.
- Purple Knight: https://www.purple-knight.com/ — free AD assessment tool from Semperis
