# Too Many Local Administrators

**Category:** Endpoint Hardening
**Operational Risk of Remediation:** Medium (cultural change)
**Attacker Skill Required to Exploit:** Trivial (any local admin can dump LSASS, install persistence, pivot)

## What it is

Every member of the local `Administrators` group on a workstation or server can:
- Read LSASS memory (credential theft).
- Install services and drivers (persistence, rootkits).
- Modify the firewall, disable AV/EDR.
- Access administrative shares on the host.
- Modify any file, registry key, or scheduled task.

In many environments, "Domain Users" or a very large IT group is a member of local Administrators on workstations, often because it was easier than fixing the one app that needed admin rights in 2010. The result: every domain user is a local admin on every workstation, and a single compromised credential gives the attacker full control of the host and everything cached on it.

## What attack it enables

- LSASS credential dumping from any compromised account.
- Lateral movement via administrative shares (C$, ADMIN$).
- Privilege escalation: if a regular user is local admin, "local priv esc" is free.
- Persistence: install services, scheduled tasks, WMI subscriptions.
- UAC bypass: most UAC bypasses require local admin group membership.

MITRE ATT&CK: T1078.003, T1003.001

## How to confirm it's present

**Single host:**
```powershell
Get-LocalGroupMember -Group 'Administrators'
# Look for Domain Users, Authenticated Users, or large departmental groups.
```

**At scale:**
```powershell
$sample = Get-ADComputer -Filter 'OperatingSystem -like "*Windows 10*" -or OperatingSystem -like "*Windows 11*"' -Properties Name |
    Select-Object -ExpandProperty Name | Get-Random -Count 50

foreach ($h in $sample) {
    try {
        Invoke-Command -ComputerName $h -ScriptBlock {
            Get-LocalGroupMember -Group 'Administrators' | Select-Object @{N='Host';E={$env:COMPUTERNAME}}, Name, ObjectClass, PrincipalSource
        } -ErrorAction Stop
    } catch {}
} | Export-Csv admin-audit.csv -NoTypeInformation
```

Review the CSV. Expected good state: the built-in Administrator account (managed by LAPS), a small Tier 2 helpdesk group, and nothing else. Common bad findings: "Domain Users," "DOMAIN\AllIT," or individual user accounts from years of accumulated access grants.

## What to audit before remediation

Find out *why* users were made admin. Common reasons and their proper fixes:

| "Why" they're admin | Proper fix |
|---|---|
| "This app needs admin to run" | Run as standard user + application compatibility shim, or use RunAs for just that app, or package it with MSIX/App-V for per-user install |
| "They need to install software" | Use Intune / SCCM / RMM self-service Software Center |
| "They need to manage printers" | Honestly, they don't, but delegate via GPO. No admin needed for mapped printers |
| "They need to change network settings" | GPO: `Allow users to modify network settings` or use Intune profiles |
| "It's always been this way" | Not a reason |

Before removing admin rights, pilot with a group of 20–30 users for 2 weeks. Collect complaints and address them individually.

Tools that help bridge the gap during transition:
- **Endpoint Privilege Management (EPM)** products (BeyondTrust, CyberArk EPM, Delinea, ThreatLocker, CyberQP) let specific apps elevate without giving the user full admin.
- **MakeMeAdmin** (open-source) - grants temporary admin for a configurable window, with logging.

## Remediation

**Via GPO - Restricted Groups (prescriptive, replaces the entire local admin group):**
`Computer Configuration → Policies → Windows Settings → Security Settings → Restricted Groups`
- Add `Administrators` group.
- Members should be: `BUILTIN\Administrator` (LAPS-managed), `YOURDOMAIN\Tier2-Helpdesk`.
- This replaces the entire membership at every gpupdate. Anything not listed is removed.

**Via GPO - Preferences (additive or subtractive, more flexible):**
`Computer Configuration → Preferences → Control Panel Settings → Local Users and Groups`
- Action: Update, Group: Administrators
- Delete all member users / Delete all member groups (this wipes existing)
- Then add back only the intended members.

**Use Item-Level Targeting** to scope differently for laptops vs. desktops vs. servers if needed.

**On servers**: restrict local admin membership to the specific server admin group for that server's tier. Don't use a single group for all servers as that defeats tiering.

## What might break

- Users who were admin will now hit UAC prompts for things that previously worked silently.
- Specific applications that require admin privileges (usually write to `Program Files`, `HKLM`, or bind to privileged ports). Identify these during the pilot phase and fix individually.
- Self-service software installation if not replaced with SCCM/Intune/equivalent.
- IT helpdesk staff who RDP'd in as local admin — ensure they're in the retained helpdesk group.

The first two weeks will generate tickets. Set expectations with the help desk. The ticket volume drops to baseline within a month in most deployments.

## Rollback

Remove the Restricted Groups or Preferences GPO. The local admin membership reverts to whatever was there before the GPO was applied on next gpupdate.

If you used Restricted Groups (which replaces membership), rollback leaves the group with whatever members exist after removing the GPO, **not** the original membership. Document the original state before enforcing.

## Validate the fix

Re-run the fleet-wide admin audit query. Every workstation should have:
- BUILTIN\Administrator (LAPS) (You can also use LAPS with a custom username)
- Your Tier 2 helpdesk group if you can't get by any other way
- Nothing else

Attempt to run an elevated task as a standard user, you should prompted for admin credentials.

```powershell
# On a workstation
Get-LocalGroupMember -Group 'Administrators'
# Count should be 2-3 entries, not 15.
```

## References

- Microsoft: [Implementing Least-Privilege Administrative Models](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- Microsoft: [Restricted Groups](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc785631(v=ws.10))
- MITRE ATT&CK: T1078.003
