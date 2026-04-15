# krbtgt Password Not Rotated

**Category:** Accounts & Policies
**Operational Risk of Remediation:** Low-Medium (if done correctly with the supported script)
**Attacker Skill Required to Exploit:** N/A — this is the foundation of Golden Ticket attacks

## What it is

The `krbtgt` account is the special domain account whose password hash is used to encrypt every Kerberos TGT issued by every DC in the domain. If an attacker ever obtains the krbtgt hash (typically via DCSync after compromising a DC or a privileged account), they can forge arbitrary TGTs as any user — the famous "Golden Ticket" — for as long as the password remains the same. There is no token revocation, no MFA, no log that distinguishes a forged TGT from a real one.

The hash is changed only when the krbtgt password is changed. Microsoft's guidance is to rotate it twice on a schedule, with the second rotation 12+ hours after the first. Many environments have never rotated it since the domain was created.

## Why "twice"?

AD keeps the current and previous krbtgt password to validate in-flight tickets. If you rotate once, only the previous password is invalidated. If an attacker captured the hash before your rotation, their forged tickets still work until you rotate again. Two rotations, separated by enough time for legitimate tickets to refresh, fully invalidate any prior compromise.

## How to confirm it's not been rotated

```powershell
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
# If this date is >180 days old (or matches the domain creation date), rotate.
```

## What to audit before remediation

The official rotation script is well-tested and Microsoft-supported. Audit considerations:

- **Make sure no DC is offline or behind on replication.** Rotation must replicate to every DC promptly. Run `repadmin /replsummary` and confirm zero failures.
- **Make sure RODCs and read/write DCs are all healthy.** RODCs have separate krbtgt accounts (`krbtgt_<numeric>`) — those should be rotated too.
- **Plan around large batch jobs.** Anything that started before the rotation will need to refresh tickets after the second rotation. A 4-hour TGT lifetime (default) means the second rotation should be at least 10 hours after the first, ideally 24h.

## Remediation

Use Microsoft's official **New-KrbtgtKeys.ps1** script (search Microsoft Learn / GitHub `Microsoft/New-KrbtgtKeys.ps1`). This is the only supported method.

The procedure:

1. Download and review the script.
2. Run with `-Mode 1` (informational) first to confirm domain health and see what would happen.
3. Run with `-Mode 9` (single rotation in production). Wait 24 hours.
4. Run with `-Mode 9` again. Done.

If you cannot use the script for some reason, the manual equivalent is:
```powershell
# DO NOT use Set-ADAccountPassword on krbtgt. Use the script.
# The script handles RODC-specific krbtgt accounts, replication checks, and avoids common pitfalls.
```

## What might break

- In-flight Kerberos tickets issued before the rotation will fail validation when they expire and try to refresh, **if** the second rotation has happened. Symptoms: users get re-prompted for credentials; some services may need to restart to re-acquire tickets.
- Accounts with extremely long-lived TGTs (delegation, special apps) may be affected sooner.
- Replication lag can cause inconsistent ticket validation across DCs for a brief window — hence the need to confirm replication health first.

In healthy environments, a typical rotation is invisible to users.

## Rollback

You cannot directly roll back a krbtgt rotation. If something breaks, identify the affected service and restart it to force a fresh ticket request. In severe cases, you can do another single rotation, which will restore validity for tickets issued under the password just-set (because that password is now the "previous" one). This is why proceeding carefully is so important.

## Validate the fix

```powershell
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
# Should reflect today's date after each rotation
```

Set up an annual or 6-monthly calendar event for future rotations. Some orgs rotate quarterly; Microsoft's documented baseline is "regularly" without a hard number, but 180 days is a common and defensible cadence.

For ongoing assurance, **PingCastle** and **Purple Knight** both report on krbtgt password age.

## References

- Microsoft: [AD Forest Recovery — Resetting the krbtgt password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password)
- Microsoft / GitHub: New-KrbtgtKeys.ps1 (search the Microsoft GitHub org for the current canonical version)
- Sean Metcalf: [Golden Tickets and krbtgt rotation](https://adsecurity.org/?p=556)
- MITRE ATT&CK: T1558.001 (Golden Ticket)
