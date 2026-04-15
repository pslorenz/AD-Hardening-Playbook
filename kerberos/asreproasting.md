# AS-REP Roasting (DONT_REQUIRE_PREAUTH)

**Category:** Kerberos
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Low (Rubeus / GetNPUsers.py)

## What it is

By default, Kerberos requires "pre-authentication" — the client encrypts a timestamp with the user's password hash and sends it with the AS-REQ. The KDC verifies it before issuing a TGT. This prevents offline brute-forcing.

Some accounts have the `DONT_REQ_PREAUTH` flag set in `userAccountControl` (bit 0x400000). For these accounts, the KDC will issue an AS-REP encrypted with the account's password hash to anyone who asks — no authentication required at all. The attacker takes the AS-REP offline and brute-forces it.

Unlike Kerberoasting, AS-REP roasting does not even require the attacker to have a valid domain credential. Anyone who can reach the KDC can do this.

## What attack it enables

- Offline cracking of any account flagged `DONT_REQ_PREAUTH`.
- Credentials with no authentication required to enumerate.

MITRE ATT&CK: T1558.004

## How to confirm it's present in your environment

```powershell
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth, MemberOf |
    Select-Object SamAccountName, MemberOf
```

If this returns any rows, you have AS-REP-roastable accounts. Common offenders:
- Service accounts for old Java apps that couldn't do pre-auth
- Accounts created by an admin who copied a template object from 2006
- A small number of legitimate cases (very rare)

Simulate the attack:
```bash
# From any host that can reach the DC; no credentials required
GetNPUsers.py 'example.local/' -usersfile users.txt -no-pass -dc-ip <dc-ip>
```

## What to audit before remediation

For each account returned, ask: why is this flag set? In ~95% of cases, no one knows, and the answer is "remove the flag, see if anything breaks."

Before clearing the flag, check Event ID 4768 on DCs (Kerberos TGT requested) for the account, filtered for "Pre-Authentication Type: 0" — these are the no-pre-auth requests. If you see these from a known-good host doing legitimate work, you have a real dependency to address. If you only see them from the attacker simulation you ran, you're fine.

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4768] and EventData[Data[@Name='PreAuthType']='0']]" |
    Select-Object TimeCreated, @{N='User';E={$_.Properties[0].Value}}, @{N='IP';E={$_.Properties[9].Value}}
```

## Remediation

For each account that doesn't legitimately need it, clear the flag:

```powershell
Get-ADUser -Identity <samaccountname> | Set-ADAccountControl -DoesNotRequirePreAuth $false
```

Bulk:
```powershell
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } | Set-ADAccountControl -DoesNotRequirePreAuth $false
```

Also: if any of these accounts had weak passwords, rotate them — assume the AS-REP has already been captured.

## What might break

- Any application that genuinely cannot perform Kerberos pre-authentication. Real cases are vanishingly rare in 2026. Old MIT Kerberos clients used to have issues; modern ones don't.
- If something does break, you'll see authentication failures from a specific host immediately after the change.

## Rollback

```powershell
Get-ADUser -Identity <user> | Set-ADAccountControl -DoesNotRequirePreAuth $true
```
Effective immediately.

## Validate the fix

```powershell
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true }
# Should return zero rows (or only known accepted exceptions)
```

Re-run the GetNPUsers.py / Rubeus asreproast attack — should return no hashes.

## References

- Will Schroeder: [Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- MITRE ATT&CK: T1558.004
