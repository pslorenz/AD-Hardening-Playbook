# Protected Users Group Not Used

**Category:** Privileged Access
**Operational Risk of Remediation:** Medium (members lose certain auth options)
**Attacker Skill Required to Exploit:** N/A, this is a defensive control as opposed to a vulnerability.

## What it is

`Protected Users` is a built-in security group introduced in Server 2012 R2 that applies several non-configurable security restrictions to its members:

- No NTLM authentication
- No DES or RC4 in Kerberos pre-auth
- No long-term Kerberos keys cached
- No credential delegation (CredSSP, unconstrained delegation)
- TGT lifetime limited to 4 hours, no renewal

In practical terms, members are immune to a wide swath of credential theft and pass-the-hash attacks. The group is empty by default in nearly every environment.

## Why this matters

If your privileged users were in Protected Users, several common attacks against them simply do not work:
- Kerberoasting (RC4 disabled)
- Pass-the-hash (no NTLM)
- Cached credential theft after logoff (no long-term keys cached)
- Unconstrained delegation TGT capture (no delegation)

It costs nothing in license, software, or infrastructure. It just needs to be turned on for the right accounts.

## How to confirm it's not in use

```powershell
Get-ADGroupMember 'Protected Users'
# Empty in most environments
```

For comparison, list privileged users who *should* be in it:
```powershell
@('Domain Admins','Enterprise Admins','Schema Admins') | ForEach-Object {
    Get-ADGroupMember $_ -Recursive
} | Select-Object SamAccountName -Unique
```

## What to audit before adding members

The four-hour TGT lifetime and the no-NTLM restriction are the two things most likely to surprise you. Before adding a privileged user:

1. **Identify any service or scheduled task running as that user.** Service accounts should not be in Protected Users period. Use gMSAs instead.
2. **Identify any application that uses NTLM with that user.** Check Event ID 4624 with Logon Process = "NtLmSsp" on hosts the admin logs into. If you see that admin's account doing NTLM authentications, you'll need to fix the underlying app or accept that those workflows will break.
3. **Confirm the domain functional level is Server 2012 R2 or later.** The full set of protections requires that.

For a one-week trial, add a single non-critical admin account to the group and have them work normally. Watch for issues, then expand.

## Remediation

```powershell
# Add specific privileged users
Add-ADGroupMember -Identity 'Protected Users' -Members 'admin1','admin2','admin3'

# Or all members of Domain Admins
Get-ADGroupMember 'Domain Admins' -Recursive | Where-Object objectClass -eq 'user' | ForEach-Object {
    Add-ADGroupMember -Identity 'Protected Users' -Members $_
}
```

**What goes in:** Human privileged accounts (DAs, EAs, helpdesk admins doing tier-2 work, server admins doing tier-1 work).

**What does NOT go in:**
- Service accounts (use gMSAs instead)
- The default Administrator account (it's used for DSRM and other recovery, see Microsoft's guidance)
- Computer accounts
- Any account used by a service that requires NTLM, RC4, or unconstrained delegation

## What might break

- Any workflow currently using NTLM as a privileged user (admin connecting to a non-Kerberos-capable resource, e.g., by IP address rather than hostname).
- Long-running admin sessions that exceed 4 hours and require ticket renewal.
- Anything that relies on cached domain credentials when the DC is unreachable.
- Scheduled tasks running as a privileged user (these fail; convert to gMSA).

## Rollback

```powershell
Remove-ADGroupMember -Identity 'Protected Users' -Members 'admin1' -Confirm:$false
```

The user must log off and back on for restrictions to clear.

## Validate the fix

After adding a user, log in as them and check ticket lifetime:
```powershell
klist
# "End Time" should be ~4 hours after "Start Time", with "Renew Time" the same as End Time
```

Attempt a Kerberoast against the account:
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList <SPN-of-admin>
```
The ticket should come back AES-only (not RC4), making cracking dramatically slower. Even better: privileged accounts should not have SPNs at all.

Attempt NTLM authentication as the user — should fail.

## References

- Microsoft: [Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- Microsoft: [Guidance about how to configure protected accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts)
