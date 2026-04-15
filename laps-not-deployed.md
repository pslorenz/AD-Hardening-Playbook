# LAPS Not Deployed

**Category:** Accounts & Policies
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Low (a single shared local admin password is one of the easiest lateral-movement wins)

## What it is

Without Local Administrator Password Solution (LAPS), most environments end up with the **same local administrator password on every workstation** — set during imaging and never changed. An attacker who compromises one workstation extracts the local admin hash, then uses pass-the-hash to authenticate to every other workstation in the company as local admin.

LAPS gives every machine a unique, random local admin password, automatically rotated on a schedule, stored in AD with read access controlled by ACLs.

Microsoft now ships **Windows LAPS** built into Windows 10/11 and Server 2019+ as of April 2023 — the older "Legacy LAPS" MSI is no longer needed for modern OSes.

## What attack it enables

- Lateral movement across the entire workstation fleet from a single foothold (pass-the-hash with shared local admin).
- Persistence — even if a user's domain credentials are reset, the local admin remains.

MITRE ATT&CK: T1078.003, T1550.002

## How to confirm it's not deployed

```powershell
# Check whether Windows LAPS schema attributes exist in AD
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter { Name -like 'ms-LAPS*' } |
    Select-Object Name
# If empty, schema has not been extended for Windows LAPS

# Legacy LAPS schema check
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter { Name -eq 'ms-Mcs-AdmPwd' }
```

Sample test for shared local admin password — from one workstation, dump the SAM hash and try to authenticate to a different workstation:
```bash
# (Lab/authorized testing only)
crackmapexec smb 10.0.0.0/24 -u Administrator -H <hash>
# If this returns "Pwn3d!" on multiple hosts, you have a shared local admin password.
```

## What to audit before deployment

LAPS deployment is unusually low-risk. The main "audit" is:

1. **Inventory who currently uses the local admin password.** Helpdesk staff who type the same admin password to fix issues will need to look up the per-host password in AD instead. Train them.
2. **Identify any scripts or tools that hardcode the local admin password.** They will break — convert them to use a domain account or to retrieve the LAPS password via the LAPS PowerShell module.
3. **Decide who can read LAPS passwords.** Default permission should be a small "LAPS-Readers" group, not Domain Users.

## Remediation

For modern environments (Windows 10/11, Server 2019+):

**1. Update the AD schema for Windows LAPS:**
```powershell
# Run on a DC as Schema Admin
Update-LapsADSchema
```

**2. Grant the computer accounts permission to update their own LAPS attributes:**
```powershell
Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=example,DC=local'
```

**3. Configure who can READ LAPS passwords:**
```powershell
Set-LapsADReadPasswordPermission -Identity 'OU=Workstations,DC=example,DC=local' -AllowedPrincipals 'EXAMPLE\LAPS-Readers'
```

**4. Configure the LAPS GPO** (built into modern AD GPMC under `Computer Configuration → Policies → Administrative Templates → System → LAPS`):
- Configure password backup directory: Active Directory (or Azure AD if hybrid)
- Password complexity: Large letters + small letters + numbers + specials
- Password length: 20+
- Password age: 30 days
- Post-authentication actions: Reset password (after the configured grace period when an admin logs in)

**5. Apply the GPO** to OUs containing workstations and member servers.

**For older environments still on Server 2016/2019 without the April 2023 update**, install Legacy LAPS (the MSI from Microsoft) — but plan migration to Windows LAPS.

## What might break

- Helpdesk workflow ("what's the local admin password?") — they now retrieve it per-host:
  ```powershell
  Get-LapsADPassword -Identity 'WORKSTATION01' -AsPlainText
  ```
- Hardcoded scripts using the old password — find and fix.
- Some imaging workflows that rejoin domain post-deploy may need a refresh cycle to populate the LAPS attribute.

## Rollback

Disable the LAPS GPO and `gpupdate /force`. The local admin password will stop rotating but the last LAPS-set password remains in effect on each host (and can still be retrieved from AD until you delete those attributes). To fully revert, also reset the local admin password manually on affected hosts.

## Validate the fix

```powershell
# On a single host, after GPO applies and a rotation cycle:
Get-LapsADPassword -Identity 'WORKSTATION01' -AsPlainText
# Should return a randomized password
```

Verify each workstation has a unique password (sample 10 hosts; the passwords should all differ).

Attempt pass-the-hash from one workstation to another — should fail because the hashes no longer match.

## References

- Microsoft: [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- Microsoft: [Get started with Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- MITRE ATT&CK: T1078.003, T1550.002
