# ESC9 — No Security Extension on Certificate Template

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Medium

## What it is

ESC9 emerged after the May 2022 KB5014754 patches introduced a new certificate extension (`szOID_NTDS_CA_SECURITY_EXT`, `1.3.6.1.4.1.311.25.2`) that embeds the requester's SID inside the certificate. DCs validating PKINIT compare this SID to the SID of the account being authenticated as. Without the extension, the DC falls back to weak UPN-based mapping.

A template with the `CT_FLAG_NO_SECURITY_EXTENSION` flag explicitly omits this extension. Combined with a target user whose `userPrincipalName` an attacker controls (via GenericWrite/GenericAll on the user object), the attacker can change the UPN to match a privileged account, request a cert under the unprotected template, then revert the UPN — successfully authenticating as the privileged account.

## What attack it enables

UPN-spoofing escalation when the attacker has write access on at least one user object's UPN attribute (more common than you'd think — see also [`dangerous-acls.md`](../ad-objects/dangerous-acls.md)).

## How to confirm it's present

```bash
certipy find -u user -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# ESC9 flagged.
```

PowerShell:
```powershell
$schemaPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
Get-ADObject -SearchBase $schemaPath -Filter * -Properties msPKI-Enrollment-Flag |
    Where-Object { $_.'msPKI-Enrollment-Flag' -band 0x80000 } |  # CT_FLAG_NO_SECURITY_EXTENSION
    Select-Object Name, msPKI-Enrollment-Flag
```

## What to audit before remediation

Why was the flag set? In nearly all cases, it's set on templates created or modified before May 2022 by tools that didn't know about the new extension, or by admins working around an unrelated PKINIT failure. There is rarely a legitimate need to omit the SID extension in 2026.

## Remediation

In `certtmpl.msc` → Template Properties → Subject Name tab → ensure "Include security identifier (SID) in certificate" or equivalent is checked. Or via PowerShell, clear bit `0x80000` from `msPKI-Enrollment-Flag`.

```powershell
$tmpl = Get-ADObject "CN=<TemplateName>,$schemaPath" -Properties msPKI-Enrollment-Flag
$newFlag = $tmpl.'msPKI-Enrollment-Flag' -band (-bnot 0x80000)
Set-ADObject $tmpl -Replace @{ 'msPKI-Enrollment-Flag' = $newFlag }
```

Combined with `StrongCertificateBindingEnforcement = 2` on DCs (see ESC1), this fully closes the attack class.

## What might break

If a third-party PKI integration genuinely relied on certificates without the SID extension (very rare), it may need a config change. Test with one template first.

## Rollback

Set the flag bit back.

## Validate

`certipy find -vulnerable` should no longer flag ESC9 for the template.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md).
- Microsoft: [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- ly4k: [Certipy 4.0 — ESC9 & ESC10](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-and-beyond-7237d88061f7)
