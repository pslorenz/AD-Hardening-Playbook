# ESC10 — Weak Certificate Mappings on Domain Controller

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Medium (audit before enforcing)
**Attacker Skill Required to Exploit:** Medium

## What it is

ESC10 covers two registry settings on Domain Controllers that, if configured weakly, allow ESC9-style UPN-spoofing attacks even if templates include the SID extension:

- `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement` controls whether the DC validates the SID extension. Values: `0` = Disabled (most permissive), `1` = Compatibility (audit only), `2` = Full Enforcement.
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\UseSubjectAltName` controls whether Schannel/Kerberos uses the SAN UPN for mapping. If set to `0`, mapping uses an explicit `altSecurityIdentities` entry (strong mapping). If set to `1` (default), implicit UPN mapping is used (weak).

The May 2022 patches (KB5014754) added these knobs, but Microsoft set them to permissive defaults to avoid breaking environments. The ESC10 finding flags any DC where these are still in the permissive state.

## What attack it enables

UPN spoofing → authenticate as a different account via a legitimately-issued cert. Often chained from ACL abuse on user objects.

## How to confirm it's present

```powershell
# On each DC
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue
# Goal: 2

Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name UseSubjectAltName -ErrorAction SilentlyContinue
# Goal: 0
```

## What to audit before remediation

Setting `StrongCertificateBindingEnforcement = 2` will reject certificates that:
- Don't contain the SID extension AND
- Don't have an explicit `altSecurityIdentities` mapping on the target user.

Common breakage:
- Certs issued before May 2022 templates were updated.
- Certs from external CAs (vendor-issued, partner-issued) that don't have the AD SID extension.
- Smart card credentials provisioned by older systems.

**Use Compatibility mode (`1`) for at least 4–6 weeks** before flipping to `2`. In Compatibility mode the DC logs Event ID **39** (or **41**) in the `System` log when it sees a weakly-mapped cert that *would* have been rejected in Enforcement mode. That's your offender list.

```powershell
Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] and (EventID=39 or EventID=41)]]"
```

## Remediation

**Step 1: Set Compatibility mode and audit:**
```powershell
# On every DC
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement -Value 1
```

**Step 2: For each Event 39/41**, fix the source — reissue the cert from a template that includes the SID extension, or add an explicit `altSecurityIdentities` mapping on the user object:
```powershell
# Example explicit mapping
Set-ADUser -Identity user -Add @{altSecurityIdentities='X509:<I>DC=local,DC=example,CN=ContosoCA<S>CN=user'}
```

**Step 3: Once Event 39/41 is at zero for several weeks**, enforce:
```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement -Value 2
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name UseSubjectAltName -Value 0
```

## What might break

In enforcement mode, any cert without proper mapping fails authentication. Symptom: smart card login fails, VPN cert auth fails, app-to-DC PKINIT fails. The audit period exists specifically to catch these.

## Rollback

Set both values back to their permissive state (`0` for StrongCertificateBindingEnforcement, `1` for UseSubjectAltName) and reboot the DC. Authentication restores immediately.

## Validate

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' | Select-Object StrongCertificateBindingEnforcement
# 2

# In an attack simulation, ESC9-style UPN spoofing should now fail with a Kerberos error.
```

## References

- Microsoft: [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- ly4k: [Certipy 4.0 — ESC9 & ESC10](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-and-beyond-7237d88061f7)
