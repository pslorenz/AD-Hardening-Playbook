# ESC2 — Templates with Any Purpose or No EKU

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low (per-template)
**Attacker Skill Required to Exploit:** Low (Certipy)

## What it is

A certificate template that has the **Any Purpose EKU** (`2.5.29.37.0`) or **no EKU at all**, combined with low-privileged enrollment rights, allows the requester to receive a certificate usable for *anything* — including client authentication, code signing, or even acting as a Subordinate CA. This is broader than ESC1: even without subject supply, the issued cert can authenticate as the requester and be reused in unexpected ways.

## What attack it enables

- Certificate usable for client auth → Kerberos PKINIT → TGT for the requester (which is fine on its own, but combined with other ESCs becomes an escalation primitive).
- Certificate usable for code signing or other purposes the admin never intended.
- "No EKU" certs are particularly dangerous because some apps treat them as trusted for everything.

## How to confirm it's present

```bash
certipy find -u user@example.local -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# Look for templates flagged ESC2.
```

PowerShell check on template attributes:
```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Filter * -Properties pKIExtendedKeyUsage |
    Where-Object { $_.pKIExtendedKeyUsage -contains '2.5.29.37.0' -or $_.pKIExtendedKeyUsage.Count -eq 0 } |
    Select-Object Name, pKIExtendedKeyUsage
```

## What to audit before remediation

For each template, identify the actual use case and the specific EKU it should have. Most templates were templated from "User" or "Computer" originally and the EKU got widened over time without justification.

## Remediation

Edit the template (`certtmpl.msc`) → Extensions → Application Policies (this is the GUI for EKU). Restrict to only the specific EKUs needed:
- Client Authentication only → `1.3.6.1.5.5.7.3.2`
- Server Authentication only → `1.3.6.1.5.5.7.3.1`

Alternatively, restrict enrollment rights to a small group instead of broad groups.

## What might break

Any cert reissued from the template that depended on the broader EKU. Inventory existing issued certs first:
```powershell
certutil -view -restrict "CertificateTemplate=<oid>" -out "RequesterName,NotBefore,NotAfter"
```

## Rollback

Add the EKU back via the template editor. New requests pick up the change immediately.

## Validate

Re-run `certipy find -vulnerable`. Template should no longer appear under ESC2.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md) for shared remediation context.
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
