# ESC5 — Vulnerable PKI Object Access Control

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low (ACL fix)
**Attacker Skill Required to Exploit:** Medium

## What it is

ESC5 is ESC4's bigger sibling. Instead of a single template, it covers weak ACLs on the broader PKI infrastructure objects in AD:
- The CA computer object
- The CA's AD container (`CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,...`)
- The NTAuthCertificates object (controls which CAs are trusted for client authentication domain-wide)
- The Root CA Certificates object
- The PKI container itself

If a low-privileged principal has write access on any of these, the attacker can publish a rogue CA cert to NTAuth (making the attacker's CA trusted for authentication), modify CA configuration, or take over the CA's computer object.

## What attack it enables

- Publish attacker-controlled CA to NTAuth → issue arbitrary client auth certs → authenticate as anyone, including DA.
- Compromise CA host → full control of issued certificates.

## How to confirm it's present

```bash
certipy find -u user@example.local -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# ESC5 flagged for problematic ACLs on PKI objects.
```

PowerShell — check ACLs on the key PKI containers:
```powershell
$pkiObjects = @(
    "CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)",
    "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)",
    "CN=Certification Authorities,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
)
foreach ($obj in $pkiObjects) {
    $acl = Get-Acl "AD:$obj"
    $acl.Access | Where-Object {
        $_.ActiveDirectoryRights -match 'Write|GenericAll|GenericWrite' -and
        $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Enterprise Read'
    } | Select-Object @{N='Object';E={$obj}}, IdentityReference, ActiveDirectoryRights
}
```

Also check the CA *computer* object's ACL — anyone with write rights there can effectively own the CA.

## What to audit before remediation

These ACLs should be exclusively held by Tier 0 admins. Any other principal with write access is a finding — there is essentially no legitimate reason for "PKI Operators" or similar to have write on NTAuth.

## Remediation

Strip non-Tier-0 write access from PKI objects via ADSI Edit or PowerShell (see ESC4 example for the pattern). Document the legitimate ACE list explicitly.

Pay particular attention to the **CA computer object** — it should be in a protected OU with an ACL preventing non-Tier-0 modification, and the host itself should be tier 0.

## What might break

If your environment delegated PKI operations to a non-Tier-0 group, removing those rights breaks their workflow. Fix: move them to Tier 0 (where they belong if they administer PKI), or use a different delegation that doesn't grant object-modification rights.

## Rollback

Re-add the ACE.

## Validate

Re-run the ACL query and `certipy find -vulnerable`.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md).
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
