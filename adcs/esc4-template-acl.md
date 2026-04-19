# ESC4 — Vulnerable Certificate Template Access Control

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low (per-template ACL fix)
**Attacker Skill Required to Exploit:** Low

## What it is

Certificate templates are AD objects with their own ACLs. If a low-privileged principal (Domain Users, Authenticated Users, or any compromisable group) has **WriteDacl, WriteOwner, GenericAll, GenericWrite, or WriteProperty** on a certificate template, the attacker can rewrite the template into an ESC1-vulnerable configuration, enroll for a DA cert, and clean up afterward.

ESC4 is essentially "I can become ESC1 whenever I want."

## What attack it enables

Privilege escalation to Domain Admin, with the side benefit that the attack can be cleaned up immediately by reverting the template — leaving little forensic trace.

## How to confirm it's present

```bash
certipy find -u user@example.local -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# ESC4 will be flagged on any template with weak ACLs.
```

PowerShell — find non-default principals with write rights on templates:
```powershell
$tmpls = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Filter * -Properties nTSecurityDescriptor
foreach ($t in $tmpls) {
    $t.nTSecurityDescriptor.Access | Where-Object {
        $_.ActiveDirectoryRights -match 'WriteDacl|WriteOwner|GenericAll|GenericWrite|WriteProperty' -and
        $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Cert Publishers|Enterprise Read-only Domain Controllers'
    } | Select-Object @{N='Template';E={$t.Name}}, IdentityReference, ActiveDirectoryRights
}
```

## What to audit before remediation

For each unexpected ACE, find out who/why. Common legitimate cases:
- A PKI admin group (fine, but should be a *small* group, not Domain Users).
- A delegated certificate template manager.

Anything broader — `Authenticated Users`, `Domain Users`, `Everyone` — is a finding, not a feature.

## Remediation

Edit the template ACL via the Certificate Templates console (`certtmpl.msc`) → Template Properties → Security tab → remove the inappropriate principal or strip down to Read/Enroll only.

Or via PowerShell:
```powershell
$tmpl = Get-ADObject "CN=<TemplateName>,CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
$acl = Get-Acl "AD:$($tmpl.DistinguishedName)"
$badAces = $acl.Access | Where-Object { $_.IdentityReference -eq 'EXAMPLE\BadGroup' }
foreach ($ace in $badAces) { $acl.RemoveAccessRule($ace) | Out-Null }
Set-Acl "AD:$($tmpl.DistinguishedName)" -AclObject $acl
```

## What might break

If a legitimate PKI workflow used the now-removed permission (rare), template management for that workflow breaks until the right principal is granted minimal rights.

## Rollback

Re-add the ACE via the GUI or PowerShell.

## Validate

Re-run the PowerShell ACL query above. The bad ACE should be gone. Re-run `certipy find -vulnerable`.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md).
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
