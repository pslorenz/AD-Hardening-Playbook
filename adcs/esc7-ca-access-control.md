# ESC7 — Vulnerable CA Access Control

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Medium

## What it is

The CA itself has two relevant role permissions: **Manage CA** and **Manage Certificates**. A non-admin principal granted Manage CA can flip the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (creating ESC6 conditions on demand) or modify other CA-level settings. A principal with Manage Certificates can approve pending requests — useful when combined with templates requiring "manager approval."

If either of these roles is granted to a low-privileged group, the attacker can chain to a full domain compromise.

## What attack it enables

- Manage CA → enable ESC6 → ESC1-style escalation.
- Manage Certificates → approve their own pending malicious cert request.

## How to confirm it's present

```bash
certipy find -u user -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# ESC7 flagged for inappropriate CA role assignments.
```

PowerShell on the CA host:
```powershell
# Manage CA / Manage Certificates rights are stored in the CA's security descriptor
certutil -getreg CA\Security
```

Or in `certsrv.msc`: right-click the CA → Properties → Security tab.

## What to audit before remediation

These rights should be held only by Tier 0 PKI administrators. Any other principal — including "Server Operators," helpdesk groups, or generic IT groups — is a misconfiguration.

## Remediation

In `certsrv.msc`:
- Right-click CA → Properties → Security
- Remove non-Tier-0 principals from "Manage CA" and "Manage Certificates"

Restart `certsvc` to ensure changes apply.

## What might break

Any delegated PKI ops staff who relied on these rights lose the ability to manage the CA. Either move them into a Tier 0 PKI admin group or scope their tasks more narrowly (e.g., template-level Read for visibility without modify rights).

## Rollback

Re-add the principal in the CA Security tab.

## Validate

Re-run `certipy find -vulnerable` and `certutil -getreg CA\Security`.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md).
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
