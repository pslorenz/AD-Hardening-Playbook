# ESC3 — Misconfigured Enrollment Agent Templates

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Medium

## What it is

The Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`) lets the holder request certificates **on behalf of other users**. If a template that issues this EKU is enrollable by low-privileged users (and the CA does not restrict who can act as an enrollment agent), an attacker enrolls in the agent template, then uses that cert to request a client-auth cert as any user, including Domain Admins.

ESC3 has two flavors:
- **ESC3.1** — vulnerable enrollment agent template (low-priv enrollment).
- **ESC3.2** — a target template that allows enrollment-on-behalf-of with no enrollment agent restrictions on the CA itself.

Both must be addressed.

## What attack it enables

Two-step privilege escalation: enroll for an agent cert, then request a cert as Domain Admin → PKINIT → DA TGT.

## How to confirm it's present

```bash
certipy find -u user@example.local -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# Look for ESC3.
```

Also check the CA's enrollment agent restrictions:
```powershell
# On the CA
certutil -getreg CA\EnrollmentAgentRights
# If empty/blank, no restriction is in place — anyone with an agent cert can enroll for anyone.
```

## What to audit before remediation

Most environments do not legitimately use enrollment-on-behalf-of. Smart card provisioning is the main legitimate use. If your org doesn't issue smart cards, you can disable agent functionality entirely.

If smart cards are issued, identify the specific service account that does the provisioning — only that account should hold the agent cert.

## Remediation

**1. On the CA, configure Enrollment Agent restrictions:**
- Open `certsrv.msc` → right-click CA → Properties → Enrollment Agents tab
- Switch from "Do not restrict enrollment agents" to "Restrict enrollment agents"
- Add only the specific agent account(s) and the specific templates they're allowed to enroll for, scoped to the specific target users.

**2. Restrict enrollment on the agent template** to that agent account only (Template Properties → Security).

**3. If enrollment-on-behalf-of is unused, remove the EKU** from any template that has it, or delete the template.

## What might break

If smart card enrollment is in use and you restrict the wrong principal, smart card issuance breaks. Coordinate with whoever runs that program.

## Rollback

Switch CA back to "Do not restrict enrollment agents." Effective immediately.

## Validate

Re-run `certipy find -vulnerable` — ESC3 entries should be gone.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md) for shared context.
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
