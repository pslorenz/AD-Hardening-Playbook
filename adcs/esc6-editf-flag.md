# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Low

## What it is

A CA-wide registry flag, `EDITF_ATTRIBUTESUBJECTALTNAME2`, allows the requester to specify a Subject Alternative Name (SAN) **on every certificate request, regardless of the template's settings**. This effectively turns every client-auth template into an ESC1 — the requester can claim to be Administrator without the template explicitly allowing subject supply.

This flag was set by some old Microsoft documentation as a "fix" for an unrelated issue. It should never be enabled in modern environments.

The May 2022 patches (KB5014754) and the StrongCertificateBindingEnforcement registry change defeat the SAN-spoofing portion of this even when the flag is set, but the flag should still be removed.

## What attack it enables

ESC1-style escalation against any client-auth template, even templates that are otherwise correctly configured.

## How to confirm it's present

```powershell
# On the CA host
certutil -getreg policy\EditFlags
# Look for EDITF_ATTRIBUTESUBJECTALTNAME2 in the output
```

Or via Certipy:
```bash
certipy find -u user -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# ESC6 flagged if present.
```

## What to audit before remediation

Determine why the flag was ever set. If the original reason was "we needed certificates with custom SANs," the supported answer is to configure those SANs in the template (build from AD) or use offline cert requests with the appropriate template settings — not to leave this flag on.

## Remediation

```cmd
:: On the CA host
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

The leading `-` removes the flag from the bitmask.

## What might break

Any workflow that depended on submitting a SAN attribute via the request rather than configuring it in the template. Migrate those to use proper template config or to use the `certreq.exe` `-attrib` workflow with explicit policy rather than CA-wide allowance.

## Rollback

```cmd
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

## Validate

```powershell
certutil -getreg policy\EditFlags
# EDITF_ATTRIBUTESUBJECTALTNAME2 should not be listed.
```

Re-run `certipy find -vulnerable`.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md).
- Microsoft KB: [How to disable the SAN for UPN mapping](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/disable-subject-alternative-name-upn-mapping)
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
