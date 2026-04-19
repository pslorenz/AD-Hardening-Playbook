# ESC11 — Relay to ICPR (No RPC Encryption)

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Medium

## What it is

ESC11 is the RPC equivalent of ESC8. The MS-ICPR (`ICertPassage`) protocol — the RPC interface for certificate enrollment — by default does not require packet privacy (encryption). When unencrypted, the authentication can be relayed in the same way an attacker relays NTLM over HTTP for ESC8, except over RPC. An attacker coerces a privileged machine, captures the NTLM auth, and relays it to the CA's RPC interface to request a cert as that machine.

## What attack it enables

NTLM relay against the CA RPC interface → cert as a privileged machine account → DCSync.

## How to confirm it's present

```powershell
# On the CA host
certutil -getreg CA\InterfaceFlags
# Look for the IF_ENFORCEENCRYPTICERTREQUEST flag (0x00000200). If absent, ESC11 applies.
```

Certipy:
```bash
certipy find -u user -p Pass -dc-ip <dc-ip> -enabled -vulnerable
# ESC11 flagged.
```

## What to audit before remediation

Enabling RPC encryption requires that all enrollment clients support it. Any modern Windows client does. Older non-Windows clients (some Linux/Java certreq workflows) may not — test the specific client(s) that enroll against the CA before enforcing.

## Remediation

```cmd
:: On the CA host
certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc && net start certsvc
```

This forces RPC packet privacy for all certificate enrollment requests.

## What might break

Old enrollment clients that don't negotiate RPC encryption. In practice, modern Windows is fine; non-Windows enrollment is the place to test.

## Rollback

```cmd
certutil -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc && net start certsvc
```

## Validate

```powershell
certutil -getreg CA\InterfaceFlags
# IF_ENFORCEENCRYPTICERTREQUEST should be set (the value will include 0x200).
```

Try a relay attack (lab) — should fail because the RPC channel rejects unencrypted authentication.

## References

- See [`esc1-misconfigured-templates.md`](esc1-misconfigured-templates.md) and [`esc8-ntlm-relay-to-adcs.md`](esc8-ntlm-relay-to-adcs.md).
- ly4k: [Certipy ESC11 writeup](https://research.ifcr.dk/) (reference)
- Microsoft: [Certificate Services interface flags](https://learn.microsoft.com/en-us/windows/win32/seccrypto/interface-flags)
