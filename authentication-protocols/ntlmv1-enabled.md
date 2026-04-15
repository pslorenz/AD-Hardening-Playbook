# NTLMv1 Still Allowed

**Category:** Authentication Protocols
**Operational Risk of Remediation:** Medium
**Attacker Skill Required to Exploit:** Low (captured NTLMv1 hashes are trivially cracked)

## What it is

NTLMv1 is the original NT LAN Manager authentication protocol. Its challenge-response is cryptographically broken, meaning a captured NTLMv1 response can be converted to NT hash in under 24 hours via crack.sh for free, and often in seconds with a GPU rig. NTLMv2 (1996) replaced it. NTLMv1 should not exist in a modern network.

## What attack it enables

Any attacker who can capture NTLMv1 traffic (Responder, SMB relay listener, or even a malicious DC in some configurations) recovers the plaintext NT hash, which is equivalent to the user's password. Combined with coercion bugs (PetitPotam, PrinterBug), an attacker can force a DC to authenticate over NTLMv1 and obtain the DC machine account hash.

## How to confirm it's present in your environment

Check the `LmCompatibilityLevel` on your DCs and across the fleet:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue
```

Levels:
- `0` or `1` sends and accepts LM and NTLMv1. **Vulnerable.**
- `2` sends NTLM only, accepts everything. Vulnerable.
- `3` sends NTLMv2 only, accepts everything. **Still vulnerable** (this is the most common misconfiguration).
- `4` DCs refuse LM. Better but not enough.
- `5` DCs refuse LM and NTLMv1. **Target state.**

The key insight: setting clients to "send NTLMv2" doesn't matter if the DC will still *accept* NTLMv1 from anyone who asks. You must set `5` on the DCs.

## What to audit before remediation

Before setting `LmCompatibilityLevel = 5` on DCs, find what's still using NTLMv1.

Enable NTLM auditing GPO on Domain Controllers:
`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Restrict NTLM: Audit Incoming NTLM Traffic = Enable auditing for all accounts`

Then watch the **Operational** log: `Applications and Services Logs → Microsoft → Windows → NTLM → Operational`

- **Event ID 8001** — Outgoing NTLM authentication attempt. Field `SChannelType` and the auth message indicate version.
- **Event ID 8002** — Outgoing NTLM call to remote server.
- **Event ID 8003** — Server received NTLM authentication.

For NTLMv1 specifically, look at incoming auth events on the DC and filter for NTLMv1 in the message body. PowerShell:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' |
    Where-Object { $_.Message -match 'NTLM V1' }
```

Run this for at least a week. The offenders are usually: old NAS appliances, ESXi hosts joined to AD, copiers, legacy SQL Server linked servers, mainframe gateways, and one or two forgotten Windows 2003 boxes everyone insists isn't there.

## Remediation

Once audit log is clean (or remaining offenders are accepted risk and isolated):

GPO on Domain Controllers OU:
`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM`

This sets `LmCompatibilityLevel = 5`.

Apply the same setting to all member servers and workstations as well. Phase: workstations first, then non-critical servers, then critical servers, then DCs.

## What might break

- **Hard breakage** for any client genuinely unable to do NTLMv2: very old printers/MFPs, some old ESXi-to-AD integrations, SQL Server with old linked-server configs, anything still running Windows 2000 or XP without the appropriate updates.
- Linux Samba clients are fine if `client ntlmv2 auth = yes` is set (default on modern Samba).
- macOS is fine on any version still receiving updates.

If audit log shows zero NTLMv1 traffic for two weeks, breakage risk is near zero.

## Rollback

Set the GPO back to "Send NTLMv2 response only" (level 3) to restores DC acceptance of older protocols. `gpupdate /force` and reboot. Affected services authenticate again immediately.

## Validate the fix

```powershell
# On the DC
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel
# Should show 5
```

From a test host, attempt to coerce NTLMv1 (e.g., with a tool like ntlm_theft or by configuring a client to send NTLMv1). The DC should reject the authentication. Watch for **Event ID 4625** (account failed to log on) with Status `0xC000006A` or similar on the DC.

## References

- Microsoft: [Network security: LAN Manager authentication level](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)
- crack.sh — public NTLMv1 cracking service (illustrates how trivial this is)
- MITRE ATT&CK: T1557, T1187
