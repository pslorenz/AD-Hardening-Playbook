# SMB Signing Not Required

**Category:** Network Services
**Operational Risk of Remediation:** Low-Medium
**Attacker Skill Required to Exploit:** Low

## What it is

SMB signing cryptographically signs each SMB packet so the receiver can detect tampering. Without it, an attacker who relays an authentication attempt can issue arbitrary SMB commands as the relayed user. Domain Controllers require SMB signing by default; member servers and workstations do not.

## What attack it enables

Classic SMB relay. The capture or coerce authentication from a privileged user, relay it to any host that does not require signing, and execute commands as that user. Often paired with LLMNR/NBT-NS poisoning or the IPv6/mitm6 attack.

## How to confirm it's present in your environment

```powershell
# Run on each server/workstation
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
# RequireSecuritySignature should be True on all hosts.

# At scale, query AD-joined machines from one box:
$hosts = Get-ADComputer -Filter 'Enabled -eq $true' | Select-Object -ExpandProperty Name
foreach ($h in $hosts) {
    try {
        Invoke-Command -ComputerName $h -ScriptBlock {
            Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
        } -ErrorAction Stop | Select-Object @{N='Host';E={$h}}, RequireSecuritySignature
    } catch { }
}
```

External validation against a single host:
```bash
nmap -p445 --script smb2-security-mode <host>
# Look for "Message signing enabled but not required" — this is the bad case.
```

## What to audit before remediation

SMB signing is enforced (not optional) on virtually all modern OSes. The breakage risk comes from:
- Very old Linux Samba clients that don't support signing.
- Some old NAS appliances accessed by Windows clients.
- Performance-sensitive workloads on very old hardware (signing has measurable CPU cost on pre-2010 CPUs; on anything modern it's noise).

Enable SMB client/server auditing on a sample of hosts and look at:
- Event log: `Microsoft-Windows-SMBServer/Audit` and `Microsoft-Windows-SMBClient/Security`
- Watch for connections from clients negotiating without signing.

```powershell
Set-SmbServerConfiguration -AuditSmb1Access $true -Confirm:$false
# Use this period to also catch SMBv1 (separate finding)
```

## Remediation

GPO scope: all member servers and workstations.

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`:
- `Microsoft network server: Digitally sign communications (always) = Enabled`
- `Microsoft network client: Digitally sign communications (always) = Enabled`

For Linux Samba servers in `smb.conf`:
```
server signing = mandatory
client signing = mandatory
```

## What might break

- Connections to/from any host that cannot do signing (increasingly rare.)
- Slight CPU overhead. On modern hardware (anything with AES-NI) it's negligible. Old appliances may show measurable slowdowns.

## Rollback

Set the two GPO settings to "Disabled" or "Not Configured" and `gpupdate /force`. Affected SMB sessions reconnect immediately.

## Validate the fix

```powershell
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
# True
```

```bash
nmap -p445 --script smb2-security-mode <host>
# Should now report "Message signing enabled and required"
```

Run an SMB relay attempt from a lab attacker host (`ntlmrelayx.py -t smb://target`) — it should fail with a signing error.

## References

- Microsoft: [Overview of Server Message Block signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing)
- MITRE ATT&CK: T1557.001
