# WPAD Spoofing

**Category:** Network Services
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Low

## What it is

Web Proxy Auto-Discovery (WPAD) is a mechanism where Windows automatically searches for a proxy server by querying `wpad.<domain>` via DNS, and falls back to LLMNR/NBT-NS broadcast if DNS doesn't answer. If the lookup succeeds, the client downloads a `wpad.dat` PAC file from that host and routes web traffic through it.

The attack: an adversary on the network responds to the WPAD lookup, serves a malicious PAC file, and now sees (and can modify) all of the victim's web traffic — including HTTP basic auth and NTLM challenges from intranet sites.

## What attack it enables

- Capture of NTLM authentication when victims access intranet sites (the malicious proxy can prompt for auth).
- Adversary-in-the-middle on cleartext HTTP.
- Combined with NTLM relay, full credential abuse.

## How to confirm it's present in your environment

```powershell
# Is "Automatically detect settings" enabled in IE/Edge proxy config?
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object AutoDetect
# 1 = enabled (vulnerable), 0 = disabled
```

Check whether WPAD is in your DNS Global Query Block List (this should be on by default on Windows DNS):
```powershell
dnscmd /info /globalqueryblocklist
# Should include 'wpad' and 'isatap'
```

If the GQBL doesn't include `wpad`, anyone who can register a hostname (any domain user, by default) can register `wpad.<yourdomain>` and immediately MitM half the company. Test:
```powershell
Resolve-DnsName wpad.<yourdomain>
# NXDOMAIN or filtered = good. An IP returned = bad.
```

## What to audit before remediation

WPAD is rarely used legitimately. If your environment does use a PAC file for proxy config, it's typically distributed via GPO (`User Configuration → Administrative Templates → Windows Components → Internet Explorer → Use automatic configuration script`), not WPAD discovery.

Confirm no business workflow depends on WPAD before disabling. Ask the network team and check if any GPO sets `AutoConfigURL` — if it does, you are using PAC explicitly, not WPAD, and you're fine.

## Remediation

Defense in depth — do all three:

**1. Confirm/restore the DNS Global Query Block List on every DNS server:**
```powershell
dnscmd /config /globalqueryblocklist wpad isatap
# Restart DNS service
Restart-Service DNS
```

**2. Add an explicit WPAD record sinkholing the lookup** (belt-and-suspenders if GQBL is ever modified):
```powershell
Add-DnsServerResourceRecordA -Name 'wpad' -ZoneName '<yourdomain>' -IPv4Address '127.0.0.1'
```

**3. Disable WPAD on clients via GPO:**
- `User Configuration → Administrative Templates → Windows Components → Internet Explorer → Disable changing Automatic Configuration settings = Enabled`
- `User Configuration → Preferences → Control Panel Settings → Internet Settings` → uncheck "Automatically detect settings"
- For modern browsers also disable the `WinHttp` auto-proxy service:
  ```
  sc.exe config WinHttpAutoProxySvc start= disabled
  ```

## What might break

- Nothing if no one was using WPAD. If a business unit relied on auto-proxy discovery, give them an explicit PAC file URL via `AutoConfigURL`.

## Rollback

Reverse the GPO settings, remove the sinkhole DNS record, restore the GQBL to whatever it was. `gpupdate /force` on clients.

## Validate the fix

```powershell
Resolve-DnsName wpad.<yourdomain>
# Should return 127.0.0.1 or NXDOMAIN, not an attacker IP
```

From a test attacker host on a user subnet, attempt to register `wpad` via DHCP option 252 or NBT-NS spoofing — clients should not accept the proxy config.

## References

- US-CERT: TA16-144A (WPAD Name Collision Vulnerability)
- Microsoft: [Configure WPAD](https://learn.microsoft.com/en-us/windows-server/networking/branchcache/deploy/use-bits-with-branchcache)
- MITRE ATT&CK: T1557.001
