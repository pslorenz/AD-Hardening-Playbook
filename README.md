# AD Hardening Playbook

A practical, contributor-friendly catalog of common Active Directory misconfigurations and weaknesses, written for **junior security analysts and systems administrators** who need to fix issues without taking down production.

Every finding in this repo follows the same template:

- **What it is** and the attack it enables
- **Likelihood of operational impact** (Low / Medium / High)
- **How to confirm it's actually present** in your environment
- **What to audit before changing anything** (the logs, event IDs, and queries that tell you who will break)
- **The remediation itself**, with the exact GPO / PowerShell / registry change
- **What it might break** and how to roll back
- **How to validate the fix worked**

The goal is that you can hand any one of these documents to a junior admin on a Tuesday morning and they can safely close the finding by Friday.

## Finding index

### Authentication protocols
- [LLMNR / NBT-NS poisoning](authentication-protocols/llmnr-nbtns-poisoning.md)
- [NTLMv1 still allowed](authentication-protocols/ntlmv1-enabled.md)

### Network services
- [LDAP signing not enforced](network-services/ldap-signing-not-enforced.md)
- [SMB signing not required](network-services/smb-signing-not-required.md)
- [SMBv1 enabled](network-services/smbv1-enabled.md)
- [WPAD spoofing](network-services/wpad-spoofing.md)
- [IPv6 / mitm6](network-services/ipv6-mitm6.md)
- [RDP exposed or weakly configured](network-services/rdp-exposed-or-weak.md)
- [Anonymous AD enumeration (LDAP / SAMR / Pre-Win2K)](network-services/anonymous-ldap-samr-enumeration.md)

### Kerberos
- [Kerberoasting (weak service account passwords)](kerberos/kerberoasting.md)
- [AS-REP roasting (DONT_REQUIRE_PREAUTH)](kerberos/asreproasting.md)
- [Unconstrained delegation](kerberos/unconstrained-delegation.md)

### Active Directory Certificate Services
- [ESC1 — Misconfigured certificate templates](adcs/esc1-misconfigured-templates.md)
- [ESC8 — NTLM relay to AD CS HTTP endpoints](adcs/esc8-ntlm-relay-to-adcs.md)

### Privileged access
- [Domain Admins logging into workstations](privileged-access/domain-admins-on-workstations.md)
- [Protected Users group not used](privileged-access/protected-users-not-used.md)
- [BloodHound attack paths (finding and prioritising)](privileged-access/bloodhound-attack-paths.md)
- [Dangerous AD ACLs on sensitive objects](privileged-access/ad-acl-misconfigurations.md)
- [Dangerous built-in groups over-populated](privileged-access/dangerous-builtin-groups.md)
- [Entra Connect server treated as member server](privileged-access/entra-connect-is-tier0.md)

### Accounts and policies
- [krbtgt password not rotated](accounts-policies/krbtgt-not-rotated.md)
- [MachineAccountQuota = 10 (default)](accounts-policies/machine-account-quota.md)
- [LAPS not deployed](accounts-policies/laps-not-deployed.md)
- [GPP cpassword in SYSVOL](accounts-policies/gpp-cpassword.md)
- [Weak account lockout / password spray exposure](accounts-policies/weak-account-lockout-and-spray.md)
- [Stale accounts and password hygiene](accounts-policies/stale-accounts-password-hygiene.md)

### Detection and logging
- [Insufficient audit policy and logging](detection-and-logging/insufficient-audit-policy.md)
- [No honey accounts / honey SPNs deployed](detection-and-logging/honey-accounts-and-spns.md)

### Legacy
- [Print Spooler running on Domain Controllers](legacy/print-spooler-on-dc.md)

## How to use this repo

1. **Don't just start applying fixes.** Read the "What to audit before changing anything" section first. The fastest way to lose a weekend is to flip a GPO that breaks a vendor app no one documented (and trust me, they exist).
2. **Order matters.** Some fixes (LDAP signing, SMB signing) need a 1–2 week audit window before enforcement. Others (LAPS, krbtgt rotation, Protected Users) you can do same-day.
3. **Keep change windows.** Even "safe" changes have a non-zero blast radius in AD. Pair with someone, document the rollback, and don't push to all DCs at once.
4. **Test in audit mode where it exists.** A surprising number of these settings have an audit-only mode that logs what *would* break before you enforce.
5. **Detection before prevention, where possible.** Get logging and honey accounts in place early. They help you measure whether the rest of the work is paying off.

## Suggested learning order for a junior admin

If you're new to AD security and don't know where to start, work through findings in roughly this order. Each one teaches a concept the next ones build on.

1. **Logging first** - [Insufficient audit policy](detection-and-logging/insufficient-audit-policy.md). You can't measure progress without logs. (Being Redone currently)
2. **Quick wins** - [LLMNR/NBT-NS](authentication-protocols/llmnr-nbtns-poisoning.md), [WPAD](network-services/wpad-spoofing.md), [Print Spooler on DCs](legacy/print-spooler-on-dc.md), [GPP cpassword](accounts-policies/gpp-cpassword.md).
3. **Account hygiene** - [Stale accounts](accounts-policies/stale-accounts-password-hygiene.md), [Lockout / spray](accounts-policies/weak-account-lockout-and-spray.md), [LAPS](accounts-policies/laps-not-deployed.md).
4. **Run BloodHound and PingCastle** - read the [ACL misconfigurations](privileged-access/bloodhound-attack-paths.md) finding, then run the tools and use the rest of the repo to interpret what they show you.
5. **Tier 0 work** - [Domain Admins on workstations](privileged-access/domain-admins-on-workstations.md), [Protected Users](privileged-access/protected-users-not-used.md), [Built-in groups](privileged-access/dangerous-builtin-groups.md), [Entra Connect](privileged-access/entra-connect-is-tier0.md).
6. **Bigger projects with audit windows** - [LDAP signing](network-services/ldap-signing-not-enforced.md), [SMB signing](network-services/smb-signing-not-required.md), [SMBv1](network-services/smbv1-enabled.md), [NTLMv1](authentication-protocols/ntlmv1-enabled.md), [IPv6/mitm6](network-services/ipv6-mitm6.md), [RDP](network-services/rdp-exposed-or-weak.md).
7. **Kerberos and ADCS** - [Kerberoasting](kerberos/kerberoasting.md), [AS-REP](kerberos/asreproasting.md), [Unconstrained delegation](kerberos/unconstrained-delegation.md), [ESC1](adcs/esc1-misconfigured-templates.md), [ESC8](adcs/esc8-ntlm-relay-to-adcs.md).
8. **Foundational identity hygiene** - [krbtgt rotation](accounts-policies/krbtgt-not-rotated.md), [MachineAccountQuota](accounts-policies/machine-account-quota.md), [Anonymous enumeration](network-services/anonymous-ldap-samr-enumeration.md).
9. **Detection canaries** - [Honey accounts/SPNs](detection-and-logging/honey-accounts-and-spns.md). High-signal detection layer. (This is being redone currently)

## Tools referenced throughout

These come up across many findings. Worth installing and learning early:

- **PingCastle** - free AD security audit tool, produces ranked report. If you are in managed services or consulting you will need to buy a license. 
- **BloodHound** (Community Edition) - visualizes attack paths in AD.
- **SharpHound** / **bloodhound-ce-python** - collectors for BloodHound.
- **Purple Knight** (Semperis, free) - alternative AD audit tool. Check licensing requirements if you are in managed services or consulting.
- **Certipy** - ADCS enumeration and abuse (and verification of fixes).
- **Microsoft Security Compliance Toolkit** - official baseline GPOs.
- **Sysmon** + community config - endpoint logging.
- **Responder** (analyze mode `-A` for safe defensive testing).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Use [TEMPLATE.md](TEMPLATE.md) for new findings - consistency is what makes this repo useful.

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

These documents describe defensive hardening for environments you own and are authorized to administer. Validation commands are run against your own infrastructure. Don't run anything in here against systems you don't have written authorization to test. If you break something in prod following one of these, you are responsible, not me. Test... Test, and test some more.  
