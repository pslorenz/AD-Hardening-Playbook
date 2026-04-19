# Tiered Administrative Model Not Implemented

**Category:** Governance (Architecture)
**Operational Risk of Remediation:** High (multi-month project)
**Attacker Skill Required to Exploit:** Low (one phishing email is enough without tiering)

## What it is

The Microsoft tier model (sometimes called the Enterprise Access Model) divides administrative accounts and the systems they manage into isolated tiers, with strict rules about which tier-N account can log into which tier-M system.

- **Tier 0**: Forest/domain control plane. Domain Controllers, AD CS, ADFS, Azure AD Connect, PAM solutions, identity providers, the things that can grant credentials. Tier 0 admins use Tier 0 accounts only on Tier 0 systems, accessed only from Privileged Access Workstations (PAWs).
- **Tier 1**: Servers and applications. Server admins use Tier 1 accounts only on Tier 1 systems.
- **Tier 2**: Workstations and end-user devices. Helpdesk admins use Tier 2 accounts only on Tier 2 systems.

The rule that matters: **a higher-tier credential never touches a lower-tier system**. If a DA logs into a workstation, the entire purpose of having a DA account collapses — the next time that workstation is compromised, so is the domain.

## Why this matters

Without tiering, your domain's effective security is the security of the *least-secure machine any admin has ever logged into*. With tiering, an attacker compromising tier 2 stays in tier 2.

Most "we got ransomwared" incidents involve a tier 0 account logging into a tier 2 box at some point.

## How to confirm it's not implemented

Indicators that you have no functional tier model:
- Domain Admins regularly RDP to workstations or member servers (see [`domain-admins-on-workstations.md`](../privileged-access/domain-admins-on-workstations.md)).
- Server admins use the same account for servers, workstations, and email.
- IT staff have one account they use for everything.
- There's no separate OU structure for admin accounts.
- No PAWs (Privileged Access Workstations) exist.
- No "deny logon" GPOs prevent cross-tier authentication.

```powershell
# Crude check — does each DA also have an active mailbox / regular workstation logons?
$das = Get-ADGroupMember 'Domain Admins' -Recursive
foreach ($d in $das) {
    Get-ADUser $d -Properties LastLogon, mail, Description | Select-Object SamAccountName, mail, Description
}
# If DAs have email addresses that match human users, those accounts are also being used for daily work — wrong.
```

The right pattern: every human admin has TWO (or more) accounts. `jsmith` for email/web/normal use, `jsmith-admin` for tier 1 server admin, `jsmith-da` for tier 0 (and used only on PAWs).

## What to audit before remediation

This is a multi-month project, not a Tuesday afternoon fix. Before starting:

1. **Inventory current admin accounts and their actual usage.** Who logs into what, with which account?
2. **Map applications to tiers.** What's tier 0? Most orgs have more than they realize (Azure AD Connect, ADFS, vCenter for VMs hosting DCs, PKI, anything that issues credentials).
3. **Identify cross-tier dependencies that need to be broken.** E.g., "the SCCM site server uses a domain admin service account" — that's a tier 0/tier 1 mixing problem.
4. **Plan the OU structure.** Separate OUs for tier 0 / tier 1 / tier 2 admin accounts and computers, each with their own GPO scope.
5. **Plan PAWs.** Even one or two PAWs for tier 0 work is dramatically better than zero.

## Remediation (high-level program)

This document is a roadmap, not a single fix. Each step is its own work stream.

**Step 1 — OU structure.** Create:
```
OU=Tier0,DC=example,DC=local
    OU=Tier0-Users
    OU=Tier0-Computers   (DCs, AD CS, ADFS, AAD Connect)
    OU=Tier0-Groups
OU=Tier1,DC=example,DC=local
    OU=Tier1-Users       (server admin accounts)
    OU=Tier1-Servers
    OU=Tier1-Groups
OU=Tier2,DC=example,DC=local
    OU=Tier2-Users       (helpdesk admin accounts)
    OU=Tier2-Workstations
    OU=Tier2-Groups
```

**Step 2 — Create per-tier admin accounts.** Each human admin gets `name`, `name-t1`, `name-t0` as appropriate. Long random passwords. Add to Protected Users (see [`protected-users-not-used.md`](../privileged-access/protected-users-not-used.md)). Set "Account is sensitive and cannot be delegated."

**Step 3 — Deny-logon GPOs.** Apply at OU scope:
- On Tier 2 (workstations) OU: deny interactive/RDP logon for Tier 0 and Tier 1 admin groups.
- On Tier 1 (servers) OU: deny interactive/RDP logon for Tier 0 admin groups; deny for Tier 2.
- On Tier 0 (DCs etc.) OU: deny logon for everyone except Tier 0 admin groups.

Use `Deny log on locally`, `Deny log on through Remote Desktop Services`, `Deny access to this computer from the network`, `Deny log on as a batch job`, `Deny log on as a service`.

**Step 4 — Build PAWs.** Dedicated workstations (physical or VDI) used solely for tier 0 work. Hardened image, no email, no internet, no productivity apps. Tier 0 accounts can only be used from PAWs.

**Step 5 — Migrate workflows.** Service accounts, scheduled tasks, monitoring agents — anything currently running as a Domain Admin needs a different identity (gMSA, tier 1 service account).

**Step 6 — Remove the legacy admin accounts.** Once new tiered accounts are in use and validated, decommission the old "do everything" accounts.

**Step 7 — Continuous validation.** Quarterly review of who's logging into what, with which account, from where.

## What might break

- Workflows: every "I just RDP'd in as DA to fix the printer" workflow has to change. Big cultural shift.
- Operational efficiency in the short term — admins now have more steps to do their jobs.
- Specific tools that assume a single admin identity (some old vendor management consoles).

The benefit: the day someone phishes a helpdesk tech, the blast radius is helpdesk's tier 2 systems, not your domain.

## Rollback

You can dial back the deny-logon GPOs at any time. The OU structure and per-tier accounts can stay even if the enforcement is loosened — they cost nothing.

## Validate

After deployment:
- Try to RDP as a Tier 0 account to a Tier 2 workstation — should be denied.
- Try to RDP as a Tier 2 account to a Domain Controller — should be denied.
- Run `Get-WinEvent` queries for Event 4624 across the fleet, filtered for cross-tier account/host combinations — should return zero.

Use BloodHound to look for residual cross-tier paths (see [`bloodhound-attack-paths.md`](bloodhound-attack-paths.md)).

## References

- Microsoft: [Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- Microsoft: [Privileged Access Workstations](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment)
- Microsoft: [Securing privileged access](https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview)
