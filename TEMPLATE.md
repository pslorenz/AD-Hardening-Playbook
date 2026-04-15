# [Finding Name]

**Category:** [Authentication Protocols / Network Services / Kerberos / ADCS / Privileged Access / Accounts & Policies / Legacy]
**Operational Risk of Remediation:** [Low / Medium / High]
**Attacker Skill Required to Exploit:** [Low / Medium / High]

## What it is

One or two paragraphs. Plain English. Assume the reader has heard of AD but has not read a Microsoft whitepaper this week.

## What attack it enables

What can a foothold inside the network do with this? Be specific (credential theft, privilege escalation to DA, lateral movement, etc.).

## How to confirm it's present in your environment

The exact PowerShell, `nmap`, registry query, or LDAP query a junior admin runs to see whether they have this problem. Include expected output.

```powershell
# Example
Get-ADObject ...
```

## What to audit before remediation

The single most important section. What event logs, auditing GPOs, or test deployments should be in place *before* the fix is applied?

- Event IDs to watch
- Where to find them
- How long to leave audit running (typically 1–2 weeks)
- What "clean" looks like

## Remediation

Step-by-step. Exact GPO paths. Exact registry keys. Exact PowerShell. No ambiguity.

## What might break

Honest list. If the answer is "nothing," say so — that's useful information.

## Rollback

How to undo the change in under five minutes if the helpdesk lights up.

## Validate the fix

How to confirm post-change that the fix is in place AND attackers cannot exploit it. Include both defender-side checks and attacker-side checks where appropriate (e.g., "run Responder in analyze mode and confirm no LLMNR queries appear").

## References

- Microsoft Docs: ...
- MITRE ATT&CK: T...
- Original research / advisory: ...
