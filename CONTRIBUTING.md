# Contributing

Thanks for considering a contribution. The audience for this repo is **junior security and systems admins** who need to fix a real environment without breaking it. Keep that reader in mind.

## Adding a new finding

1. Copy `TEMPLATE.md` into the appropriate `findings/<category>/` folder.
2. Name the file in `lower-kebab-case.md` matching the issue (e.g., `unconstrained-delegation.md`).
3. Fill out **every** section of the template. If a section genuinely doesn't apply, write "N/A — [reason]" rather than deleting it.
4. Add a link to the new finding in the index in `README.md`.
5. Open a PR.

## Style guide

- **Plain English.** Assume the reader knows AD basics but is not a Microsoft MVP.
- **Show, don't tell.** Every claim about "how to check" should include the actual command.
- **Honest about breakage.** "What might break" is the most-read section. Don't soft-pedal it. If a fix has broken environments before, say so.
- **No marketing.** No vendor product recommendations unless they are first-party Microsoft tools or genuinely free/open-source. LAPS, BloodHound, PingCastle, Purple Knight, certipy are fine. Commercial PAM products are not the focus.
- **Test before you commit.** If you write a PowerShell one-liner, run it in a lab first.

## What not to add

- Offensive tradecraft beyond what's needed to validate the fix. This is a defender's repo.
- Findings that only apply to a specific niche product version.
- Anything that requires breaking out of scope for a typical sysadmin (firmware reverse engineering, kernel exploits, etc.).

## Reporting issues

If something in here is wrong, dangerous, or out of date, open an issue with the file path and what's wrong. PRs welcome.
