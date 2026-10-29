# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No (scripts do not parse on Windows PowerShell 5.1; upgrade to 2.x) |

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report vulnerabilities privately through GitHub:
**Security > Advisories > [Report a vulnerability](https://github.com/anastanveer653/windows-server-hardening-toolkit/security/advisories/new)**.

Include the affected version, the steps to reproduce and the impact. You can expect an initial
response within five working days. Once a fix is available, it is released with an advisory that
credits the reporter, unless you prefer to stay anonymous.

## Scope

In scope:

- Code in this repository that could be abused to execute code, escalate privileges, disclose data
  (for example through the generated reports or logs) or weaken a system's configuration.
- Controls whose remediation leaves a system *less* secure than before, or whose rollback restores
  an incorrect value.

Out of scope:

- Disagreement with a baseline value. Open a regular issue or adjust the setting in a custom profile.
- Issues that require an attacker to already have administrative rights on the server.

## Safe use

The toolkit changes security-relevant operating system settings. Always run an audit first, review
the planned changes with `-WhatIf`, test in a non-production environment, and keep the
`sessions` folder so changes can be rolled back.
