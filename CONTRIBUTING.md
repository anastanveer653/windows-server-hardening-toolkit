# Contributing

Thanks for helping improve the Windows Server Hardening Toolkit. Bug reports, new controls,
documentation fixes and test improvements are all welcome.

## Development setup

```powershell
git clone https://github.com/anastanveer653/windows-server-hardening-toolkit.git
cd windows-server-hardening-toolkit

Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force

.\build.ps1            # analyze + test + regenerate docs and sample report
.\build.ps1 -Task Test # tests only
```

The test suite does not need administrator rights: registry behaviour is tested against Pester's
`TestRegistry:` drive and system cmdlets are mocked.

## Adding a control

1. Add an entry to the matching file in `src/WindowsServerHardening/Controls/`. Use the next free ID
   with the category prefix (`SMB-`, `AUTH-`, `ACCT-`, `LOG-`, `FW-`, `SVC-`, `SYS-`, `RDP-`,
   `NET-`, `WU-`).
2. Fill in `Rationale` (why it matters), `Impact` (what can break), `References.Benchmark` (CIS
   recommendation title or vendor guidance) and `References.MitreAttack` where applicable.
3. Mark disruptive settings with `OptIn = $true` and settings that need a reboot with
   `RebootRequired = $true`. Use `AbsentValue` only when Microsoft documents the default.
4. If the value should be tunable, add `Parameter = '<Name>'` and the default to
   `Profiles/MemberServer.json`.
5. Run `.\build.ps1`. The catalog tests validate the schema, and `docs/CONTROLS.md` is regenerated.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the control schema and the provider contract.

## Coding conventions

- Target Windows PowerShell 5.1 and PowerShell 7. Do not use `??`, ternaries or other 7-only syntax.
- **Source files must be ASCII only.** Windows PowerShell 5.1 reads BOM-less files as ANSI, and
  characters such as em dashes or emoji corrupt string literals. A test enforces this.
- Use full cmdlet names and named parameters, and no aliases. PSScriptAnalyzer must report no
  findings.
- Public functions need complete comment-based help (synopsis, description, every parameter and at
  least one example).
- Internal file IO uses .NET APIs so `-WhatIf` never suppresses logs, state or reports.

## Pull requests

- Keep each pull request focused on one change and describe the behaviour change in the PR template.
- Add or update tests for every behaviour change.
- Add an entry under `Unreleased` in `CHANGELOG.md`.
- CI must pass on both Windows PowerShell 5.1 and PowerShell 7.
