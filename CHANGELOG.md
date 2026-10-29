# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2026-10-29

### Fixed

- `Harden-WindowsServer.ps1` called through `powershell.exe -File` (scheduled tasks, RMM tools,
  cmd.exe) now accepts comma-separated lists such as `-ReportFormat Json,Html` and
  `-ControlId SMB-*,NET-*`. Before, `-File` passed them as a single string and the run failed.
- Stray arguments are no longer bound positionally to `-Mode`. The script now reports a clear
  parameter error instead.
- The scheduled task example in the README.

### Added

- CLI tests that run the script through `-File`, the way schedulers call it.

## [2.0.0] - 2026-10-29

Complete rewrite as a PowerShell module with a data-driven control catalog.

### Added

- `WindowsServerHardening` module with seven public commands: `Invoke-HardeningAudit`,
  `Invoke-HardeningRemediation`, `Undo-HardeningRemediation`, `Get-HardeningSession`,
  `Get-HardeningControl`, `Get-HardeningProfile` and `Export-HardeningReport`.
- Control catalog with 107 controls in 10 categories (SMB, Authentication, AccountPolicy,
  AuditLogging, Firewall, Services, System, RemoteDesktop, Network, WindowsUpdate). Every control
  carries a rationale, operational impact, CIS recommendation reference and MITRE ATT&CK techniques.
- New coverage: SMB client signing and SMBv1 client driver, NTLM session security, CredSSP oracle
  remediation, Credential Guard, UAC, SEHOP, Secure Boot, PowerShell script block logging, process
  command line auditing, RDP hardening, LLMNR/NetBIOS poisoning protection, SCHANNEL protocols,
  firewall logging and RDP exposure analysis, patch recency.
- Profiles (`MemberServer`, `DomainController`, `WebServer`) with inheritance (`Extends`), opt-in
  controls, exclusions, audit-only overrides and parameters. `-ProfileName Auto` picks the profile
  from the server role.
- Per-change rollback: the previous state of every setting is written to a session change log before
  it is modified; `Undo-HardeningRemediation` restores values, removes created registry keys and
  firewall rules, and restores service start types.
- Post-change verification: a remediated value that does not persist (for example because Group
  Policy overrides it) is reported as `Error` instead of `Fixed`.
- Full `-WhatIf` / `-Confirm` support.
- Self-contained HTML report (no external resources, light/dark mode, filters, search, ATT&CK links),
  versioned JSON report and CSV export. Severity-weighted security score with A-F grade.
- Remote audits over PowerShell remoting (`-ComputerName`, `-Credential`).
- Exit codes for automation: 0 compliant, 1 findings, 2 execution error.
- Pester test suite (unit, provider and end-to-end rollback tests against `TestRegistry:`),
  PSScriptAnalyzer configuration, `build.ps1` and GitHub Actions CI on Windows PowerShell 5.1 and
  PowerShell 7.
- Generated control reference (`docs/CONTROLS.md`) and sample report (`docs/sample-report.html`).
- Support for Windows Server 2012, 2012 R2, 2016, 2019, 2022 and 2025 ([docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)):
  - Controls can declare `MinimumBuild`. Features that do not exist on older releases (LSA
    protection, Credential Guard, insecure guest logon policy, process command line auditing) are
    reported as NotApplicable instead of failing.
  - Registry defaults can be limited to a minimum build (`AbsentValueMinimumBuild`), so a missing
    WDigest value is no longer treated as compliant on Windows Server 2012.
  - Services are read through CIM (`Win32_Service`), because the `StartType` property of
    `Get-Service` needs .NET 4.6.1.
  - `Harden-WindowsServer.ps1` starts on PowerShell 3.0/4.0 and explains that WMF 5.1 is required,
    and it explains how to unblock downloaded files when the execution policy blocks the module.
- Integration test (`tests/Integration/Invoke-IntegrationTest.ps1`): audit, harden, verify,
  idempotency, rollback and baseline comparison on a real server, with a JSON evidence file. CI runs
  it on Windows Server 2022 and 2025 under PowerShell 5.1 and 7.
- `build.ps1` picks a Pester version that works with the installed .NET Framework (Pester 5.7+ needs
  .NET 4.7.2).

### Changed

- **Breaking:** `Harden-WindowsServer.ps1` now defaults to a read-only audit. Use `-Mode Harden` to
  apply changes. The v1 switches `-ReportOnly`, `-Rollback` and `-Modules` are still accepted.
- **Breaking:** `config/hardening-config.json` is replaced by JSON profiles; every setting in a
  profile is now actually honoured.
- Audit policy is read with `auditpol /backup` and set by subcategory GUID; account policy is read
  and written with `secedit`. Both work on non-English Windows installations.
- Output (logs, reports, rollback sessions) defaults to `%ProgramData%\WindowsServerHardening`
  instead of paths relative to the current directory.
- Services that are not installed and controls that do not apply to the server role are reported as
  `NotApplicable` and excluded from the score.

### Fixed

- Scripts failed to parse on Windows PowerShell 5.1 because UTF-8 files without BOM contained
  non-ASCII characters; all source files are now ASCII and a test enforces it.
- Invalid `switch` syntax in the report generator.
- `-ReportOnly` crashed under `Set-StrictMode` when a status count was 0 or 1, so no report was
  produced; the firewall module crashed the same way when all profiles were enabled.
- Rollback looked for a backup file name that was never written and therefore never worked.
- Modules that returned a single result crashed `List.AddRange`.
- `net accounts` parsing failed for "Unlimited" password age and on localized systems.
- Configuration values that were defined but ignored (`NTLMv2Level`, `AllowRDP`, `RDPAllowedSubnet`,
  `LockoutDuration`, `ComplexityEnabled`, scheduled install settings and others).
- HTML report values were not encoded.
- Risky defaults: IIS services were disabled on every server and Windows Script Host was always
  disabled; both are now excluded or opt-in.

### Removed

- The `modules/` folder of dot-sourced scripts and `tests/Test-Hardening.ps1`.
- The DEP registry check that set a non-existent value; DEP is now audited from the actual system policy.

## [1.0.0] - 2026-04-03

- Initial release: script-based hardening for SMB, NTLM, audit policy, firewall, services, account
  policy, registry and Windows Update with an HTML report.
