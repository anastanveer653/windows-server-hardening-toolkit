# Compatibility

The toolkit runs on every Windows Server release from 2012 to 2025, on Windows PowerShell 5.1 and
PowerShell 7, with Desktop Experience or Server Core, and on any display language.

## Supported releases

| Windows Server | Build | PowerShell out of the box | .NET out of the box | What you need | How it is verified |
|---|---|---|---|---|---|
| 2025 | 26100 | 5.1 | 4.8.1 | Nothing | CI on every push: unit tests and the full audit, harden and rollback lifecycle, on PowerShell 5.1 and 7 |
| 2022 | 20348 | 5.1 | 4.8 | Nothing | CI on every push: unit tests and the full lifecycle, on PowerShell 5.1 and 7 |
| 2019 | 17763 | 5.1 | 4.7.2 | Nothing | [Integration test](#verify-a-server-yourself) on a VM |
| 2016 | 14393 | 5.1 | 4.6.2 | Nothing | **Audit verified on a real server** ([details](#verification-log)); hardening and rollback: [integration test](#verify-a-server-yourself) on a VM |
| 2012 R2 | 9600 | 4.0 | 4.5.1 | [WMF 5.1](https://aka.ms/wmf51download), which needs .NET 4.5.2 or later | [Integration test](#verify-a-server-yourself) on a VM |
| 2012 | 9200 | 3.0 | 4.5 | [WMF 5.1](https://aka.ms/wmf51download), which needs .NET 4.5.2 or later | [Integration test](#verify-a-server-yourself) on a VM |

Windows Server 2012 and 2012 R2 reached the end of extended support in October 2023. They are
supported here because many environments still run them, often with Extended Security Updates.

Windows Server 2008 R2 and older are not supported, because they lack the `NetSecurity` and
`SmbShare` modules the toolkit uses.

If `Harden-WindowsServer.ps1` is started on PowerShell 3.0 or 4.0, it tells you to install WMF 5.1
instead of failing with a parser error.

## Behaviour that depends on the Windows release

Some settings only exist on newer releases. On older releases, the controls below are reported as
**NotApplicable** and are excluded from the score, rather than being shown as a false failure:

| Control | Needs | Reason |
|---|---|---|
| AUTH-004 LSA protection (RunAsPPL) | 2012 R2 | Introduced in Windows 8.1 / Server 2012 R2 |
| AUTH-013 Credential Guard | 2016 | Virtualization-based security was introduced in Server 2016 |
| SMB-007 Insecure guest logons | 2016 | Policy introduced with Windows 10 / Server 2016 |
| LOG-021 Command line in process creation events | 2012 R2 | Introduced in Windows 8.1 / Server 2012 R2 |

Other version-specific defaults the toolkit takes into account:

- **WDigest** (AUTH-003) is off by default only from Server 2012 R2 onwards. On Server 2012 a
  missing `UseLogonCredential` value is treated as *not configured* (non-compliant), not as
  compliant.
- **LSA protection** accepts both `RunAsPPL = 1` (with UEFI lock) and `RunAsPPL = 2` (without UEFI
  lock, used by Windows Server 2025 and Windows 11 22H2+).
- **SMBv1 client driver** (SMB-002) is reported as NotApplicable where the SMBv1 feature has been
  removed (the default on Server 2019 and later).
- **Services** that are not installed on a release or installation type (for example consumer
  services on Server Core) are reported as NotApplicable.

## Language and installation type

- **Any display language:** advanced audit policy is read and written by subcategory GUID
  (`auditpol /backup`), and account policy through `secedit` key names. Nothing parses localized
  command output.
- **Server Core:** fully supported. Reports are written as files; open the HTML report on any
  machine with a browser.
- **Domain controllers and member servers:** detected automatically (`-ProfileName Auto`).
- **FIPS mode:** no MD5 or other non-FIPS algorithms are used.

## Runtime requirements

- Windows PowerShell 5.1 or PowerShell 7.x.
- An elevated session for hardening and rollback. A non-elevated audit also works, but audit policy
  and account policy controls are then reported as errors.
- For remote audits: WinRM (PowerShell remoting) on the target servers.

## Developer tooling (tests only)

End users never need Pester. To run the unit tests, `build.ps1` selects a compatible Pester version
automatically:

| .NET Framework on the machine | Pester version used |
|---|---|
| 4.7.2 or later (Server 2019+) | Newest installed 5.5 or later, including 6.x |
| Older than 4.7.2 (Server 2012 / 2012 R2 / 2016 without updates) | 5.5 or 5.6 (`Install-Module Pester -RequiredVersion 5.6.1`) |

Pester 5.7 and later call a .NET API (`HashSet(int capacity)`) that does not exist before
.NET 4.7.2, so they fail on an unpatched Server 2016.

## Verify a server yourself

Run the integration test on a test VM (take a snapshot first). It audits the server, hardens it,
verifies the changes, checks that a second run changes nothing, rolls everything back, and confirms
that the server matches the original state:

```powershell
# Elevated PowerShell, from the repository folder
Get-ChildItem -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

.\tests\Integration\Invoke-IntegrationTest.ps1             # full lifecycle (asks for confirmation)
.\tests\Integration\Invoke-IntegrationTest.ps1 -AuditOnly  # read-only checks only
```

The script prints a PASS/FAIL line for each check and writes an evidence file,
`integration-<computer>-<timestamp>.json`, under `%ProgramData%\WindowsServerHardening-IntegrationTest`.
The file records the OS, build, PowerShell and .NET versions and the outcome of every check. Exit
code 0 means every check passed.

On production servers, use `-AuditOnly` only. It never changes the system.

## Verification log

Results of the integration test on real servers (host names omitted):

| Date | Windows Server | Build | PowerShell | .NET | Mode | Result |
|---|---|---|---|---|---|---|
| 2026-10-29 | 2016 Standard (on-premises) | 14393 | 5.1.14393 | 4.6.2 (394802) | Audit only | 3/3 checks passed; 102 controls evaluated, 0 errors |
| 2026-10-29 | 2022 Datacenter (GitHub runner) | 20348 | 5.1.20348 | 4.8 | Full lifecycle | 12/12 checks passed; score 47 -> 95 after hardening -> 47 after rollback; 51 changes, 51 restored |
| 2026-10-29 | 2022 Datacenter (GitHub runner) | 20348 | 7.6.9 | - | Full lifecycle | 12/12 checks passed; score 47 -> 95 -> 47; 51 changes, 51 restored |
| 2026-10-29 | 2025 Datacenter (GitHub runner) | 26100 | 5.1.26100 | 4.8.1 | Full lifecycle | 12/12 checks passed; score 46 -> 95 -> 46; 53 changes, 53 restored |
| 2026-10-29 | 2025 Datacenter (GitHub runner) | 26100 | 7.6.7 | - | Full lifecycle | 12/12 checks passed; score 46 -> 95 -> 46; 53 changes, 53 restored |

Hardening and rollback were deliberately not run on that server. CI repeats the full
lifecycle on Windows Server 2022 and 2025 for every push; the evidence files are attached to each CI
run as artifacts. Older releases are verified on VMs.
