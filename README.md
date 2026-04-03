# 🛡️ Windows Server Hardening Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?logo=powershell)
![Windows Server](https://img.shields.io/badge/Windows_Server-2016%20|%202019%20|%202022-0078D6?logo=windows)
![CIS Benchmark](https://img.shields.io/badge/CIS-Benchmark_Aligned-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)

A modular, CIS Benchmark-aligned PowerShell toolkit that **audits and hardens Windows Server** in a single command. Generates a professional HTML report with a security score after every run.

> ✅ No third-party tools required — pure PowerShell, runs on any Windows Server.

---

## ⚡ Quick Start

```powershell
# Run as Administrator

# Audit only (no changes made)
.\Harden-WindowsServer.ps1 -ReportOnly

# Apply all hardening
.\Harden-WindowsServer.ps1

# Harden specific modules only
.\Harden-WindowsServer.ps1 -Modules "SMB,NTLM,Firewall"

# Roll back last session
.\Harden-WindowsServer.ps1 -Rollback
```

---

## 🔍 What It Checks & Fixes (50+ Controls)

### 🗂️ SMB Hardening
| Check | Severity | CIS Control |
|---|---|---|
| SMBv1 Disabled (EternalBlue/WannaCry) | Critical | 18.3.3 |
| SMB Packet Signing Required | High | 2.3.8.3 |
| SMB Data Encryption Enabled | High | 18.3.4 |
| Null Session Access Restricted | High | 2.3.10.2 |

### 🔐 NTLM / Credential Hardening
| Check | Severity | CIS Control |
|---|---|---|
| NTLMv2 Only (LmCompatibilityLevel = 5) | Critical | 2.3.11.7 |
| LM Hash Storage Disabled | Critical | 2.3.11.4 |
| WDigest Disabled (no plaintext in LSASS) | Critical | 18.3.7 |
| LSA Protected Process (anti-Mimikatz) | High | 18.3.1 |

### 📋 Audit Policy
| Check | Severity | CIS Control |
|---|---|---|
| Logon/Logoff Auditing | Medium | 17.5.1 |
| Account Management Auditing | Medium | 17.2.1 |
| Policy Change Auditing | Medium | 17.7.1 |
| Privilege Use Auditing | Medium | 17.6.1 |
| Security Event Log Size (≥512MB) | Low | 18.9.27.1 |

### 🔥 Firewall
| Check | Severity | CIS Control |
|---|---|---|
| Firewall Enabled (All Profiles) | Critical | 9.1.1 |
| Default Inbound = Block | High | 9.1.2 |
| Telnet Port 23 Blocked | High | Custom |
| FTP Port 21 Blocked | Medium | Custom |

### 👤 Account Policy
| Check | Severity | CIS Control |
|---|---|---|
| Minimum Password Length (≥14) | High | 1.1.4 |
| Maximum Password Age (≤90 days) | Medium | 1.1.2 |
| Password History (≥24) | Medium | 1.1.1 |
| Account Lockout (≤5 attempts) | High | 1.2.1 |
| Guest Account Disabled | High | 2.3.1.2 |

### 🗃️ Services
| Check | Severity |
|---|---|
| Print Spooler Disabled (PrintNightmare) | High |
| Remote Registry Disabled | High |
| Telnet Server Disabled | High |
| SNMP Disabled | Medium |
| Xbox/Gaming Services Disabled | Low |

### 🗝️ Registry Hardening
| Check | Severity | CIS Control |
|---|---|---|
| Autorun/Autoplay Disabled | High | 18.8.45.1 |
| Hide Last Logged-On Username | Medium | 2.3.7.1 |
| No Anonymous SAM Enumeration | High | 2.3.10.1 |
| WDigest Disabled | Critical | 18.3.7 |
| Legal Notice Configured | Low | 2.3.7.4 |
| Windows Script Host Disabled | Medium | Custom |

### 🔄 Windows Update
| Check | Severity |
|---|---|
| Automatic Updates Enabled | High |
| Pending Updates Check | High |

---

## 📊 Sample Report Output

After every run, an HTML report is generated in `./reports/`:

```
╔══════════════════════════════════════════════════════╗
║                   SUMMARY                           ║
╠══════════════════════════════════════════════════════╣
║  ✅ Already Compliant : 28                           ║
║  🔧 Fixed             : 15                           ║
║  ⚠️  Needs Attention   : 4                            ║
║  ⏱  Duration          : 12s                          ║
║  📄 Report            : .\reports\hardening-...html  ║
╚══════════════════════════════════════════════════════╝
```

The HTML report includes: **security score**, per-check results with severity, CIS control references, and system information.

---

## 🗂️ Project Structure

```
windows-server-hardening-toolkit/
├── Harden-WindowsServer.ps1          # Main entry point
├── config/
│   └── hardening-config.json         # All settings — customize before running
├── modules/
│   ├── Logger.ps1                    # Logging + result helpers
│   ├── SMB-Hardening.ps1
│   ├── NTLM-Hardening.ps1
│   ├── AuditPolicy-Hardening.ps1
│   ├── Firewall-Hardening.ps1
│   ├── Services-Hardening.ps1
│   ├── AccountPolicy-Hardening.ps1
│   ├── Registry-Hardening.ps1
│   ├── WindowsUpdate-Hardening.ps1
│   └── Report-Generator.ps1          # HTML report engine
├── tests/
│   └── Test-Hardening.ps1            # Audit-only shortcut
├── reports/                          # Auto-generated HTML reports (gitignored)
├── backups/                          # Registry backups before changes (gitignored)
└── logs/                             # Execution logs (gitignored)
```

---

## ⚙️ Configuration

All behaviour is controlled by `config/hardening-config.json`. Key options:

```json
{
  "SMB": { "DisableSMBv1": true, "EnableSMBSigning": true },
  "NTLM": { "NTLMv2Level": 5, "DisableLMHash": true },
  "PasswordPolicy": { "MinimumPasswordLength": 14, "MaximumPasswordAge": 90 },
  "Firewall": { "EnableFirewall": true, "BlockTelnet": true },
  "General": { "RebootAfterHardening": false, "CreateRestorePoint": true }
}
```

---

## 🔄 Rollback

Before any change is made, registry keys are exported to `./backups/`. To undo:

```powershell
.\Harden-WindowsServer.ps1 -Rollback
```

---

## ✅ Tested On

- Windows Server 2016 (Build 14393)
- Windows Server 2019 (Build 17763)
- Windows Server 2022 (Build 20348)

> ⚠️ **Always test in a non-production environment first. Some changes require a reboot.**

---

## 📄 License

MIT © [Anas Tanveer](https://github.com/anastanveer653)
