@{
    Controls = @(
        @{
            Id         = 'WU-001'
            Title      = 'Automatic Updates are enabled by policy'
            Category   = 'WindowsUpdate'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'NoAutoUpdate'; ValueType = 'DWord' }
            Expected   = 0
            Rationale  = 'Unpatched servers are the most common root cause of successful intrusions.'
            Impact     = 'If updates are managed by WSUS, SCCM or Azure Update Manager, exclude the WU controls or align them with that tooling.'
            References = @{
                Benchmark   = 'CIS: Configure Automatic Updates = Enabled'
                MitreAttack = @('T1190', 'T1210')
            }
        }
        @{
            Id         = 'WU-002'
            Title      = 'Updates are downloaded automatically and installed on a schedule'
            Category   = 'WindowsUpdate'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'AUOptions'; ValueType = 'DWord' }
            Expected   = 4
            Rationale  = 'Option 4 (auto download and schedule the install) ensures patches are applied without depending on manual action.'
            Impact     = 'The server installs updates and may restart at the scheduled time (see WU-003).'
            References = @{
                Benchmark   = 'CIS: Configure Automatic Updates = 4 - Auto download and schedule the install'
                MitreAttack = @('T1190')
            }
        }
        @{
            Id         = 'WU-003'
            Title      = 'Scheduled install day is configured'
            Category   = 'WindowsUpdate'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'ScheduledInstallDay'; ValueType = 'DWord' }
            Expected   = 0
            Parameter  = 'ScheduledInstallDay'
            Rationale  = 'A defined install day (0 = every day) keeps the patch window predictable and short.'
            References = @{ Benchmark = 'CIS: Configure Automatic Updates: Scheduled install day = 0 - Every day' }
        }
        @{
            Id         = 'WU-004'
            Title      = 'Security updates were installed recently'
            Category   = 'WindowsUpdate'
            Severity   = 'High'
            Type       = 'Custom'
            Target     = @{ Check = 'UpdateRecency'; ManualRemediation = 'Install the latest cumulative update through Windows Update, WSUS or your patch management tool.' }
            Expected   = 35
            Operator   = 'LessOrEqual'
            Parameter  = 'MaxDaysSinceLastUpdate'
            Rationale  = 'Microsoft ships cumulative security updates monthly; a server without an update in more than about a month is missing security fixes.'
            References = @{
                Benchmark   = 'Patch management best practice'
                MitreAttack = @('T1190', 'T1210', 'T1068')
            }
        }
        @{
            Id         = 'WU-005'
            Title      = 'No software updates are pending installation'
            Category   = 'WindowsUpdate'
            Severity   = 'High'
            Type       = 'Custom'
            Target     = @{ Check = 'PendingUpdates'; ManualRemediation = 'Install pending updates and restart during the next maintenance window.' }
            Expected   = 0
            Rationale  = 'Approved but uninstalled updates leave known vulnerabilities open.'
            Impact     = 'The scan queries Windows Update or WSUS and can take several minutes. Set the profile parameter SkipPendingUpdateScan to true to skip it.'
            References = @{
                Benchmark   = 'Patch management best practice'
                MitreAttack = @('T1190', 'T1210')
            }
        }
    )
}
