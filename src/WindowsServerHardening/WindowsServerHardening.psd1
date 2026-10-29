@{
    RootModule           = 'WindowsServerHardening.psm1'
    ModuleVersion        = '2.0.0'
    GUID                 = '5bc85f50-8f4f-4b6b-9979-9e5bb59d13e2'
    Author               = 'Anas Tanveer'
    CompanyName          = 'Anas Tanveer'
    Copyright            = '(c) 2026 Anas Tanveer. Released under the MIT License.'
    Description          = 'Audit, harden and roll back Windows Server security baselines. Data-driven control catalog mapped to CIS Benchmark recommendations and MITRE ATT&CK, with per-change state capture, verified remediation and HTML/JSON/CSV reporting.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FormatsToProcess     = @('WindowsServerHardening.Format.ps1xml')
    FunctionsToExport    = @(
        'Export-HardeningReport'
        'Get-HardeningControl'
        'Get-HardeningProfile'
        'Get-HardeningSession'
        'Invoke-HardeningAudit'
        'Invoke-HardeningRemediation'
        'Undo-HardeningRemediation'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'Hardening', 'CIS', 'Benchmark', 'Compliance', 'Audit', 'WindowsServer', 'MITRE', 'BlueTeam', 'Windows')
            LicenseUri   = 'https://github.com/anastanveer653/windows-server-hardening-toolkit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/anastanveer653/windows-server-hardening-toolkit'
            ReleaseNotes = 'https://github.com/anastanveer653/windows-server-hardening-toolkit/blob/main/CHANGELOG.md'
        }
    }
}
