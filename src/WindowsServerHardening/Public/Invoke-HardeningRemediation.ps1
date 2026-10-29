function Invoke-HardeningRemediation {
    <#
    .SYNOPSIS
        Applies a hardening profile to the local server with per-change rollback data.

    .DESCRIPTION
        Evaluates each control and remediates the non-compliant ones. For every change the
        previous state is written to the session's change log *before* the setting is modified,
        and the setting is read back afterwards to verify it took effect. A control whose value
        does not persist (for example because Group Policy enforces a different value) is
        reported as Error instead of Fixed.

        Audit-only controls and controls listed in the profile's AuditOnlyControls are evaluated
        but never changed. Use -WhatIf to preview every planned change, and
        Undo-HardeningRemediation to roll a session back.

        Requires an elevated session.

    .PARAMETER ProfileName
        Built-in profile to apply: Auto (default), MemberServer, DomainController or WebServer.

    .PARAMETER ProfilePath
        Path to a custom JSON profile.

    .PARAMETER Category
        Only process controls in these categories.

    .PARAMETER ControlId
        Only process these control IDs. Wildcards are supported.

    .PARAMETER ExcludeControlId
        Skip these control IDs. Wildcards are supported.

    .PARAMETER OutputPath
        Root folder for logs, reports and rollback sessions. Defaults to %ProgramData%\WindowsServerHardening.

    .PARAMETER ReportFormat
        Report formats to write: Html, Json, Csv. Defaults to Html and Json.

    .PARAMETER NoReport
        Do not write report files.

    .PARAMETER Force
        Apply changes without prompting for confirmation.

    .EXAMPLE
        Invoke-HardeningRemediation -WhatIf

        Lists every change the automatically selected profile would make, without changing anything.

    .EXAMPLE
        Invoke-HardeningRemediation -ProfileName MemberServer -Category SMB, Authentication -Force

        Remediates only the SMB and Authentication categories without confirmation prompts.

    .EXAMPLE
        Invoke-HardeningRemediation -ProfilePath .\profiles\Contoso.json -Confirm

        Applies a custom profile and asks for confirmation before each change.

    .OUTPUTS
        WindowsServerHardening.Run
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('WindowsServerHardening.Run')]
    param(
        [Alias('Profile')]
        [string]$ProfileName = 'Auto',

        [string]$ProfilePath,

        [string[]]$Category,

        [string[]]$ControlId,

        [string[]]$ExcludeControlId,

        [string]$OutputPath,

        [ValidateSet('Html', 'Json', 'Csv')]
        [string[]]$ReportFormat = @('Html', 'Json'),

        [switch]$NoReport,

        [switch]$Force
    )

    if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm')) {
        $ConfirmPreference = 'None'
    }

    Assert-HardeningElevation
    $system = Get-HardeningSystemInfo
    if (-not $system.IsServer) {
        Write-Warning "This computer runs a client operating system ($($system.OSName)). The baseline targets Windows Server."
    }

    $profileData = Get-HardeningProfileData -Name $ProfileName -Path $ProfilePath -SystemInfo $system
    $controls = @(Resolve-HardeningControlSet -ProfileData $profileData -Category $Category -ControlId $ControlId -ExcludeControlId $ExcludeControlId)
    if ($controls.Count -eq 0) {
        throw 'No controls matched the selected profile and filters.'
    }

    $session = New-HardeningSession -Mode Remediate -OutputPath $OutputPath -ProfileName $profileData.Name
    $run = $null
    try {
        $run = Invoke-HardeningRun -Mode Remediate -Controls $controls -ProfileData $profileData -SystemInfo $system -Session $session -Cmdlet $PSCmdlet
        $session.Status = 'Completed'
    }
    catch {
        $session.Status = 'Failed'
        Write-HardeningLog -Message "Remediation session $($session.Id) failed: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        $session.EndTime = Get-Date
        Save-HardeningSessionMetadata -Session $session
    }

    if ($session.ChangeCount -gt 0) {
        Write-HardeningLog -Message "Session $($session.Id) recorded $($session.ChangeCount) change(s). Roll back with: Undo-HardeningRemediation -SessionId $($session.Id)"
    }
    if ($run.Summary.RebootRequired) {
        Write-Warning 'One or more remediated settings take effect only after a restart.'
    }
    if (-not $NoReport) {
        $run.Reports = @(Export-HardeningReport -Run $run -Format $ReportFormat -Path $session.ReportsPath | ForEach-Object { $_.FullName })
    }
    return $run
}
