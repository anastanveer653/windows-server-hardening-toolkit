function Invoke-HardeningAudit {
    <#
    .SYNOPSIS
        Audits a Windows Server against a hardening profile without changing anything.

    .DESCRIPTION
        Evaluates every control of the selected profile (registry, services, SMB, firewall,
        advanced audit policy, account policy and custom checks) and returns a run object with
        per-control results and a severity-weighted security score. HTML, JSON and CSV reports
        are written to the output folder unless -NoReport is specified.

        The audit is read-only. It can run without elevation, but controls that need
        administrator rights (audit policy, security policy, SMB configuration) are then
        reported with status Error.

        With -ComputerName the module is copied to each server over PowerShell remoting, the
        audit runs there, and the reports are written locally.

    .PARAMETER ProfileName
        Built-in profile to apply: Auto (default), MemberServer, DomainController or WebServer.
        Auto selects DomainController on domain controllers and MemberServer otherwise.

    .PARAMETER ProfilePath
        Path to a custom JSON profile. Custom profiles can extend a built-in profile with "Extends".

    .PARAMETER Category
        Only evaluate controls in these categories (for example SMB, Authentication, Firewall).

    .PARAMETER ControlId
        Only evaluate these control IDs. Wildcards are supported (for example 'SMB-*').
        Explicitly selected opt-in controls are included.

    .PARAMETER ExcludeControlId
        Skip these control IDs. Wildcards are supported.

    .PARAMETER OutputPath
        Root folder for logs and reports. Defaults to %ProgramData%\WindowsServerHardening.

    .PARAMETER ReportFormat
        Report formats to write: Html, Json, Csv. Defaults to Html and Json.

    .PARAMETER NoReport
        Do not write report files; only return the run object.

    .PARAMETER ComputerName
        Remote servers to audit over PowerShell remoting (WinRM).

    .PARAMETER Credential
        Credential for the remote sessions.

    .EXAMPLE
        Invoke-HardeningAudit

        Audits the local server with the automatically selected profile and writes HTML and JSON reports.

    .EXAMPLE
        Invoke-HardeningAudit -ProfileName WebServer -ReportFormat Html, Csv -OutputPath D:\Compliance

        Audits against the WebServer profile and writes HTML and CSV reports to D:\Compliance\reports.

    .EXAMPLE
        $run = Invoke-HardeningAudit -NoReport
        $run.Results | Where-Object Status -in 'Fail', 'Error' | Sort-Object Severity | Format-Table Id, Severity, Title, Actual

        Returns results to the pipeline for further processing.

    .EXAMPLE
        Invoke-HardeningAudit -ComputerName SRV01, SRV02 -Credential (Get-Credential)

        Audits two remote servers and writes one report per server locally.

    .OUTPUTS
        WindowsServerHardening.Run
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
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

        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter(ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($PSCmdlet.ParameterSetName -eq 'Remote') {
        $forward = @{ ProfileName = $ProfileName }
        foreach ($name in @('Category', 'ControlId', 'ExcludeControlId')) {
            if ($PSBoundParameters.ContainsKey($name)) { $forward[$name] = $PSBoundParameters[$name] }
        }
        $reportPath = Join-Path -Path (Resolve-HardeningOutputRoot -Path $OutputPath) -ChildPath 'reports'
        foreach ($computer in $ComputerName) {
            try {
                $run = Invoke-RemoteHardeningAudit -ComputerName $computer -Credential $Credential -Parameters $forward -ProfilePath $ProfilePath
                if (-not $NoReport) {
                    $run.Reports = @(Export-HardeningReport -Run $run -Format $ReportFormat -Path $reportPath | ForEach-Object { $_.FullName })
                }
                $run
            }
            catch {
                Write-Error -Message "[$computer] Remote audit failed: $($_.Exception.Message)" -TargetObject $computer -Category ConnectionError
            }
        }
        return
    }

    $system = Get-HardeningSystemInfo
    if (-not $system.IsElevated) {
        Write-Warning 'Not running elevated. Audit policy and account/security policy checks need administrator rights and will be reported as errors.'
    }
    if (-not $system.IsServer) {
        Write-Warning "This computer runs a client operating system ($($system.OSName)). The baseline targets Windows Server; treat results as indicative."
    }

    $profileData = Get-HardeningProfileData -Name $ProfileName -Path $ProfilePath -SystemInfo $system
    $controls = @(Resolve-HardeningControlSet -ProfileData $profileData -Category $Category -ControlId $ControlId -ExcludeControlId $ExcludeControlId)
    if ($controls.Count -eq 0) {
        throw 'No controls matched the selected profile and filters.'
    }

    $session = New-HardeningSession -Mode Audit -OutputPath $OutputPath -ProfileName $profileData.Name
    $run = Invoke-HardeningRun -Mode Audit -Controls $controls -ProfileData $profileData -SystemInfo $system -Session $session -Cmdlet $PSCmdlet
    if (-not $NoReport) {
        $run.Reports = @(Export-HardeningReport -Run $run -Format $ReportFormat -Path $session.ReportsPath | ForEach-Object { $_.FullName })
    }
    return $run
}
