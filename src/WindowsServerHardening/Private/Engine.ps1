function New-ControlState {
    # The contract every provider's Get-<Type>State returns.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()]
        [object]$Value,

        [bool]$Exists = $true,

        [string]$Display,

        [bool]$Applicable = $true,

        [string]$Reason,

        [Nullable[bool]]$Compliant = $null,

        [hashtable]$Extra = @{}
    )

    if (-not $PSBoundParameters.ContainsKey('Display')) {
        $Display = Format-HardeningValue -Value $Value
    }

    return [pscustomobject]@{
        Value      = $Value
        Exists     = $Exists
        Display    = $Display
        Applicable = $Applicable
        Reason     = $Reason
        Compliant  = $Compliant
        Extra      = $Extra
    }
}

function New-HardeningResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [string]$ComputerName = $env:COMPUTERNAME
    )

    return [pscustomobject]@{
        PSTypeName     = 'WindowsServerHardening.Result'
        Id             = $Control.Id
        Title          = $Control.Title
        Category       = $Control.Category
        Severity       = $Control.Severity
        Status         = 'Error'
        Expected       = $Control.ExpectedDisplay
        Actual         = $null
        Detail         = $null
        Remediation    = $Control.Remediation
        AuditOnly      = $Control.AuditOnly
        RebootRequired = $false
        Rationale      = $Control.Rationale
        Impact         = $Control.Impact
        Benchmark      = $Control.Benchmark
        MitreAttack    = @($Control.MitreAttack)
        Links          = @($Control.Links)
        ComputerName   = $ComputerName
        Timestamp      = Get-Date
        DurationMs     = 0
    }
}

function Invoke-HardeningProvider {
    # Dispatches to Get-/Set-<Type>State. Commands are invoked by name so Pester mocks apply, and
    # Context/State are only passed to providers that declare those parameters.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Set')]
        [string]$Action,

        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [hashtable]$Context,

        [pscustomobject]$State
    )

    $name = '{0}-{1}State' -f $Action, $Control.Type
    $command = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "No '$Action' provider is implemented for control type '$($Control.Type)'."
    }

    $arguments = @{ Control = $Control }
    if ($command.Parameters.ContainsKey('Context')) { $arguments.Context = $Context }
    if ($command.Parameters.ContainsKey('State')) { $arguments.State = $State }
    & $name @arguments
}

function Test-ControlCompliance {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [pscustomobject]$State
    )

    if ($null -ne $State.Compliant) {
        return [bool]$State.Compliant
    }

    $name = "Test-$($Control.Type)State"
    if (Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue) {
        return [bool](& $name -Control $Control -State $State)
    }

    return (Test-HardeningValue -Actual $State.Value -Control $Control)
}

function Get-ControlSkipReason {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    $role = $Context.System.Role
    if (@($Control.Roles).Count -gt 0 -and $Control.Roles -notcontains $role) {
        return "Applies only to: $($Control.Roles -join ', ') (this computer: $role)."
    }
    if ($Control.ExcludeRoles -contains $role) {
        return "Not applicable to the $role role."
    }

    $build = Get-HardeningOSBuild -SystemInfo $Context.System
    if ($Control.MinimumBuild -gt 0 -and $build -gt 0 -and $build -lt $Control.MinimumBuild) {
        return "Requires Windows build $($Control.MinimumBuild) or later ($(Get-HardeningOSRelease -Build $Control.MinimumBuild)); this computer runs build $build."
    }
    return $null
}

function Get-HardeningOSBuild {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [AllowNull()]
        [object]$SystemInfo
    )

    $build = 0
    if ($null -ne $SystemInfo -and $SystemInfo.PSObject.Properties['OSBuild']) {
        [void][int]::TryParse([string]$SystemInfo.OSBuild, [ref]$build)
    }
    return $build
}

function Get-HardeningOSRelease {
    # Maps a Windows build number to the matching Windows Server release name.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int]$Build
    )

    if ($Build -ge 26100) { return 'Windows Server 2025' }
    if ($Build -ge 20348) { return 'Windows Server 2022' }
    if ($Build -ge 17763) { return 'Windows Server 2019' }
    if ($Build -ge 14393) { return 'Windows Server 2016' }
    if ($Build -ge 9600) { return 'Windows Server 2012 R2' }
    if ($Build -ge 9200) { return 'Windows Server 2012' }
    return "Windows build $Build"
}

function Invoke-HardeningControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $result = New-HardeningResult -Control $Control -ComputerName $Context.System.ComputerName
    try {
        Invoke-HardeningControlCore -Control $Control -Context $Context -Result $result
    }
    catch {
        $result.Status = 'Error'
        $result.Detail = $_.Exception.Message
        Write-HardeningLog -Message "[$($Control.Id)] $($_.Exception.Message)" -Level Error -NoConsole
    }
    finally {
        $timer.Stop()
        $result.DurationMs = $timer.ElapsedMilliseconds
    }
    return $result
}

function Invoke-HardeningControlCore {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'ShouldProcess is called on the public cmdlet passed in the context, so -WhatIf and -Confirm apply per control.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context,

        [Parameter(Mandatory)]
        [pscustomobject]$Result
    )

    $skipReason = Get-ControlSkipReason -Control $Control -Context $Context
    if ($skipReason) {
        $Result.Status = 'NotApplicable'
        $Result.Detail = $skipReason
        return
    }

    $state = Invoke-HardeningProvider -Action Get -Control $Control -Context $Context
    if (-not $state.Applicable) {
        $Result.Status = 'NotApplicable'
        $Result.Detail = $state.Reason
        return
    }

    $Result.Actual = $state.Display
    if (Test-ControlCompliance -Control $Control -State $state) {
        $Result.Status = 'Pass'
        $Result.Detail = 'Compliant.'
        return
    }

    $Result.Status = 'Fail'
    if ($Context.Mode -eq 'Audit') {
        $Result.Detail = 'Not compliant.'
        return
    }
    if ($Control.AuditOnly) {
        $Result.Detail = 'Not compliant. This control is audit-only and must be remediated manually.'
        return
    }
    if (-not $Context.Cmdlet.ShouldProcess("$($Control.Id) - $($Control.Title)", $Control.Remediation)) {
        $Result.Detail = "Not changed (-WhatIf or declined). Planned: $($Control.Remediation)"
        return
    }

    # The previous state is persisted before anything is modified so a crash mid-run can still be rolled back.
    Add-HardeningChange -Session $Context.Session -Control $Control -State $state
    & {
        # Confirmation already happened above; keep inner cmdlets from prompting or honouring -WhatIf again.
        $ConfirmPreference = 'None'
        $WhatIfPreference = $false
        Invoke-HardeningProvider -Action Set -Control $Control -Context $Context -State $state | Out-Null
    }

    $after = Invoke-HardeningProvider -Action Get -Control $Control -Context $Context
    $Result.Actual = $after.Display
    if ($after.Applicable -and (Test-ControlCompliance -Control $Control -State $after)) {
        $Result.Status = 'Fixed'
        $Result.Detail = "Remediated. Previous value: $($state.Display)."
        $Result.RebootRequired = $Control.RebootRequired
        Write-HardeningLog -Message "[$($Control.Id)] Remediated: $($Control.Remediation) Previous value: $($state.Display)."
    }
    else {
        $Result.Status = 'Error'
        $Result.Detail = 'The change was applied but verification failed. The setting may be enforced by Group Policy or require a restart.'
        Write-HardeningLog -Message "[$($Control.Id)] Verification failed after remediation (actual: $($after.Display))." -Level Error -NoConsole
    }
}

function Invoke-HardeningRun {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Audit', 'Remediate')]
        [string]$Mode,

        [Parameter(Mandatory)]
        [object[]]$Controls,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$ProfileData,

        [Parameter(Mandatory)]
        [pscustomobject]$SystemInfo,

        [Parameter(Mandatory)]
        [pscustomobject]$Session,

        # The calling cmdlet ($PSCmdlet); only its ShouldProcess method is used, which keeps the engine testable.
        [object]$Cmdlet
    )

    $context = @{
        Mode       = $Mode
        Parameters = $ProfileData.Parameters
        System     = $SystemInfo
        Session    = $Session
        Cmdlet     = $Cmdlet
        Cache      = @{}
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($control in $Controls) {
        $index++
        $percent = [int](($index - 1) / $Controls.Count * 100)
        Write-Progress -Activity "Windows Server Hardening ($Mode)" -Status "[$index/$($Controls.Count)] $($control.Id) $($control.Title)" -PercentComplete $percent
        $results.Add((Invoke-HardeningControl -Control $control -Context $context))
    }
    Write-Progress -Activity "Windows Server Hardening ($Mode)" -Completed

    $endTime = Get-Date
    $summary = Get-HardeningSummary -Results $results.ToArray()
    Write-HardeningLog -Message ("Session {0} finished: score {1}, pass {2}, fixed {3}, fail {4}, error {5}, not applicable {6}." -f $Session.Id, $summary.Score, $summary.Pass, $summary.Fixed, $summary.Fail, $summary.Error, $summary.NotApplicable)

    return [pscustomobject]@{
        PSTypeName      = 'WindowsServerHardening.Run'
        SessionId       = $Session.Id
        Mode            = $Mode
        Profile         = $ProfileData.Name
        ComputerName    = $SystemInfo.ComputerName
        Score           = $summary.Score
        Grade           = $summary.Grade
        StartTime       = $Session.StartTime
        EndTime         = $endTime
        DurationSeconds = [Math]::Round(($endTime - $Session.StartTime).TotalSeconds, 1)
        ModuleVersion   = $script:ModuleVersion
        System          = $SystemInfo
        Summary         = $summary
        Results         = $results.ToArray()
        LogPath         = $Session.LogPath
        Reports         = @()
    }
}

function Get-HardeningSummary {
    # Score is severity weighted (Critical 10, High 5, Medium 3, Low 1) over controls that could be
    # evaluated. Errors count as non-compliant; NotApplicable controls are excluded.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Results
    )

    $count = @{}
    foreach ($status in @('Pass', 'Fixed', 'Fail', 'Error', 'NotApplicable')) {
        $count[$status] = @($Results | Where-Object { $_.Status -eq $status }).Count
    }

    $scored = @($Results | Where-Object { @('Pass', 'Fixed', 'Fail', 'Error') -contains $_.Status })
    $earned = 0
    $possible = 0
    foreach ($result in $scored) {
        $weight = $script:SeverityWeight[[string]$result.Severity]
        $possible += $weight
        if ($result.Status -eq 'Pass' -or $result.Status -eq 'Fixed') { $earned += $weight }
    }

    $score = if ($possible -gt 0) { [int][Math]::Floor($earned / $possible * 100) } else { $null }
    $grade = if ($null -eq $score) { 'N/A' }
    elseif ($score -ge 90) { 'A' }
    elseif ($score -ge 80) { 'B' }
    elseif ($score -ge 70) { 'C' }
    elseif ($score -ge 60) { 'D' }
    else { 'F' }

    $openBySeverity = [ordered]@{}
    foreach ($severity in $script:ValidSeverities) {
        $openBySeverity[$severity] = @($Results | Where-Object { $_.Severity -eq $severity -and ($_.Status -eq 'Fail' -or $_.Status -eq 'Error') }).Count
    }

    $categories = foreach ($group in @($Results | Group-Object -Property Category)) {
        $groupScored = @($group.Group | Where-Object { @('Pass', 'Fixed', 'Fail', 'Error') -contains $_.Status })
        $groupCompliant = @($groupScored | Where-Object { $_.Status -eq 'Pass' -or $_.Status -eq 'Fixed' }).Count
        [pscustomobject]@{
            Name      = $group.Name
            Total     = $group.Count
            Evaluated = $groupScored.Count
            Compliant = $groupCompliant
            Rate      = if ($groupScored.Count -gt 0) { [int][Math]::Floor($groupCompliant / $groupScored.Count * 100) } else { $null }
        }
    }

    $evaluated = $scored.Count
    return [pscustomobject]@{
        Score          = $score
        Grade          = $grade
        ComplianceRate = if ($evaluated -gt 0) { [int][Math]::Floor(($count.Pass + $count.Fixed) / $evaluated * 100) } else { $null }
        Total          = @($Results).Count
        Evaluated      = $evaluated
        Pass           = $count.Pass
        Fixed          = $count.Fixed
        Fail           = $count.Fail
        Error          = $count.Error
        NotApplicable  = $count.NotApplicable
        RebootRequired = (@($Results | Where-Object { $_.RebootRequired }).Count -gt 0)
        OpenBySeverity = $openBySeverity
        Categories     = @($categories)
    }
}
