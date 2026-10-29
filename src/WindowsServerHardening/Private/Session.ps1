# Output layout (default root: %ProgramData%\WindowsServerHardening):
#   logs\<session>.log
#   reports\hardening-<host>-<mode>-<session>.{html,json,csv}
#   sessions\<session>\session.json    metadata (remediation sessions only)
#   sessions\<session>\changes.jsonl   one JSON record per change, written *before* the change

function New-HardeningSession {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Audit', 'Remediate')]
        [string]$Mode,

        [string]$OutputPath,

        [string]$ProfileName
    )

    $root = Resolve-HardeningOutputRoot -Path $OutputPath
    $now = Get-Date
    $id = '{0}-{1}' -f $now.ToString('yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 6)

    $logs = New-HardeningDirectory -Path (Join-Path -Path $root -ChildPath 'logs')
    $reports = New-HardeningDirectory -Path (Join-Path -Path $root -ChildPath 'reports')
    $sessionPath = Join-Path -Path (Join-Path -Path $root -ChildPath 'sessions') -ChildPath $id
    if ($Mode -eq 'Remediate') {
        New-HardeningDirectory -Path $sessionPath | Out-Null
    }

    $script:LogFile = Join-Path -Path $logs -ChildPath "$id.log"
    $session = [pscustomobject]@{
        PSTypeName    = 'WindowsServerHardening.Session'
        Id            = $id
        Mode          = $Mode
        ComputerName  = $env:COMPUTERNAME
        Profile       = $ProfileName
        StartTime     = $now
        EndTime       = $null
        Status        = 'Running'
        ChangeCount   = 0
        RolledBack    = $false
        RolledBackAt  = $null
        ModuleVersion = $script:ModuleVersion
        OutputRoot    = $root
        SessionPath   = $sessionPath
        ChangesPath   = Join-Path -Path $sessionPath -ChildPath 'changes.jsonl'
        LogPath       = $script:LogFile
        ReportsPath   = $reports
    }

    if ($Mode -eq 'Remediate') {
        Save-HardeningSessionMetadata -Session $session
    }
    Write-HardeningLog -Message "Session $id started (mode: $Mode, profile: $ProfileName, computer: $env:COMPUTERNAME, toolkit: $script:ModuleVersion)."
    return $session
}

function Save-HardeningSessionMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Session
    )

    $metadata = [ordered]@{
        Id            = $Session.Id
        Mode          = $Session.Mode
        ComputerName  = $Session.ComputerName
        Profile       = $Session.Profile
        StartTime     = ConvertTo-HardeningIsoDate -Value $Session.StartTime
        EndTime       = ConvertTo-HardeningIsoDate -Value $Session.EndTime
        Status        = $Session.Status
        ChangeCount   = $Session.ChangeCount
        RolledBack    = $Session.RolledBack
        RolledBackAt  = ConvertTo-HardeningIsoDate -Value $Session.RolledBackAt
        ModuleVersion = $Session.ModuleVersion
    }
    $path = Join-Path -Path $Session.SessionPath -ChildPath 'session.json'
    Write-HardeningTextFile -Path $path -Content (ConvertTo-Json -InputObject $metadata -Depth 4)
}

function Add-HardeningChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Session,

        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [pscustomobject]$State
    )

    $Session.ChangeCount++
    $record = [ordered]@{
        Sequence  = $Session.ChangeCount
        ControlId = $Control.Id
        Title     = $Control.Title
        Type      = $Control.Type
        Target    = $Control.Target
        Previous  = [ordered]@{
            Exists  = $State.Exists
            Value   = $State.Value
            Display = $State.Display
            Extra   = $State.Extra
        }
        Timestamp = ConvertTo-HardeningIsoDate -Value (Get-Date)
    }

    $line = ConvertTo-Json -InputObject $record -Depth 8 -Compress
    Write-HardeningTextFile -Path $Session.ChangesPath -Content ($line + [Environment]::NewLine) -Append
    Save-HardeningSessionMetadata -Session $Session
}

function Read-HardeningChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionPath
    )

    $file = Join-Path -Path $SessionPath -ChildPath 'changes.jsonl'
    if (-not [System.IO.File]::Exists($file)) {
        return
    }

    foreach ($line in [System.IO.File]::ReadAllLines($file)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        ConvertTo-HashtableDeep -InputObject (ConvertFrom-Json -InputObject $line)
    }
}

function Read-HardeningSessionMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionPath
    )

    $file = Join-Path -Path $SessionPath -ChildPath 'session.json'
    if (-not [System.IO.File]::Exists($file)) {
        return $null
    }
    return ConvertTo-HashtableDeep -InputObject (ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($file)))
}

function Update-HardeningSessionMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionPath,

        [Parameter(Mandatory)]
        [hashtable]$Values
    )

    $metadata = Read-HardeningSessionMetadata -SessionPath $SessionPath
    if ($null -eq $metadata) {
        throw "Session metadata not found in '$SessionPath'."
    }
    foreach ($key in $Values.Keys) {
        $metadata[$key] = $Values[$key]
    }
    Write-HardeningTextFile -Path (Join-Path -Path $SessionPath -ChildPath 'session.json') -Content (ConvertTo-Json -InputObject $metadata -Depth 4)
}

function Restore-ControlState {
    # Dispatches a recorded change to Restore-<Type>State. Providers return @{ Status; Detail }.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $name = "Restore-$($Change.Type)State"
    if (-not (Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue)) {
        throw "No restore provider is implemented for control type '$($Change.Type)'."
    }
    & $name -Change $Change
}

function New-RestoreOutcome {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Restored', 'Skipped')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Detail
    )

    return @{ Status = $Status; Detail = $Detail }
}
