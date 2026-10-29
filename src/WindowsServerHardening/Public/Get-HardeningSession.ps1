function Get-HardeningSession {
    <#
    .SYNOPSIS
        Lists remediation sessions that can be inspected or rolled back.

    .DESCRIPTION
        Returns the remediation sessions stored under the output folder, newest first, with their
        status, number of recorded changes and rollback state.

    .PARAMETER Id
        Return only sessions whose ID matches this value. Wildcards are supported.

    .PARAMETER OutputPath
        Root folder that contains the sessions. Defaults to %ProgramData%\WindowsServerHardening.

    .EXAMPLE
        Get-HardeningSession

        Lists all remediation sessions on this server.

    .EXAMPLE
        Get-HardeningSession | Where-Object { -not $_.RolledBack -and $_.ChangeCount -gt 0 }

        Lists sessions with changes that have not been rolled back yet.

    .OUTPUTS
        WindowsServerHardening.SessionInfo
    #>
    [CmdletBinding()]
    [OutputType('WindowsServerHardening.SessionInfo')]
    param(
        [string]$Id,

        [string]$OutputPath
    )

    $root = Resolve-HardeningOutputRoot -Path $OutputPath
    $directory = Join-Path -Path $root -ChildPath 'sessions'
    if (-not [System.IO.Directory]::Exists($directory)) {
        return
    }

    foreach ($folder in @(Get-ChildItem -LiteralPath $directory -Directory | Sort-Object -Property Name -Descending)) {
        if ($Id -and $folder.Name -notlike $Id) { continue }
        $metadata = Read-HardeningSessionMetadata -SessionPath $folder.FullName
        if ($null -eq $metadata) { continue }

        [pscustomobject]@{
            PSTypeName    = 'WindowsServerHardening.SessionInfo'
            Id            = $metadata.Id
            Mode          = $metadata.Mode
            ComputerName  = $metadata.ComputerName
            Profile       = $metadata.Profile
            StartTime     = if ($metadata.StartTime) { [datetime]$metadata.StartTime } else { $null }
            EndTime       = if ($metadata.EndTime) { [datetime]$metadata.EndTime } else { $null }
            Status        = $metadata.Status
            ChangeCount   = [int]$metadata.ChangeCount
            RolledBack    = [bool]$metadata.RolledBack
            RolledBackAt  = if ($metadata.RolledBackAt) { [datetime]$metadata.RolledBackAt } else { $null }
            ModuleVersion = $metadata.ModuleVersion
            Path          = $folder.FullName
        }
    }
}
