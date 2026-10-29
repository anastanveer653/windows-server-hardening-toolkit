# Shared helpers. Internal file IO deliberately uses .NET APIs instead of cmdlets so that
# -WhatIf / -Confirm on the public commands never suppress or prompt for logs, state and reports.

function Write-HardeningLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        # Write to the log file and the verbose stream only (used for per-control errors that are
        # already reported in the results).
        [switch]$NoConsole
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpperInvariant(), $Message
    if ($script:LogFile) {
        try {
            [System.IO.File]::AppendAllText($script:LogFile, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        }
        catch {
            Write-Verbose "Unable to write to log file '$($script:LogFile)': $($_.Exception.Message)"
        }
    }

    if ($Level -eq 'Info' -or $NoConsole) {
        Write-Verbose $Message
    }
    else {
        Write-Warning $Message
    }
}

function Write-HardeningTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content,

        [switch]$Append
    )

    $encoding = [System.Text.UTF8Encoding]::new($false)
    if ($Append) {
        [System.IO.File]::AppendAllText($Path, $Content, $encoding)
    }
    else {
        [System.IO.File]::WriteAllText($Path, $Content, $encoding)
    }
}

function New-HardeningDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    [void][System.IO.Directory]::CreateDirectory($Path)
    return $Path
}

function New-HardeningTempPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Extension
    )

    $name = 'wsh-{0}{1}' -f [guid]::NewGuid().ToString('N'), $Extension
    return (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $name)
}

function Remove-HardeningTempPath {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Path
    )

    foreach ($item in $Path) {
        if ($item -and [System.IO.File]::Exists($item)) {
            try {
                [System.IO.File]::Delete($item)
            }
            catch {
                Write-Verbose "Unable to delete temporary file '$item': $($_.Exception.Message)"
            }
        }
    }
}

function Resolve-HardeningOutputRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Path
    )

    if (-not $Path) {
        $Path = Join-Path -Path $env:ProgramData -ChildPath 'WindowsServerHardening'
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    New-HardeningDirectory -Path $fullPath | Out-Null
    return $fullPath
}

function Test-HardeningElevation {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-HardeningElevation {
    [CmdletBinding()]
    param()

    if (-not (Test-HardeningElevation)) {
        throw 'This operation changes system configuration and requires an elevated PowerShell session (Run as Administrator).'
    }
}

function Test-HardeningIdMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Pattern
    )

    foreach ($item in @($Pattern)) {
        if ($item -and $Id -like $item) {
            return $true
        }
    }
    return $false
}

function ConvertTo-HashtableDeep {
    # Converts ConvertFrom-Json output (PSCustomObject graphs) into ordered hashtables and arrays.
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject
    )

    process {
        if ($null -eq $InputObject) {
            return $null
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $hash = [ordered]@{}
            foreach ($key in $InputObject.Keys) {
                $hash[$key] = ConvertTo-HashtableDeep -InputObject $InputObject[$key]
            }
            return $hash
        }

        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $hash = [ordered]@{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertTo-HashtableDeep -InputObject $property.Value
            }
            return $hash
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $items = foreach ($item in $InputObject) { ConvertTo-HashtableDeep -InputObject $item }
            return , @($items)
        }

        return $InputObject
    }
}

function Format-HardeningValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'Not configured'
    }

    if ($Value -is [string] -and $Value.Length -eq 0) {
        return '(empty)'
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($key in $Value.Keys) { '{0}={1}' -f $key, (Format-HardeningValue -Value $Value[$key]) }
        return (@($parts) -join '; ')
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return ((@($Value) | ForEach-Object { [string]$_ }) -join ', ')
    }

    return [string]$Value
}

function ConvertTo-HardeningIsoDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [datetime]) {
        return $Value.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}

function ConvertTo-NativeArgument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value -eq '') {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-HardeningNativeCommand {
    # Runs a console tool (auditpol, secedit, ...) with captured output and exit code. Using
    # System.Diagnostics.Process avoids the Windows PowerShell 5.1 behaviour of turning native
    # stderr output into terminating errors when $ErrorActionPreference is 'Stop'.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @()
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (@($ArgumentList | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($startInfo)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output   = $stdout.Result.Trim()
            Error    = $stderr.Trim()
        }
    }
    finally {
        $process.Dispose()
    }
}
