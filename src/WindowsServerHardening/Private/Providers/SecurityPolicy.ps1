# Password, lockout and related local security policy is read with "secedit /export" (an INF file
# with language independent key names) instead of parsing localized "net accounts" output.

function ConvertFrom-SecurityPolicyInf {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Content
    )

    $policy = @{}
    $section = $null
    foreach ($line in $Content) {
        if ($line -match '^\s*\[(.+?)\]\s*$') {
            $section = $Matches[1]
            if (-not $policy.Contains($section)) { $policy[$section] = @{} }
            continue
        }
        if ($section -and $line -match '^\s*([^=;]+?)\s*=\s*(.*?)\s*$') {
            $policy[$section][$Matches[1]] = $Matches[2]
        }
    }
    return $policy
}

function Get-SecurityPolicySnapshot {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $file = New-HardeningTempPath -Extension '.inf'
    try {
        $result = Invoke-HardeningNativeCommand -FilePath 'secedit.exe' -ArgumentList @('/export', '/cfg', $file, '/areas', 'SECURITYPOLICY', '/quiet')
        if ($result.ExitCode -ne 0 -or -not [System.IO.File]::Exists($file)) {
            throw "secedit /export failed (exit code $($result.ExitCode)). Reading security policy requires administrator rights."
        }
        return ConvertFrom-SecurityPolicyInf -Content ([System.IO.File]::ReadAllLines($file))
    }
    finally {
        Remove-HardeningTempPath -Path $file
    }
}

function Get-SecurityPolicyState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    if (-not $Context.Cache.Contains('SecurityPolicy')) {
        try {
            $Context.Cache['SecurityPolicy'] = Get-SecurityPolicySnapshot
        }
        catch {
            # Remember the failure so the remaining policy controls do not run secedit again.
            $Context.Cache['SecurityPolicy'] = $_.Exception.Message
        }
    }

    $section = Get-SecurityPolicySection -Target $Control.Target
    $key = $Control.Target.Key
    $policy = $Context.Cache['SecurityPolicy']
    if ($policy -is [string]) {
        throw $policy
    }
    if (-not $policy.Contains($section) -or -not $policy[$section].Contains($key)) {
        return New-ControlState -Value $null -Exists $false -Display 'Not defined'
    }

    $raw = [string]$policy[$section][$key]
    $number = 0L
    $value = if ([long]::TryParse($raw, [ref]$number)) { $number } else { $raw.Trim('"') }
    return New-ControlState -Value $value
}

function Set-SecurityPolicyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    Set-SecurityPolicyValue -Section (Get-SecurityPolicySection -Target $Control.Target) -Key $Control.Target.Key -Value $Control.Expected
    $Context.Cache.Remove('SecurityPolicy')
}

function Restore-SecurityPolicyState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $key = $Change.Target.Key
    if (-not $Change.Previous.Exists) {
        return New-RestoreOutcome -Status Skipped -Detail "Security policy $key was not defined before hardening; secedit cannot undefine a setting, so it was left unchanged."
    }
    Set-SecurityPolicyValue -Section (Get-SecurityPolicySection -Target $Change.Target) -Key $key -Value $Change.Previous.Value
    return New-RestoreOutcome -Status Restored -Detail "Restored security policy $key = $($Change.Previous.Value)."
}

function Get-SecurityPolicySection {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Target
    )

    if ($Target.Contains('Section') -and $Target.Section) {
        return [string]$Target.Section
    }
    return 'System Access'
}

function Set-SecurityPolicyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Section,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [object]$Value
    )

    $inf = New-HardeningTempPath -Extension '.inf'
    $database = New-HardeningTempPath -Extension '.sdb'
    try {
        $content = @(
            '[Unicode]'
            'Unicode=yes'
            "[$Section]"
            ('{0} = {1}' -f $Key, $Value)
            '[Version]'
            'signature="$CHICAGO$"'
            'Revision=1'
        ) -join "`r`n"
        [System.IO.File]::WriteAllText($inf, $content, [System.Text.Encoding]::Unicode)

        $result = Invoke-HardeningNativeCommand -FilePath 'secedit.exe' -ArgumentList @('/configure', '/db', $database, '/cfg', $inf, '/areas', 'SECURITYPOLICY', '/quiet')
        if ($result.ExitCode -ne 0) {
            throw "secedit /configure failed while setting $Key = $Value (exit code $($result.ExitCode)). $($result.Output)".Trim()
        }
    }
    finally {
        Remove-HardeningTempPath -Path @($inf, $database, [System.IO.Path]::ChangeExtension($database, '.jfm'))
    }
}
