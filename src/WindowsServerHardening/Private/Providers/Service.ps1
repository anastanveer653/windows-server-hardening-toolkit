# Services are read through CIM (Win32_Service) rather than Get-Service: the StartType property of
# Get-Service needs .NET Framework 4.6.1, which Windows Server 2012 / 2012 R2 do not have by default.

$script:ServiceStartModeMap = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled'; Boot = 'Boot'; System = 'System' }

function Get-HardeningServiceInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $filter = "Name='{0}'" -f ($Name -replace "'", "\'")
    $service = Get-CimInstance -ClassName Win32_Service -Filter $filter -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $service) {
        return $null
    }

    $startType = [string]$service.StartMode
    if ($script:ServiceStartModeMap.Contains($startType)) {
        $startType = $script:ServiceStartModeMap[$startType]
    }
    return [pscustomobject]@{
        Name      = [string]$service.Name
        StartType = $startType
        Status    = [string]$service.State
    }
}

function Get-ServiceState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $name = $Control.Target.Name
    $service = Get-HardeningServiceInfo -Name $name
    if ($null -eq $service) {
        return New-ControlState -Applicable $false -Exists $false -Reason "Service '$name' is not installed."
    }

    $delayed = $false
    if ($service.StartType -eq 'Automatic') {
        $item = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name 'DelayedAutostart' -ErrorAction SilentlyContinue
        $delayed = ($null -ne $item -and $item.DelayedAutostart -eq 1)
    }

    $display = 'StartType={0}, Status={1}' -f $service.StartType, $service.Status
    return New-ControlState -Value $service.StartType -Display $display -Extra @{ Status = $service.Status; DelayedAutoStart = $delayed }
}

function Set-ServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $name = $Control.Target.Name
    if ($Control.Expected -eq 'Disabled') {
        $service = Get-HardeningServiceInfo -Name $name
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $name -Force -ErrorAction Stop
        }
    }
    Set-Service -Name $name -StartupType $Control.Expected -ErrorAction Stop
}

function Restore-ServiceState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $name = $Change.Target.Name
    $previous = $Change.Previous
    if ($previous.Extra.DelayedAutoStart) {
        $result = Invoke-HardeningNativeCommand -FilePath 'sc.exe' -ArgumentList @('config', $name, 'start=', 'delayed-auto')
        if ($result.ExitCode -ne 0) {
            throw "sc.exe config failed for '$name' (exit code $($result.ExitCode)): $($result.Output)"
        }
    }
    else {
        Set-Service -Name $name -StartupType $previous.Value -ErrorAction Stop
    }

    $detail = "Restored startup type of '$name' to $($previous.Value)"
    if ($previous.Extra.Status -eq 'Running') {
        Start-Service -Name $name -ErrorAction Stop
        $detail += ' and started the service'
    }
    return New-RestoreOutcome -Status Restored -Detail "$detail."
}
