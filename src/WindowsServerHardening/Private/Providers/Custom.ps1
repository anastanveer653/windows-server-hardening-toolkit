# Audit-only checks that do not map to a single setting. Each returns a control state whose Value is
# evaluated with the control's normal Operator/Expected, so thresholds stay configurable in profiles.

function Get-CustomState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    switch ($Control.Target.Check) {
        'PendingUpdates'   { return Get-PendingUpdateState -Context $Context }
        'UpdateRecency'    { return Get-UpdateRecencyState }
        'DepPolicy'        { return Get-DepPolicyState }
        'CredentialGuard'  { return Get-CredentialGuardState }
        'RdpFirewallScope' { return Get-RdpFirewallScopeState }
        default            { throw "Unknown custom check '$($Control.Target.Check)' in control $($Control.Id)." }
    }
}

function Set-CustomState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    throw "Control $($Control.Id) is audit-only and cannot be remediated automatically."
}

function Get-PendingUpdateState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    if ($Context.Parameters.Contains('SkipPendingUpdateScan') -and $Context.Parameters.SkipPendingUpdateScan) {
        return New-ControlState -Applicable $false -Reason 'Pending update scan disabled by the profile parameter SkipPendingUpdateScan.'
    }

    $session = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $titles = @(foreach ($update in $search.Updates) { [string]$update.Title })

    if ($titles.Count -eq 0) {
        return New-ControlState -Value 0 -Display 'No pending software updates'
    }
    $preview = ($titles | Select-Object -First 5) -join '; '
    if ($titles.Count -gt 5) { $preview += '; ...' }
    return New-ControlState -Value $titles.Count -Display ('{0} pending update(s): {1}' -f $titles.Count, $preview)
}

function Get-UpdateRecencyState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $latest = $null
    foreach ($hotfix in @(Get-HotFix -ErrorAction Stop)) {
        $installedOn = $null
        try { $installedOn = $hotfix.InstalledOn } catch { $installedOn = $null }
        if ($installedOn -is [datetime] -and ($null -eq $latest -or $installedOn -gt $latest.Date)) {
            $latest = [pscustomobject]@{ Date = $installedOn; Id = $hotfix.HotFixID }
        }
    }

    if ($null -eq $latest) {
        return New-ControlState -Value $null -Exists $false -Display 'No installed updates with an install date were found'
    }
    $days = [int][Math]::Floor(((Get-Date) - $latest.Date).TotalDays)
    return New-ControlState -Value $days -Display ('{0} day(s) since the last update was installed ({1} on {2:yyyy-MM-dd})' -f $days, $latest.Id, $latest.Date)
}

function Get-DepPolicyState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $policy = [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).DataExecutionPrevention_SupportPolicy
    $name = switch ($policy) {
        0       { 'AlwaysOff' }
        1       { 'AlwaysOn' }
        2       { 'OptIn' }
        3       { 'OptOut' }
        default { 'Unknown' }
    }
    return New-ControlState -Value $policy -Display "$name ($policy)"
}

function Get-CredentialGuardState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    }
    catch {
        return New-ControlState -Value 'NotSupported' -Display 'Device Guard information is not available on this system'
    }

    $running = @($deviceGuard.SecurityServicesRunning) -contains 1
    $vbs = switch ([int]$deviceGuard.VirtualizationBasedSecurityStatus) {
        0       { 'not enabled' }
        1       { 'enabled but not running' }
        2       { 'running' }
        default { 'unknown' }
    }
    $value = if ($running) { 'Running' } else { 'NotRunning' }
    return New-ControlState -Value $value -Display ('Credential Guard {0}; virtualization-based security {1}' -f $value, $vbs)
}

function Get-RdpFirewallScopeState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $terminalServer = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
    if ($null -ne $terminalServer -and $terminalServer.fDenyTSConnections -eq 1) {
        return New-ControlState -Applicable $false -Reason 'Remote Desktop connections are disabled on this computer.'
    }

    $port = 3389
    $rdpTcp = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -ErrorAction SilentlyContinue
    if ($null -ne $rdpTcp -and $rdpTcp.PortNumber) { $port = [int]$rdpTcp.PortNumber }

    $unrestricted = [System.Collections.Generic.List[string]]::new()
    $filters = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { [string]$_.Protocol -eq 'TCP' -and @($_.LocalPort) -contains [string]$port })
    foreach ($filter in $filters) {
        $rule = $filter | Get-NetFirewallRule -ErrorAction SilentlyContinue
        if (-not $rule -or [string]$rule.Enabled -ne 'True' -or [string]$rule.Direction -ne 'Inbound' -or [string]$rule.Action -ne 'Allow') {
            continue
        }
        $addresses = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        if ($null -ne $addresses -and @($addresses.RemoteAddress) -contains 'Any') {
            $unrestricted.Add([string]$rule.DisplayName)
        }
    }

    if ($unrestricted.Count -eq 0) {
        return New-ControlState -Value 0 -Display "All enabled inbound rules for TCP $port are limited to specific remote addresses"
    }
    return New-ControlState -Value $unrestricted.Count -Display ('{0} rule(s) allow TCP {1} from any address: {2}' -f $unrestricted.Count, $port, ($unrestricted -join '; '))
}
