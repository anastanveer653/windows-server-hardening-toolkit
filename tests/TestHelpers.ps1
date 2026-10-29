# Shared helpers for the Pester suites. Dot-source inside InModuleScope so the helpers can call
# private module functions.

function New-TestControl {
    param(
        [hashtable]$Override = @{}
    )

    $definition = @{
        Id        = 'TST-001'
        Title     = 'Test control'
        Category  = 'Test'
        Severity  = 'High'
        Type      = 'Registry'
        Target    = @{ Path = 'TestRegistry:\Hardening'; Name = 'Value'; ValueType = 'DWord' }
        Expected  = 1
        Rationale = 'Used by unit tests.'
    }
    foreach ($key in $Override.Keys) {
        $definition[$key] = $Override[$key]
    }
    return ConvertTo-HardeningControl -Definition $definition -Source 'test'
}

function New-TestCmdlet {
    param(
        [bool]$Allow = $true
    )

    $cmdlet = [pscustomobject]@{ Allow = $Allow; Calls = 0 }
    $cmdlet | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value {
        param($Target, $Action)
        $this.Calls++
        return $this.Allow
    }
    return $cmdlet
}

function New-TestSystemInfo {
    param(
        [string]$Role = 'MemberServer'
    )

    return [pscustomobject]@{
        ComputerName      = 'SRV-TEST-01'
        Domain            = 'corp.example.com'
        PartOfDomain      = $true
        Role              = $Role
        OSName            = 'Microsoft Windows Server 2022 Datacenter'
        OSVersion         = '10.0.20348'
        OSBuild           = '20348'
        IsServer          = $true
        LastBootTime      = (Get-Date).AddDays(-3)
        PowerShellVersion = '5.1'
        IsElevated        = $true
    }
}

function New-TestContext {
    param(
        [ValidateSet('Audit', 'Remediate')]
        [string]$Mode = 'Audit',

        [object]$Cmdlet = (New-TestCmdlet),

        [object]$Session = [pscustomobject]@{ Id = 'test-session' },

        [string]$Role = 'MemberServer'
    )

    return @{
        Mode       = $Mode
        Parameters = [ordered]@{}
        System     = New-TestSystemInfo -Role $Role
        Session    = $Session
        Cmdlet     = $Cmdlet
        Cache      = @{}
    }
}

function New-TestRun {
    param(
        [object[]]$Results
    )

    $start = Get-Date
    return [pscustomobject]@{
        SessionId       = '20261029-120000-abc123'
        Mode            = 'Audit'
        Profile         = 'MemberServer'
        ComputerName    = 'SRV-TEST-01'
        Score           = $null
        Grade           = $null
        StartTime       = $start
        EndTime         = $start.AddSeconds(4)
        DurationSeconds = 4
        ModuleVersion   = '2.0.0'
        System          = New-TestSystemInfo
        Summary         = Get-HardeningSummary -Results $Results
        Results         = $Results
        LogPath         = $null
        Reports         = @()
    }
}
