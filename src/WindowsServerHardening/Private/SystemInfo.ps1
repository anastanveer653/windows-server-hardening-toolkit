function Get-HardeningSystemInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-computersystem (DomainRole)
    $role = switch ([int]$computer.DomainRole) {
        0       { 'Workstation' }
        1       { 'Workstation' }
        2       { 'StandaloneServer' }
        3       { 'MemberServer' }
        4       { 'DomainController' }
        5       { 'DomainController' }
        default { 'Workstation' }
    }

    return [pscustomobject]@{
        PSTypeName        = 'WindowsServerHardening.SystemInfo'
        ComputerName      = $env:COMPUTERNAME
        Domain            = [string]$computer.Domain
        PartOfDomain      = [bool]$computer.PartOfDomain
        Role              = $role
        OSName            = [string]$os.Caption
        OSVersion         = [string]$os.Version
        OSBuild           = [string]$os.BuildNumber
        IsServer          = ([int]$os.ProductType -ne 1)
        LastBootTime      = $os.LastBootUpTime
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsElevated        = Test-HardeningElevation
    }
}
