function Invoke-RemoteHardeningAudit {
    # Copies this module to the remote server over an existing WinRM session, runs a read-only
    # audit there and returns the (deserialized) run object. Nothing is installed permanently:
    # the module copy lives under %ProgramData%\WindowsServerHardening\module\<version>.
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory)]
        [hashtable]$Parameters,

        [string]$ProfilePath
    )

    $sessionParameters = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $sessionParameters.Credential = $Credential
    }

    Write-HardeningLog -Message "Connecting to $ComputerName for a remote audit."
    $session = New-PSSession @sessionParameters
    try {
        $version = $script:ModuleVersion
        $remoteRoot = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            $path = Join-Path -Path $env:ProgramData -ChildPath "WindowsServerHardening\module\$using:version"
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            $path
        }

        Copy-Item -Path (Join-Path -Path $script:ModuleRoot -ChildPath '*') -Destination $remoteRoot -ToSession $session -Recurse -Force -ErrorAction Stop

        $remoteParameters = $Parameters.Clone()
        if ($ProfilePath) {
            $remoteProfile = Join-Path -Path $remoteRoot -ChildPath 'Profiles\custom-remote-profile.json'
            Copy-Item -LiteralPath $ProfilePath -Destination $remoteProfile -ToSession $session -Force -ErrorAction Stop
            $remoteParameters.ProfilePath = $remoteProfile
        }

        return Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            $auditParameters = $using:remoteParameters
            Import-Module -Name (Join-Path -Path $using:remoteRoot -ChildPath 'WindowsServerHardening.psd1') -Force -ErrorAction Stop
            Invoke-HardeningAudit @auditParameters -NoReport -WarningAction SilentlyContinue
        }
    }
    finally {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}
