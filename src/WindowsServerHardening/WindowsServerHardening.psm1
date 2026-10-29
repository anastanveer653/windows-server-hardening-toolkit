Set-StrictMode -Version Latest

$script:ModuleRoot    = $PSScriptRoot
$script:ControlsPath  = Join-Path -Path $PSScriptRoot -ChildPath 'Controls'
$script:ProfilesPath  = Join-Path -Path $PSScriptRoot -ChildPath 'Profiles'
$script:TemplatePath  = Join-Path -Path $PSScriptRoot -ChildPath 'Private\Reporting\ReportTemplate.html'
$script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsServerHardening.psd1')).ModuleVersion
$script:ProjectUri    = 'https://github.com/anastanveer653/windows-server-hardening-toolkit'
$script:LogFile       = $null
$script:Catalog       = $null

$private = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Private') -Filter '*.ps1' -Recurse)
$public  = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Public') -Filter '*.ps1')

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to import '$($file.FullName)': $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function $public.BaseName
