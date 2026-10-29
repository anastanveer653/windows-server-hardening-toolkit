BeforeDiscovery {
    $root = Split-Path -Path $PSScriptRoot -Parent
    $publicFunctions = @(Get-ChildItem -Path (Join-Path $root 'src\WindowsServerHardening\Public') -Filter '*.ps1' | ForEach-Object { $_.BaseName })

    $textFiles = @(
        Get-ChildItem -Path (Join-Path $root 'src'), (Join-Path $root 'tools'), (Join-Path $root 'tests') -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1', '*.ps1xml', '*.json', '*.html', '*.csv', '*.inf'
        Get-Item -Path (Join-Path $root 'Harden-WindowsServer.ps1'), (Join-Path $root 'build.ps1')
    ) | ForEach-Object { @{ Name = $_.FullName.Substring($root.Length + 1); FullName = $_.FullName } }

    $scriptFiles = @($textFiles | Where-Object { $_.Name -match '\.ps(m|d)?1$' })
}

BeforeAll {
    $root = Split-Path -Path $PSScriptRoot -Parent
    $manifestPath = Join-Path $root 'src\WindowsServerHardening\WindowsServerHardening.psd1'
    Import-Module -Name $manifestPath -Force
}

Describe 'Module manifest' {
    It 'is a valid module manifest' {
        { Test-ModuleManifest -Path $manifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports exactly the functions in the Public folder' {
        $exported = @((Get-Module -Name WindowsServerHardening).ExportedFunctions.Keys | Sort-Object)
        $expected = @(Get-ChildItem -Path (Join-Path $root 'src\WindowsServerHardening\Public') -Filter '*.ps1' | ForEach-Object { $_.BaseName } | Sort-Object)
        $exported | Should -Be $expected
    }

    It 'lists every exported function in FunctionsToExport' {
        $manifest = Import-PowerShellDataFile -Path $manifestPath
        $public = @(Get-ChildItem -Path (Join-Path $root 'src\WindowsServerHardening\Public') -Filter '*.ps1' | ForEach-Object { $_.BaseName } | Sort-Object)
        @($manifest.FunctionsToExport | Sort-Object) | Should -Be $public
    }

    It 'has a changelog entry for the module version' {
        $version = (Import-PowerShellDataFile -Path $manifestPath).ModuleVersion
        Get-Content -Path (Join-Path $root 'CHANGELOG.md') -Raw | Should -Match ([regex]::Escape("[$version]"))
    }
}

Describe 'Help for <_>' -ForEach $publicFunctions {
    BeforeAll {
        $functionName = $_
        $help = Get-Help -Name $functionName -Full
        $command = Get-Command -Name $functionName
        $commonParameters = @([System.Management.Automation.PSCmdlet]::CommonParameters) + @([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)
    }

    It 'has a synopsis' {
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis.Trim() | Should -Not -Be $functionName
    }

    It 'has a description' {
        ($help.Description | Out-String).Trim() | Should -Not -BeNullOrEmpty
    }

    It 'has at least one example' {
        @($help.Examples.Example).Count | Should -BeGreaterThan 0
    }

    It 'documents every parameter' {
        $undocumented = foreach ($name in $command.Parameters.Keys) {
            if ($commonParameters -contains $name) { continue }
            $parameterHelp = $help.Parameters.Parameter | Where-Object { $_.Name -eq $name }
            if (-not $parameterHelp -or -not ($parameterHelp.Description | Out-String).Trim()) { $name }
        }
        $undocumented | Should -BeNullOrEmpty
    }
}

Describe 'Source file hygiene' {
    It '<Name> contains only ASCII characters' -ForEach $textFiles {
        # Windows PowerShell 5.1 reads BOM-less files as ANSI; non-ASCII characters (em dashes,
        # emoji, box drawing) then corrupt string literals. This is what broke v1.
        $bytes = [System.IO.File]::ReadAllBytes($FullName)
        $offending = @($bytes | Where-Object { $_ -gt 127 }).Count
        $offending | Should -Be 0
    }

    It '<Name> parses without errors' -ForEach $scriptFiles {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($FullName, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
    }
}
