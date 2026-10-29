BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

InModuleScope WindowsServerHardening {
    Describe 'Test-HardeningValue' {
        BeforeAll {
            function New-CompareControl {
                param($Operator, $Expected, $Minimum = $null, $Allowed = @())
                [pscustomobject]@{ Id = 'TST-001'; Operator = $Operator; Expected = $Expected; Minimum = $Minimum; Maximum = $null; Allowed = $Allowed }
            }
        }

        It '<Operator> <Expected> with actual <Actual> is <Result>' -TestCases @(
            @{ Operator = 'Equals'; Expected = 1; Actual = 1; Result = $true }
            @{ Operator = 'Equals'; Expected = 1; Actual = 0; Result = $false }
            @{ Operator = 'Equals'; Expected = 1; Actual = '1'; Result = $true }
            @{ Operator = 'Equals'; Expected = 1; Actual = $null; Result = $false }
            @{ Operator = 'Equals'; Expected = 1; Actual = 'abc'; Result = $false }
            @{ Operator = 'Equals'; Expected = $false; Actual = $false; Result = $true }
            @{ Operator = 'Equals'; Expected = $false; Actual = 'False'; Result = $true }
            @{ Operator = 'Equals'; Expected = $true; Actual = 'False'; Result = $false }
            @{ Operator = 'Equals'; Expected = 'Block'; Actual = 'block'; Result = $true }
            @{ Operator = 'Equals'; Expected = 'Block'; Actual = 'Allow'; Result = $false }
            @{ Operator = 'GreaterOrEqual'; Expected = 14; Actual = 14; Result = $true }
            @{ Operator = 'GreaterOrEqual'; Expected = 14; Actual = 20; Result = $true }
            @{ Operator = 'GreaterOrEqual'; Expected = 14; Actual = 8; Result = $false }
            @{ Operator = 'GreaterOrEqual'; Expected = 16384; Actual = '4096'; Result = $false }
            @{ Operator = 'LessOrEqual'; Expected = 35; Actual = 12; Result = $true }
            @{ Operator = 'LessOrEqual'; Expected = 35; Actual = 90; Result = $false }
        ) {
            $control = New-CompareControl -Operator $Operator -Expected $Expected
            Test-HardeningValue -Actual $Actual -Control $control | Should -Be $Result
        }

        It 'Range 1..<Expected> with actual <Actual> is <Result>' -TestCases @(
            @{ Expected = 5; Actual = 0; Result = $false }
            @{ Expected = 5; Actual = 1; Result = $true }
            @{ Expected = 5; Actual = 5; Result = $true }
            @{ Expected = 5; Actual = 6; Result = $false }
            @{ Expected = 365; Actual = -1; Result = $false }
        ) {
            $control = New-CompareControl -Operator 'Range' -Expected $Expected -Minimum 1
            Test-HardeningValue -Actual $Actual -Control $control | Should -Be $Result
        }

        It 'In (1, 2) with actual <Actual> is <Result>' -TestCases @(
            @{ Actual = 1; Result = $true }
            @{ Actual = 2; Result = $true }
            @{ Actual = 5; Result = $false }
        ) {
            $control = New-CompareControl -Operator 'In' -Expected 2 -Allowed @(1, 2)
            Test-HardeningValue -Actual $Actual -Control $control | Should -Be $Result
        }

        It 'requires every entry of a dictionary to comply' {
            $control = New-CompareControl -Operator 'Equals' -Expected 'True'
            Test-HardeningValue -Actual ([ordered]@{ Domain = 'True'; Private = 'True'; Public = 'True' }) -Control $control | Should -BeTrue
            Test-HardeningValue -Actual ([ordered]@{ Domain = 'True'; Private = 'False'; Public = 'True' }) -Control $control | Should -BeFalse
        }

        It 'treats an empty dictionary as non-compliant' {
            $control = New-CompareControl -Operator 'Equals' -Expected 'True'
            Test-HardeningValue -Actual ([ordered]@{}) -Control $control | Should -BeFalse
        }

        It 'throws for an unsupported operator' {
            $control = New-CompareControl -Operator 'Matches' -Expected 1
            { Test-HardeningValue -Actual 1 -Control $control } | Should -Throw '*Unsupported operator*'
        }
    }

    Describe 'ConvertTo-NativeArgument' {
        It 'quotes <Value> as <Quoted>' -TestCases @(
            @{ Value = 'simple'; Quoted = 'simple' }
            @{ Value = 'with space'; Quoted = '"with space"' }
            @{ Value = 'say "hi"'; Quoted = '"say \"hi\""' }
            @{ Value = 'C:\dir with space\'; Quoted = '"C:\dir with space\\"' }
            @{ Value = ''; Quoted = '""' }
        ) {
            ConvertTo-NativeArgument -Value $Value | Should -BeExactly $Quoted
        }
    }

    Describe 'Format-HardeningValue' {
        It 'formats <Description>' -TestCases @(
            @{ Description = 'null'; Value = $null; Text = 'Not configured' }
            @{ Description = 'empty string'; Value = ''; Text = '(empty)' }
            @{ Description = 'numbers'; Value = 5; Text = '5' }
            @{ Description = 'arrays'; Value = @(1, 3); Text = '1, 3' }
            @{ Description = 'dictionaries'; Value = [ordered]@{ Domain = 'True'; Public = 'False' }; Text = 'Domain=True; Public=False' }
        ) {
            Format-HardeningValue -Value $Value | Should -Be $Text
        }
    }
}
