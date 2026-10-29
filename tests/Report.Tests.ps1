BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

InModuleScope WindowsServerHardening {
    Describe 'Report export' {
        BeforeAll {
            . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

            $pass = New-HardeningResult -Control (New-TestControl -Override @{ Id = 'TST-001'; Severity = 'Critical'; References = @{ Benchmark = 'CIS: test'; MitreAttack = @('T1003.001') } })
            $pass.Status = 'Pass'
            $pass.Actual = '1'

            $hostile = New-HardeningResult -Control (New-TestControl -Override @{ Id = 'TST-002'; Title = 'Hostile <b>title</b> & co' })
            $hostile.Status = 'Fail'
            $hostile.Actual = '</script><script>alert(1)</script>'
            $hostile.Detail = "Quote ' and `"double`""

            $run = New-TestRun -Results @($pass, $hostile)
            $files = @(Export-HardeningReport -Run $run -Format Html, Json, Csv -Path (Join-Path $TestDrive 'reports'))
            $html = Get-Content -Path ($files | Where-Object { $_.Extension -eq '.html' }).FullName -Raw
            $json = Get-Content -Path ($files | Where-Object { $_.Extension -eq '.json' }).FullName -Raw | ConvertFrom-Json
        }

        It 'writes one file per format with a predictable name' {
            $files.Count | Should -Be 3
            @($files | ForEach-Object { $_.Name }) | Should -Contain 'hardening-SRV-TEST-01-audit-20261029-120000-abc123.html'
        }

        It 'writes a versioned JSON document with summary and results' {
            $json.schemaVersion | Should -Be '1.0'
            $json.system.computerName | Should -Be 'SRV-TEST-01'
            $json.summary.fail | Should -Be 1
            $json.summary.openBySeverity.high | Should -Be 1
            @($json.results).Count | Should -Be 2
            @($json.results[0].mitreAttack) | Should -Be @('T1003.001')
        }

        It 'keeps hostile values out of the HTML markup' {
            $html | Should -Not -Match '</script><script>alert'
            $html | Should -Not -Match '<b>title</b>'
            $html | Should -Match '\\u003c/script\\u003e'
        }

        It 'embeds JSON in the HTML that round-trips to the original values' {
            $start = $html.IndexOf('<script id="report-data" type="application/json">')
            $start | Should -BeGreaterThan 0
            $start += '<script id="report-data" type="application/json">'.Length
            $end = $html.IndexOf('</script>', $start)
            $embedded = $html.Substring($start, $end - $start) | ConvertFrom-Json
            ($embedded.results | Where-Object { $_.id -eq 'TST-002' }).actual | Should -Be '</script><script>alert(1)</script>'
            ($embedded.results | Where-Object { $_.id -eq 'TST-002' }).title | Should -Be 'Hostile <b>title</b> & co'
        }

        It 'contains no unreplaced template placeholders or external resources' {
            $html | Should -Not -Match '\{\{(TITLE|DATA)\}\}'
            $html | Should -Not -Match '<(script|link)[^>]+(src|href)="https?://'
        }

        It 'writes a CSV with one row per control' {
            $rows = @(Import-Csv -Path ($files | Where-Object { $_.Extension -eq '.csv' }).FullName)
            $rows.Count | Should -Be 2
            $rows[1].Actual | Should -Be '</script><script>alert(1)</script>'
            $rows[0].MitreAttack | Should -Be 'T1003.001'
        }
    }
}
