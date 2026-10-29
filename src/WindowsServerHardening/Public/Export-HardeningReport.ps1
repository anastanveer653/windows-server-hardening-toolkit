function Export-HardeningReport {
    <#
    .SYNOPSIS
        Writes HTML, JSON and/or CSV reports for a hardening run.

    .DESCRIPTION
        Converts a run object returned by Invoke-HardeningAudit or Invoke-HardeningRemediation into
        report files. The HTML report is a single self-contained file (no external resources) with
        the security score, open findings by severity, compliance per category and a filterable
        list of all controls. The JSON report uses a stable, versioned schema suitable for SIEM or
        CMDB ingestion; the CSV report has one row per control.

    .PARAMETER Run
        The run object to export. Accepts pipeline input.

    .PARAMETER Format
        Report formats to write: Html, Json, Csv. Defaults to Html and Json.

    .PARAMETER Path
        Destination folder. Defaults to %ProgramData%\WindowsServerHardening\reports.

    .EXAMPLE
        Invoke-HardeningAudit -NoReport | Export-HardeningReport -Format Html, Csv -Path C:\Reports

        Audits the server and writes HTML and CSV reports to C:\Reports.

    .OUTPUTS
        System.IO.FileInfo
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject]$Run,

        [ValidateSet('Html', 'Json', 'Csv')]
        [string[]]$Format = @('Html', 'Json'),

        [string]$Path
    )

    begin {
        $destination = if ($Path) { $Path } else { Join-Path -Path (Resolve-HardeningOutputRoot) -ChildPath 'reports' }
        $destination = New-HardeningDirectory -Path ([System.IO.Path]::GetFullPath($destination))
    }

    process {
        $baseName = 'hardening-{0}-{1}-{2}' -f $Run.ComputerName, ([string]$Run.Mode).ToLowerInvariant(), $Run.SessionId
        $basePath = Join-Path -Path $destination -ChildPath $baseName
        $document = ConvertTo-HardeningReportDocument -Run $Run

        foreach ($item in @($Format | Select-Object -Unique)) {
            switch ($item) {
                'Json' {
                    $file = "$basePath.json"
                    Write-HardeningTextFile -Path $file -Content (ConvertTo-Json -InputObject $document -Depth 8)
                }
                'Csv' {
                    $file = "$basePath.csv"
                    Write-HardeningTextFile -Path $file -Content (ConvertTo-HardeningCsv -Run $Run)
                }
                'Html' {
                    $file = "$basePath.html"
                    Write-HardeningTextFile -Path $file -Content (ConvertTo-HardeningHtml -Document $document)
                }
            }
            Write-HardeningLog -Message "Report written: $file"
            Get-Item -LiteralPath $file
        }
    }
}
