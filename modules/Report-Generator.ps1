function New-HardeningReport {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [PSCustomObject]$SystemInfo,
        [string]$OutputPath,
        [switch]$ReportOnly
    )

    $passCount   = ($Results | Where-Object { $_.Status -eq "PASS" }).Count
    $fixedCount  = ($Results | Where-Object { $_.Status -eq "FIXED" }).Count
    $failCount   = ($Results | Where-Object { $_.Status -eq "FAIL" }).Count
    $totalCount  = $Results.Count
    $score       = if ($totalCount -gt 0) { [math]::Round((($passCount + $fixedCount) / $totalCount) * 100) } else { 0 }
    $modeLabel   = if ($ReportOnly) { "AUDIT ONLY" } else { "HARDENING APPLIED" }

    $scoreColor = switch {
        { $score -ge 90 } { "#27ae60" }
        { $score -ge 70 } { "#f39c12" }
        default           { "#e74c3c" }
    }

    # Build rows per category
    $categories = $Results | Group-Object Category

    $tableRows = foreach ($cat in $categories) {
        $catHeader = "<tr><td colspan='5' style='background:#1e272e;color:#ecf0f1;font-weight:bold;padding:10px 14px;font-size:13px;letter-spacing:1px;'>📁 $($cat.Name)</td></tr>"
        $catHeader

        foreach ($r in $cat.Group) {
            $statusHtml = switch ($r.Status) {
                "PASS"    { "<span style='color:#27ae60;font-weight:bold;'>✅ PASS</span>" }
                "FIXED"   { "<span style='color:#f39c12;font-weight:bold;'>🔧 FIXED</span>" }
                "FAIL"    { "<span style='color:#e74c3c;font-weight:bold;'>❌ FAIL</span>" }
                "SKIPPED" { "<span style='color:#95a5a6;font-weight:bold;'>⏭ SKIP</span>" }
            }
            $sevColor = switch ($r.Severity) {
                "Critical" { "#e74c3c" }
                "High"     { "#e67e22" }
                "Medium"   { "#f1c40f" }
                "Low"      { "#27ae60" }
                default    { "#95a5a6" }
            }
            "<tr>
                <td style='padding:10px 14px;'>$($r.Check)</td>
                <td>$statusHtml</td>
                <td><span style='color:$sevColor;font-weight:bold;font-size:12px;'>$($r.Severity)</span></td>
                <td style='font-size:12px;color:#7f8c8d;'>$($r.CISControl)</td>
                <td style='font-size:12px;'>$($r.Details)</td>
            </tr>"
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Windows Server Hardening Report — $($SystemInfo.ComputerName)</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #2c3e50; }
  .header { background: linear-gradient(135deg, #1a252f, #2c3e50); color: #ecf0f1; padding: 40px; }
  .header h1 { font-size: 26px; margin-bottom: 6px; }
  .header p  { color: #95a5a6; font-size: 14px; }
  .badge { display:inline-block; padding:4px 12px; border-radius:20px; font-size:12px; font-weight:bold; margin-top:10px; }
  .badge-audit    { background:#3498db; color:#fff; }
  .badge-hardened { background:#27ae60; color:#fff; }
  .summary { display:flex; gap:20px; padding:30px 40px; flex-wrap:wrap; }
  .card { background:#fff; border-radius:10px; padding:24px 30px; flex:1; min-width:160px;
          box-shadow:0 2px 8px rgba(0,0,0,.08); text-align:center; }
  .card .num  { font-size:42px; font-weight:700; }
  .card .lbl  { font-size:13px; color:#7f8c8d; margin-top:4px; }
  .score-ring { font-size:52px; font-weight:800; color:$scoreColor; }
  .sysinfo { background:#fff; margin:0 40px 30px; border-radius:10px;
             padding:20px 30px; box-shadow:0 2px 8px rgba(0,0,0,.08); display:flex; flex-wrap:wrap; gap:20px; }
  .sysinfo div { font-size:13px; color:#555; }
  .sysinfo span { font-weight:600; color:#2c3e50; }
  .section { margin:0 40px 40px; background:#fff; border-radius:10px;
             box-shadow:0 2px 8px rgba(0,0,0,.08); overflow:hidden; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th { background:#2c3e50; color:#ecf0f1; padding:12px 14px; text-align:left; font-size:12px; letter-spacing:.5px; }
  tr:nth-child(even) { background:#f8f9fa; }
  td { padding:10px 14px; border-bottom:1px solid #ecf0f1; vertical-align:top; }
  .footer { text-align:center; padding:30px; color:#95a5a6; font-size:12px; }
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ Windows Server Hardening Report</h1>
  <p>Generated: $($SystemInfo.ScanTime) &nbsp;|&nbsp; Host: $($SystemInfo.ComputerName) &nbsp;|&nbsp; OS: $($SystemInfo.OSName)</p>
  <span class="badge $(if ($ReportOnly) { 'badge-audit' } else { 'badge-hardened' })">$modeLabel</span>
</div>

<div class="summary">
  <div class="card">
    <div class="score-ring">$score%</div>
    <div class="lbl">Security Score</div>
  </div>
  <div class="card">
    <div class="num" style="color:#27ae60;">$passCount</div>
    <div class="lbl">Already Compliant</div>
  </div>
  <div class="card">
    <div class="num" style="color:#f39c12;">$fixedCount</div>
    <div class="lbl">Fixed</div>
  </div>
  <div class="card">
    <div class="num" style="color:#e74c3c;">$failCount</div>
    <div class="lbl">Needs Attention</div>
  </div>
  <div class="card">
    <div class="num" style="color:#3498db;">$totalCount</div>
    <div class="lbl">Total Checks</div>
  </div>
</div>

<div class="sysinfo">
  <div><span>Computer:</span> $($SystemInfo.ComputerName)</div>
  <div><span>OS:</span> $($SystemInfo.OSName)</div>
  <div><span>Build:</span> $($SystemInfo.OSBuild)</div>
  <div><span>RAM:</span> $($SystemInfo.TotalRAM_GB) GB</div>
  <div><span>Domain:</span> $($SystemInfo.Domain)</div>
  <div><span>CPU:</span> $($SystemInfo.CPU)</div>
</div>

<div class="section">
  <table>
    <thead>
      <tr>
        <th style="width:28%">CHECK</th>
        <th style="width:10%">STATUS</th>
        <th style="width:10%">SEVERITY</th>
        <th style="width:12%">CIS CONTROL</th>
        <th>DETAILS</th>
      </tr>
    </thead>
    <tbody>
      $($tableRows -join "`n")
    </tbody>
  </table>
</div>

<div class="footer">
  Windows Server Hardening Toolkit v1.0.0 &nbsp;|&nbsp;
  <a href="https://github.com/anastanveer653/windows-server-hardening-toolkit">GitHub</a> &nbsp;|&nbsp;
  CIS Benchmark Aligned &nbsp;|&nbsp; Report generated $($SystemInfo.ScanTime)
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "HTML report saved: $OutputPath"
}
