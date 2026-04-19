#Requires -RunAsAdministrator
$logFile = "C:\S04Demo\detector_audit.log"
Write-Host "--- S04 ADVANCED BEHAVIORAL DETECTOR IS RUNNING ---" -ForegroundColor Cyan

# Whitelist: PyPI CDN (Fastly 151.101.x.x), localhost
$WhitelistIPs = @("151.101.", "127.0.0.1", "::1")
$ReportedConnections = @()  # Chống spam cảnh báo trùng lặp
$isSystemClear = $false

while($true) {
    $timestamp = Get-Date -Format "HH:mm:ss"
    $network = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
        try {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $isPython = $proc.ProcessName -match "python"  # Bắt python, python3, pythonw...
            $remoteIP = $_.RemoteAddress
            $isWhitelisted = $false
            foreach ($ip in $WhitelistIPs) {
                if ($remoteIP -like "$ip*") { $isWhitelisted = $true }
            }
            return ($isPython -and -not $isWhitelisted)
        } catch { return $false }
    }
    if ($network) {
        $isSystemClear = $false
        foreach ($conn in $network) {
            $procId = $conn.OwningProcess
            $remote = $conn.RemoteAddress
            $connectionKey = "$procId-$remote"
            if ($ReportedConnections -notcontains $connectionKey) {
                $proc = Get-Process -Id $procId
                Write-Host "[$timestamp] ALERT: Suspicious Python Outbound!" -ForegroundColor Red
                Write-Host "[!] PID: $procId | Path: $($proc.Path) | Remote: $remote" -ForegroundColor Yellow
                $ReportedConnections += $connectionKey
                "[$timestamp] ALERT: PID $procId -> $remote | $($proc.Path)" | Out-File $logFile -Append
            }
        }
    } else {
        if (-not $isSystemClear) {
            Write-Host "[$timestamp] System Clear: No active threats detected." -ForegroundColor Green
            $isSystemClear = $true
            $ReportedConnections = @()  # Reset để sẵn sàng cho đợt tấn công mới
        }
    }
    Start-Sleep -Seconds 3
}
