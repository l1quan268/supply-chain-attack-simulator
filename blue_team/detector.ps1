#Requires -RunAsAdministrator
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8

# ══════════════════════════════════════════════════════════════════════════════
#  S04 BEHAVIORAL DETECTOR  —  Network | Registry | Startup | Tasks | Process
# ══════════════════════════════════════════════════════════════════════════════

$LogFile  = "C:\S04Demo\detector_audit.log"
$YaraExe  = "C:\S04Demo\yara64.exe"
$YaraRule = "C:\S04Demo\s04_malicious_package.yar"

# ── Whitelist IP ──────────────────────────────────────────────────────────
$WhitelistIPs = @(
    "151.101.",  # PyPI / Fastly CDN
    "140.82.",   # GitHub
    "185.199.",  # GitHub CDN
    "104.16.",   # Anaconda / Cloudflare
    "127.0.0.1", "::1",   # localhost
    "172.31.0."  # Docker internal
)

# Port luôn đáng ngờ bất kể process nào
$HighRiskPorts = @(4444, 1337, 9001, 31337, 6666, 5555)

# Port bình thường cho dev — giảm false positive khi đây là signal duy nhất
$DevPorts = @(80, 443, 8000, 8888, 5000, 3000, 5432, 6379, 27017, 3306)

# Scripting runtime — đáng ngờ hơn khi kết nối ra ngoài trên port lạ
$ScriptingRuntimes = @("python", "pythonw", "py", "node", "wscript", "cscript", "mshta", "powershell", "pwsh")

# System process — bỏ qua hoàn toàn để tránh false positive
$SystemProcesses = @("svchost", "lsass", "csrss", "wininit", "services", "MsMpEng", "SearchIndexer", "spoolsv")

# Persistence keys
$RunKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$StartupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

# ── Pattern S04 (độ tin cậy cao — alert kể cả không có network) ──────────
$S04Patterns = @(
    "corp_auth_utils\.marker",
    "corpx_utils\.marker",
    "corpx_logging.*marker",
    "run_marker"
)

# ── Pattern LOLBin generic (chỉ alert khi KẾT HỢP với signal network) ────
$LolbinPatterns = @(
    "certutil.*(-(decode|urlcache|split))",
    "mshta.*(http|https|ftp)://",
    "powershell.*(-enc\b|-EncodedCommand)",
    "wscript.*\.(js|vbs|wsf)",
    "regsvr32.*scrobj",
    "rundll32.*javascript:",
    "bitsadmin.*/transfer"
)

# ── State ─────────────────────────────────────────────────────────────────
$script:Reported        = [System.Collections.Generic.HashSet[string]]::new()
$script:RegBaseline     = @{}
$script:StartupBaseline = @{}
$script:TaskBaseline    = [System.Collections.Generic.HashSet[string]]::new()
$script:NetClear        = $false
$script:TickCount       = 0

# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

function Write-Alert {
    param([string]$Level, [string]$Msg)
    $ts    = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "CRITICAL" { "Red"    }
        "WARN"     { "Yellow" }
        "CLEAR"    { "Green"  }
        default    { "Cyan"   }
    }
    $line = "[$ts][$Level] $Msg"
    Write-Host $line -ForegroundColor $color
    $line | Out-File $LogFile -Append -Encoding UTF8
}

function Test-WhitelistedIP([string]$IP) {
    foreach ($p in $WhitelistIPs) { if ($IP -like "$p*") { return $true } }
    return $false
}

function Get-ProcCmdLine([int]$TargetPid) {
    return (Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" `
        -ErrorAction SilentlyContinue).CommandLine
}

function Invoke-YaraScan([int]$TargetPid) {
    if (-not (Test-Path $YaraExe) -or -not (Test-Path $YaraRule)) { return @() }
    try {
        $out = & $YaraExe $YaraRule $TargetPid 2>&1
        return @($out | Where-Object { $_ -match "^\w" -and $_ -notmatch "error|warning" } |
            ForEach-Object { ($_ -split "\s+")[0] })
    } catch { return @() }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Risk scorer
# ══════════════════════════════════════════════════════════════════════════════

function Get-NetworkRisk {
    param($Conn, $Proc, [string]$CmdLine)

    $score   = 0
    $reasons = [System.Collections.Generic.List[string]]::new()

    # Bỏ qua system process
    if ($SystemProcesses -contains $Proc.Name) {
        return [PSCustomObject]@{ Score = 0; Level = "OK"; Reasons = "" }
    }

    # [+3] Port C2 cổ điển — bất kể process nào
    if ($HighRiskPorts -contains $Conn.RemotePort) {
        $score += 3
        $reasons.Add("high-risk port $($Conn.RemotePort)")
    }

    # [+1] IP đích không whitelist
    if (-not (Test-WhitelistedIP $Conn.RemoteAddress)) {
        $score += 1
        $reasons.Add("non-whitelisted IP $($Conn.RemoteAddress)")
    }

    # [+1] Scripting runtime kết nối ra port không phải web/dev chuẩn
    $isScripting = $ScriptingRuntimes -contains $Proc.Name
    if ($isScripting -and ($DevPorts -notcontains $Conn.RemotePort) -and ($score -lt 3)) {
        $score += 1
        $reasons.Add("scripting runtime '$($Proc.Name)' trên port $($Conn.RemotePort)")
    }

    # Cmdline check — luôn chạy, không cần gate (LOLBin cần kết hợp với IP signal)
    if ($CmdLine) {
        # [+4] S04 pattern — độ tin cậy rất cao
        foreach ($pat in $S04Patterns) {
            if ($CmdLine -match $pat) {
                $score += 4
                $reasons.Add("S04 cmdline '$pat'")
                break
            }
        }
        # [+2] LOLBin generic — cộng thêm vào signal đã có
        foreach ($pat in $LolbinPatterns) {
            if ($CmdLine -match $pat) {
                $score += 2
                $reasons.Add("LOLBin cmdline match '$pat'")
                break
            }
        }
    }

    $level = if ($score -ge 4) { "CRITICAL" } elseif ($score -ge 2) { "WARN" } else { "OK" }
    return [PSCustomObject]@{
        Score   = $score
        Level   = $level
        Reasons = ($reasons -join " | ")
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 1 — Network
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-NetworkCheck {
    $conns    = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $hitCount = 0

    foreach ($c in $conns) {
        if (-not $c.RemoteAddress -or $c.RemoteAddress -in @("0.0.0.0", "::")) { continue }
        if (Test-WhitelistedIP $c.RemoteAddress) { continue }

        $connKey = "$($c.OwningProcess)|$($c.RemoteAddress):$($c.RemotePort)"
        if ($script:Reported.Contains($connKey)) { continue }

        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { continue }

        $cmd  = Get-ProcCmdLine $c.OwningProcess
        $risk = Get-NetworkRisk -Conn $c -Proc $proc -CmdLine $cmd

        if ($risk.Level -eq "OK") { continue }

        # YARA scan process memory — upgrade WARN → CRITICAL nếu match
        $yara      = Invoke-YaraScan $c.OwningProcess
        $yaraInfo  = if ($yara.Count -gt 0) { " | YARA:[$($yara -join ', ')]" } else { "" }
        $finalLevel = if ($yara.Count -gt 0 -and $risk.Level -eq "WARN") { "CRITICAL" } else { $risk.Level }

        Write-Alert $finalLevel ("NET | PID:$($c.OwningProcess) [$($proc.Name)] → " +
            "$($c.RemoteAddress):$($c.RemotePort) | score=$($risk.Score) | $($risk.Reasons)$yaraInfo")
        $null = $script:Reported.Add($connKey)
        $hitCount++
    }

    if ($hitCount -eq 0 -and -not $script:NetClear) {
        Write-Alert "CLEAR" "NET | Không có kết nối đáng ngờ."
        $script:NetClear = $true
    } elseif ($hitCount -gt 0) { $script:NetClear = $false }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 2 — Registry Run / RunOnce  (T1547.001)
# ══════════════════════════════════════════════════════════════════════════════

function Initialize-RegBaseline {
    foreach ($key in $RunKeys) {
        $script:RegBaseline[$key] = @{}
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } |
            ForEach-Object { $script:RegBaseline[$key][$_.Name] = $_.Value }
    }
}

function Invoke-RegistryCheck {
    foreach ($key in $RunKeys) {
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $name = $_.Name; $value = $_.Value
            if (-not $script:RegBaseline[$key].ContainsKey($name)) {
                $rKey = "REG|$key|$name"
                if (-not $script:Reported.Contains($rKey)) {
                    $shortKey = ($key -split "\\")[-3..-1] -join "\"
                    Write-Alert "CRITICAL" "PERSIST | Run key mới [$shortKey] | '$name' = '$value'"
                    $null = $script:Reported.Add($rKey)
                }
                $script:RegBaseline[$key][$name] = $value
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 3 — Startup Folder  (T1547.001 variant)
# ══════════════════════════════════════════════════════════════════════════════

function Initialize-StartupBaseline {
    foreach ($folder in $StartupFolders) {
        if (-not (Test-Path $folder)) { $script:StartupBaseline[$folder] = @(); continue }
        $script:StartupBaseline[$folder] = @(
            Get-ChildItem $folder -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        )
    }
}

function Invoke-StartupCheck {
    foreach ($folder in $StartupFolders) {
        if (-not (Test-Path $folder)) { continue }
        $current  = @(Get-ChildItem $folder -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        $baseline = $script:StartupBaseline[$folder]
        foreach ($f in ($current | Where-Object { $baseline -notcontains $_ })) {
            $rKey = "STARTUP|$folder|$f"
            if (-not $script:Reported.Contains($rKey)) {
                Write-Alert "CRITICAL" "PERSIST | File mới trong Startup folder | '$f' | '$folder'"
                $null = $script:Reported.Add($rKey)
            }
            $script:StartupBaseline[$folder] += $f
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 4 — Scheduled Tasks  (T1053.005)
# ══════════════════════════════════════════════════════════════════════════════

function Initialize-TaskBaseline {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notmatch "^\\Microsoft\\" } |
        ForEach-Object { $null = $script:TaskBaseline.Add($_.TaskName) }
}

function Invoke-TaskCheck {
    $current = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notmatch "^\\Microsoft\\" }
    foreach ($t in $current) {
        if (-not $script:TaskBaseline.Contains($t.TaskName)) {
            $rKey = "TASK|$($t.TaskName)"
            if (-not $script:Reported.Contains($rKey)) {
                $action = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
                Write-Alert "CRITICAL" "PERSIST | Scheduled task mới | '$($t.TaskName)' | Action: $action"
                $null = $script:Reported.Add($rKey)
            }
            $null = $script:TaskBaseline.Add($t.TaskName)
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 5 — Process CommandLine  (S04-specific, near-zero false positive)
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-ProcessCheck {
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        if (-not $p.CommandLine) { continue }
        foreach ($pat in $S04Patterns) {
            if ($p.CommandLine -match $pat) {
                $rKey = "PROC|$($p.ProcessId)|$pat"
                if (-not $script:Reported.Contains($rKey)) {
                    Write-Alert "CRITICAL" "PROC | PID:$($p.ProcessId) [$($p.Name)] | S04 pattern '$pat' | $($p.CommandLine)"
                    $null = $script:Reported.Add($rKey)
                }
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

$logDir = Split-Path $LogFile
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory $logDir -Force | Out-Null }

Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  S04 BEHAVIORAL DETECTOR" -ForegroundColor Cyan
Write-Host "  Network | Registry | Startup | Tasks | Process" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Log  : $LogFile" -ForegroundColor DarkGray
Write-Host "  YARA : $(if (Test-Path $YaraExe) { 'enabled' } else { 'not found — disabled' })" `
    -ForegroundColor DarkGray
Write-Host ""

Write-Alert "INFO" "Thiết lập baseline..."
Initialize-RegBaseline
Initialize-StartupBaseline
Initialize-TaskBaseline
Write-Alert "INFO" "Baseline xong. Bắt đầu giám sát."

while ($true) {
    $script:TickCount++

    Invoke-NetworkCheck    # mỗi 2s
    Invoke-RegistryCheck   # mỗi 2s
    Invoke-StartupCheck    # mỗi 2s

    if ($script:TickCount % 3 -eq 0) {
        Invoke-TaskCheck       # mỗi 6s
        Invoke-ProcessCheck    # mỗi 6s
    }

    Start-Sleep -Seconds 2
}
