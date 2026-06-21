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
$DevPorts = @(80, 443, 22, 23, 8000, 8888, 5000, 3000, 5432, 6379, 27017, 3306)

# Scripting runtime — đáng ngờ hơn khi kết nối ra ngoài trên port lạ
$ScriptingRuntimes = @("python", "pythonw", "py", "node", "wscript", "cscript", "mshta", "powershell", "pwsh")

# System process — bỏ qua hoàn toàn để tránh false positive
$SystemProcesses = @(
    "svchost", "lsass", "csrss", "wininit", "services", "MsMpEng", "SearchIndexer", "spoolsv",
    "msedge", "CHXSmartScreen", "backgroundTaskHost", "RuntimeBroker",
    "taskhostw", "smartscreen", "ScreenClippingHost", "slui"
)


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

# ── Pattern DoAn npm supply chain ─────────────────────────────────────────
$DoAnPatterns = @(
    "WindowsUpdateHelper",
    "svc-node-helper\.js",
    "/exfil/secrets",
    "/exfil/persist",
    "postinstall-ci-attack",
    "postinstall-persist",
    "system-update-helper"
)

# Không cần $StrongNetCodes: mỗi indicator trong Get-NetworkRisk tự mô tả severity của nó.
# S04Pattern/DoAnPattern → severity="critical" → tự block downgrade, không cần list trung tâm.

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
$script:TempJsBaseline  = [System.Collections.Generic.HashSet[string]]::new()
$script:ProcessBaseline = [System.Collections.Generic.HashSet[int]]::new()
$script:SignatureCache  = @{}   # cache kết quả Authenticode theo exe path
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

# Trả về object mô tả mức độ tin cậy của binary — KHÔNG phải kết luận benign/malicious.
# TrustScore: signature hợp lệ (+2), trusted path (+1). Max = 3.
# Chữ ký Valid chứng minh file không bị sửa đổi và publisher có thể xác định,
# nhưng KHÔNG chứng minh chương trình không độc hại (khóa bị đánh cắp, insider...).
# Cache theo path|size|LastWriteTimeUtc để phát hiện file bị swap tại chỗ.
function Get-ProcessTrustInfo([string]$ExePath) {
    $noInfo = [PSCustomObject]@{ TrustScore = 0; SignatureValid = $false; SignatureStatus = "NoPath"; Publisher = "" }
    if (-not $ExePath) { return $noInfo }

    try {
        $fi       = Get-Item -LiteralPath $ExePath -ErrorAction Stop
        $cacheKey = '{0}|{1}|{2}' -f $ExePath.ToLowerInvariant(), $fi.Length, $fi.LastWriteTimeUtc.Ticks
    } catch {
        $cacheKey = $ExePath.ToLowerInvariant()
    }
    if ($script:SignatureCache.ContainsKey($cacheKey)) { return $script:SignatureCache[$cacheKey] }

    $trustScore = 0
    $sigValid   = $false
    $sigStatus  = "NoSignature"
    $publisher  = ""

    # Authenticode: +2 nếu chữ ký Valid (xác nhận publisher, không xác nhận intent)
    $sig = Get-AuthenticodeSignature -LiteralPath $ExePath -ErrorAction SilentlyContinue
    if ($sig) {
        $sigStatus = $sig.Status.ToString()
        if ($sig.Status -eq "Valid") {
            $trustScore += 2
            $sigValid    = $true
            $publisher   = $sig.SignerCertificate.Subject
        }
    }

    # Trusted installation path: +1 tín hiệu phụ (malware có thể cài vào đây)
    $trustedRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64"
    )
    foreach ($root in $trustedRoots) {
        if ($root -and $ExePath -like "$root\*") { $trustScore += 1; break }
    }

    $result = [PSCustomObject]@{
        TrustScore      = $trustScore
        SignatureValid  = $sigValid
        SignatureStatus = $sigStatus
        Publisher       = $publisher
    }
    $script:SignatureCache[$cacheKey] = $result
    return $result
}

# Kiểm tra tất cả YARA rules có đủ severity + confidence metadata không.
# Rule thiếu metadata sẽ trigger fail-safe (severity="critical", MetadataValid=$false)
# → downgrade bị block thầm lặng mà không có cảnh báo rõ ràng.
# Gọi 1 lần lúc startup để analyst biết trước.
function Test-YaraRuleMetadata {
    if (-not (Test-Path $YaraRule)) { return }
    $content = Get-Content $YaraRule -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return }

    $missing = @()
    foreach ($m in [regex]::Matches($content, '(?m)^\s*rule\s+(\w+)')) {
        $name  = $m.Groups[1].Value
        $start = $m.Index
        # Lấy tối đa 1200 ký tự sau khai báo rule để tìm meta block
        $chunk = $content.Substring($start, [Math]::Min(1200, $content.Length - $start))
        $hasSev  = $chunk -match 'severity\s*='
        $hasConf = $chunk -match 'confidence\s*='
        if (-not $hasSev -or -not $hasConf) { $missing += $name }
    }

    if ($missing.Count -gt 0) {
        Write-Alert "WARN" ("STARTUP | YARA rules thiếu severity/confidence metadata " +
            "(downgrade sẽ bị block tự động nếu match): [$($missing -join ', ')]")
    } else {
        Write-Alert "CLEAR" "STARTUP | Tất cả YARA rules có đủ severity + confidence metadata."
    }
}

function Test-WhitelistedIP([string]$IP) {
    foreach ($p in $WhitelistIPs) { if ($IP -like "$p*") { return $true } }
    return $false
}

function Get-ProcCmdLine([int]$TargetPid) {
    return (Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" `
        -ErrorAction SilentlyContinue).CommandLine
}

# Trả về [PSCustomObject]@{ Matches=[]; ScanFailed=$bool }.
# Mỗi match: {Rule; Severity; Confidence; MetadataValid}.
#
# Fail-safe: rule thiếu metadata → severity="critical", confidence="unknown", MetadataValid=$false.
# MetadataValid=$false hoặc ScanFailed=$true → detector sẽ block downgrade.
# Không được để lỗi scan biến thành "không có indicator" → attacker lợi dụng.
function Invoke-YaraScan([int]$TargetPid) {
    $noScan = [PSCustomObject]@{ Matches = @(); ScanFailed = $true }
    if (-not (Test-Path $YaraExe) -or -not (Test-Path $YaraRule)) { return $noScan }
    try {
        $out      = & $YaraExe -m $YaraRule $TargetPid 2>&1
        $exitCode = $LASTEXITCODE
        # YARA: 0=no match, 1=match(es), >=2=error (rule invalid / process gone / timeout)
        $failed   = ($exitCode -ge 2)

        $matches = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($line in $out) {
            if ($line -notmatch "^\w" -or $line -match "^error|^warning") { continue }
            $ruleName = ($line -split "\s+")[0]

            # Fail-safe defaults: rule không có metadata → critical/unknown → không downgrade
            $severity      = "critical"
            $confidence    = "unknown"
            $metadataValid = $false

            if ($line -match '\[([^\]]+)\]') {
                $m      = $Matches[1]
                $hasSev  = $m -match 'severity\s*=\s*"(\w+)"';   if ($hasSev)  { $severity   = $Matches[1] }
                $hasConf = $m -match 'confidence\s*=\s*"(\w+)"'; if ($hasConf) { $confidence = $Matches[1] }
                $metadataValid = $hasSev -and $hasConf
            }
            $matches.Add([PSCustomObject]@{
                Rule          = $ruleName
                Severity      = $severity
                Confidence    = $confidence
                MetadataValid = $metadataValid
            })
        }
        return [PSCustomObject]@{ Matches = $matches.ToArray(); ScanFailed = $failed }
    } catch {
        return $noScan
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Risk scorer
# ══════════════════════════════════════════════════════════════════════════════

function Get-NetworkRisk {
    param($Conn, $Proc, [string]$CmdLine, $WmiProc)

    $score      = 0
    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Helper nội bộ
    $addInd = { param($code, $sev, $conf, $reason)
        $indicators.Add([PSCustomObject]@{ Code=$code; Severity=$sev; Confidence=$conf; Reason=$reason })
    }

    # Bỏ qua system process
    if ($SystemProcesses -contains $Proc.Name) {
        return [PSCustomObject]@{ Score = 0; Level = "OK"; Indicators = @(); Reasons = ""; Codes = @() }
    }

    # [+3] Port C2 cổ điển — bất kể process nào
    if ($HighRiskPorts -contains $Conn.RemotePort) {
        $score += 3
        & $addInd "HighRiskPort" "warn" "medium" "high-risk port $($Conn.RemotePort)"
    }

    # [+1] IP đích không whitelist
    if (-not (Test-WhitelistedIP $Conn.RemoteAddress)) {
        $score += 1
        & $addInd "NonWhitelistedIP" "info" "low" "non-whitelisted IP $($Conn.RemoteAddress)"
    }

    # [+1] Scripting runtime kết nối ra port không phải web/dev chuẩn
    $isScripting = $ScriptingRuntimes -contains $Proc.Name
    if ($isScripting -and ($DevPorts -notcontains $Conn.RemotePort) -and ($score -lt 3)) {
        $score += 1
        & $addInd "ScriptingRuntime" "warn" "low" "scripting runtime '$($Proc.Name)' on port $($Conn.RemotePort)"
    }

    # ── Behavioral signals — hoạt động bất kể port nào ───────────────────

    # [+2] Process vừa tạo ra (< 60s) đã kết nối ra ngoài
    if ($Proc.StartTime -and ((Get-Date) - $Proc.StartTime).TotalSeconds -lt 60) {
        if (-not (Test-WhitelistedIP $Conn.RemoteAddress)) {
            $score += 2
            & $addInd "NewProcessOutbound" "warn" "medium" "new process (<60s) making outbound connection"
        }
    }

    # [+1] Process chạy không có cửa sổ + scripting runtime
    if ($Proc.MainWindowHandle -eq [IntPtr]::Zero -and $isScripting) {
        $score += 1
        & $addInd "HiddenScriptingProcess" "warn" "low" "hidden/windowless scripting process"
    }

    # [+2] Process cha là pip/python (Python supply chain) hoặc npm/node (npm supply chain)
    if ($WmiProc) {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($WmiProc.ParentProcessId)" `
            -ErrorAction SilentlyContinue
        if ($parent -and $parent.Name -match "pip|python|cmd" -and $parent.CommandLine -match "install|setup\.py") {
            $score += 2
            & $addInd "ParentIsPipOrPython" "warn" "medium" "spawned by install-time process '$($parent.Name)'"
        } elseif ($parent -and $parent.Name -match "^(npm|node)(\.exe)?$" -and $parent.CommandLine -match "install|postinstall") {
            $score += 2
            & $addInd "ParentIsNpmOrNode" "warn" "medium" "spawned by npm/node install process '$($parent.Name)'"
        }
    }

    # [+2] node.exe chạy script từ node_modules — npm postinstall context
    if ($Proc.Name -match "^node" -and $CmdLine -match "node_modules" -and
        (-not (Test-WhitelistedIP $Conn.RemoteAddress))) {
        $score += 2
        & $addInd "NodeFromNodeModules" "warn" "medium" "node.exe running script from node_modules"
    }

    # ── Cmdline check ─────────────────────────────────────────────────────

    if ($CmdLine) {
        # [+4] S04 pattern — severity=critical → tự block downgrade, không cần $StrongNetCodes
        foreach ($pat in $S04Patterns) {
            if ($CmdLine -match $pat) {
                $score += 4
                & $addInd "S04Pattern" "critical" "high" "S04 cmdline '$pat'"
                break
            }
        }
        # [+4] DoAn npm supply chain — severity=critical → tự block downgrade
        foreach ($pat in $DoAnPatterns) {
            if ($CmdLine -match $pat) {
                $score += 4
                & $addInd "DoAnPattern" "critical" "high" "DoAn cmdline '$pat'"
                break
            }
        }
        # [+2] LOLBin generic
        foreach ($pat in $LolbinPatterns) {
            if ($CmdLine -match $pat) {
                $score += 2
                & $addInd "LOLBin" "warn" "medium" "LOLBin cmdline match '$pat'"
                break
            }
        }
    }

    $level = if ($score -ge 4) { "CRITICAL" } elseif ($score -ge 2) { "WARN" } else { "OK" }
    return [PSCustomObject]@{
        Score      = $score
        Level      = $level
        Indicators = $indicators.ToArray()
        Reasons    = ($indicators | ForEach-Object { $_.Reason }) -join " | "
        Codes      = @($indicators | ForEach-Object { $_.Code })
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

        $proc    = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { continue }

        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)" `
                       -ErrorAction SilentlyContinue
        $cmd     = $wmiProc.CommandLine
        $risk    = Get-NetworkRisk -Conn $c -Proc $proc -CmdLine $cmd -WmiProc $wmiProc

        if ($risk.Level -eq "OK") { continue }

        # YARA scan — đọc severity từ metadata, không dùng danh sách riêng
        $scanResult  = Invoke-YaraScan $c.OwningProcess
        $yara        = $scanResult.Matches
        $yaraNames   = @($yara | ForEach-Object { $_.Rule })
        $yaraInfo    = if ($yaraNames.Count -gt 0) { " | YARA:[$($yaraNames -join ', ')]" } else { "" }
        $significant = @($yara | Where-Object { $_.Severity -ne "info" })
        $finalLevel  = if ($significant.Count -gt 0 -and $risk.Level -eq "WARN") { "CRITICAL" } else { $risk.Level }

        # Điều kiện downgrade — tất cả phải đúng:
        #   1. Không có YARA match với severity=critical (bất kể confidence)
        #   2. Không có network indicator với severity=critical (S04/DoAn tự mang field này)
        #   3. Không có YARA match với MetadataValid=false (metadata lỗi → không biết severity thật)
        #   4. Scan không thất bại (lỗi scan không phải "không có indicator")
        #   5. Binary có TrustScore >= 2 (valid Authenticode signature)
        $extraNote = ""
        if ($finalLevel -eq "CRITICAL") {
            $hasCriticalYara = ($yara | Where-Object { $_.Severity -eq "critical" }).Count -gt 0
            $hasInvalidMeta  = ($yara | Where-Object { -not $_.MetadataValid }).Count -gt 0
            $hasCriticalNet  = ($risk.Indicators | Where-Object { $_.Severity -eq "critical" }).Count -gt 0
            $canDowngrade    = -not $hasCriticalYara -and -not $hasInvalidMeta -and
                               -not $hasCriticalNet  -and -not $scanResult.ScanFailed

            if ($canDowngrade) {
                $trust = Get-ProcessTrustInfo $wmiProc.ExecutablePath
                if ($trust.TrustScore -ge 2) {
                    $pub        = if ($trust.Publisher -match 'CN=([^,]+)') { $Matches[1] } else { $trust.Publisher }
                    $extraNote  = " | [Downgraded CRITICAL→WARN | trust=$($trust.TrustScore) | signer=$pub]"
                    $finalLevel = "WARN"
                }
            } elseif ($scanResult.ScanFailed) {
                $extraNote = " | [Downgrade blocked: YARA scan failed]"
            } elseif ($hasInvalidMeta) {
                $bad = ($yara | Where-Object { -not $_.MetadataValid } | ForEach-Object { $_.Rule }) -join ","
                $extraNote = " | [Downgrade blocked: missing metadata on rule(s): $bad]"
            }
        }

        # SHA-256 đầy đủ khi CRITICAL — pháp y, tính lại không dùng cache
        $hashNote = ""
        if ($finalLevel -eq "CRITICAL" -and $wmiProc.ExecutablePath) {
            $fh = Get-FileHash -LiteralPath $wmiProc.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($fh) { $hashNote = " | sha256=$($fh.Hash)" }
        }

        Write-Alert $finalLevel ("NET | PID:$($c.OwningProcess) [$($proc.Name)] -> " +
            "$($c.RemoteAddress):$($c.RemotePort) | score=$($risk.Score) | $($risk.Reasons)$yaraInfo$extraNote$hashNote")
        $null = $script:Reported.Add($connKey)
        $hitCount++
    }

    if ($hitCount -eq 0 -and -not $script:NetClear) {
        Write-Alert "CLEAR" "NET | No suspicious connections."
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
                    Write-Alert "CRITICAL" "PERSIST | New Run key [$shortKey] | '$name' = '$value'"
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
                Write-Alert "CRITICAL" "PERSIST | New file in Startup folder | '$f' | '$folder'"
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
                Write-Alert "CRITICAL" "PERSIST | New Scheduled Task | '$($t.TaskName)' | Action: $action"
                $null = $script:Reported.Add($rKey)
            }
            $null = $script:TaskBaseline.Add($t.TaskName)
        }
    }
}


# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 5 — Temp .js file  (DoAn beacon script: svc-node-helper.js)
# ══════════════════════════════════════════════════════════════════════════════

function Initialize-TempJsBaseline {
    $tempDir = $env:TEMP
    if (Test-Path $tempDir) {
        Get-ChildItem $tempDir -Filter "*.js" -ErrorAction SilentlyContinue |
            ForEach-Object { $null = $script:TempJsBaseline.Add($_.FullName) }
    }
}

function Invoke-TempJsCheck {
    $tempDir = $env:TEMP
    if (-not (Test-Path $tempDir)) { return }
    Get-ChildItem $tempDir -Filter "*.js" -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not $script:TempJsBaseline.Contains($_.FullName)) {
            $rKey = "TEMPJS|$($_.FullName)"
            if (-not $script:Reported.Contains($rKey)) {
                Write-Alert "WARN" "ARTIFACT | New .js file in TEMP | '$($_.Name)' | $($_.FullName)"
                $null = $script:Reported.Add($rKey)
            }
            $null = $script:TempJsBaseline.Add($_.FullName)
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 6 — Child process of node.exe  (DoAn: node → schtasks, reg, crontab)
# ══════════════════════════════════════════════════════════════════════════════

function Invoke-ChildProcessCheck {
    $allProcs  = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $nodeProcs = $allProcs | Where-Object { $_.Name -match "^node(\.exe)?$" }
    foreach ($np in $nodeProcs) {
        $children = $allProcs | Where-Object { $_.ParentProcessId -eq $np.ProcessId }
        foreach ($child in $children) {
            if (-not $child.CommandLine) { continue }
            $suspicious = (
                $child.CommandLine -match "schtasks.*/Create" -or
                $child.CommandLine -match "reg\s+(add|delete).*(\\Run\\|\\RunOnce\\)" -or
                $child.CommandLine -match "crontab\s" -or
                $child.CommandLine -match "at\s+\d{1,2}:"
            )
            if ($suspicious) {
                $rKey = "CHILD|$($child.ProcessId)"
                if (-not $script:Reported.Contains($rKey)) {
                    Write-Alert "CRITICAL" ("EXEC | node.exe (PID:$($np.ProcessId)) spawned " +
                        "'$($child.Name)' [PID:$($child.ProcessId)] | $($child.CommandLine)")
                    $null = $script:Reported.Add($rKey)
                }
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Watcher 7 — New Process (YARA scan mọi process mới, không chờ network)
# ══════════════════════════════════════════════════════════════════════════════

function Initialize-ProcessBaseline {
    Get-Process -ErrorAction SilentlyContinue |
        ForEach-Object { $null = $script:ProcessBaseline.Add($_.Id) }
}

function Invoke-ProcessCheck {
    $currentProcs = Get-Process -ErrorAction SilentlyContinue
    foreach ($p in $currentProcs) {
        if ($SystemProcesses -contains $p.Name) { continue }
        if ($script:ProcessBaseline.Contains($p.Id)) { continue }

        $null = $script:ProcessBaseline.Add($p.Id)

        $scanResult  = Invoke-YaraScan $p.Id
        $yara        = $scanResult.Matches
        if ($yara.Count -eq 0 -and -not $scanResult.ScanFailed) { continue }

        # Nếu scan thất bại, log cảnh báo riêng — không bỏ qua process
        if ($scanResult.ScanFailed -and $yara.Count -eq 0) {
            $rKey = "PROC-SCANFAIL|$($p.Id)"
            if (-not $script:Reported.Contains($rKey)) {
                Write-Alert "WARN" "PROCESS | YARA scan failed (process may have exited) | PID:$($p.Id) [$($p.Name)]"
                $null = $script:Reported.Add($rKey)
            }
            continue
        }

        $yaraNames   = @($yara | ForEach-Object { $_.Rule })
        $significant = @($yara | Where-Object { $_.Severity -ne "info" })

        if ($significant.Count -eq 0) {
            $rKey = "PROC-INFO|$($p.Id)"
            if (-not $script:Reported.Contains($rKey)) {
                Write-Alert "WARN" "PROCESS | Packer detected (info only) | PID:$($p.Id) [$($p.Name)] | YARA:[$($yaraNames -join ', ')]"
                $null = $script:Reported.Add($rKey)
            }
        } else {
            $rKey = "PROC|$($p.Id)"
            if (-not $script:Reported.Contains($rKey)) {
                # severity=critical (bất kể confidence) → không downgrade
                # MetadataValid=false → không biết severity thật → không downgrade
                # ScanFailed → không downgrade (nhưng đây là case đã xử lý ở trên)
                $hasCriticalYara = ($significant | Where-Object { $_.Severity -eq "critical" }).Count -gt 0
                $hasInvalidMeta  = ($yara | Where-Object { -not $_.MetadataValid }).Count -gt 0
                $canDowngrade    = -not $hasCriticalYara -and -not $hasInvalidMeta -and -not $scanResult.ScanFailed

                $level     = "CRITICAL"
                $extraNote = ""
                $hashNote  = ""

                if ($canDowngrade) {
                    $trust = Get-ProcessTrustInfo $p.Path
                    if ($trust.TrustScore -ge 2) {
                        $level     = "WARN"
                        $pub       = if ($trust.Publisher -match 'CN=([^,]+)') { $Matches[1] } else { $trust.Publisher }
                        $extraNote = " | [Downgraded CRITICAL→WARN | trust=$($trust.TrustScore) | signer=$pub]"
                    }
                } elseif ($hasInvalidMeta) {
                    $bad = ($yara | Where-Object { -not $_.MetadataValid } | ForEach-Object { $_.Rule }) -join ","
                    $extraNote = " | [Downgrade blocked: missing metadata on rule(s): $bad]"
                }

                # SHA-256 đầy đủ khi CRITICAL — forensic evidence
                if ($level -eq "CRITICAL" -and $p.Path) {
                    $fh = Get-FileHash -LiteralPath $p.Path -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($fh) { $hashNote = " | sha256=$($fh.Hash)" }
                }

                Write-Alert $level "PROCESS | Malicious code in memory | PID:$($p.Id) [$($p.Name)] | YARA:[$($yaraNames -join ', ')]$extraNote$hashNote"
                $null = $script:Reported.Add($rKey)
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

$logDir = Split-Path $LogFile
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory $logDir -Force | Out-Null }

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  S04 BEHAVIORAL DETECTOR" -ForegroundColor Cyan
Write-Host "  Network | Registry | Startup | Tasks | TempJs | ChildProc" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Log  : $LogFile" -ForegroundColor DarkGray
Write-Host "  YARA : $(if (Test-Path $YaraExe) { 'enabled' } else { 'not found - disabled' })" `
    -ForegroundColor DarkGray
Write-Host ""

Write-Alert "INFO" "Setting up baseline..."
Test-YaraRuleMetadata
Initialize-RegBaseline
Initialize-StartupBaseline
Initialize-TaskBaseline
Initialize-TempJsBaseline
Initialize-ProcessBaseline
Write-Alert "INFO" "Baseline ready. Monitoring started."

while ($true) {
    $script:TickCount++

    Invoke-NetworkCheck       # every 2s
    Invoke-RegistryCheck      # every 2s
    Invoke-StartupCheck       # every 2s
    Invoke-TempJsCheck        # every 2s — beacon script in %TEMP%
    Invoke-ChildProcessCheck  # every 2s — node.exe spawning schtasks/reg
    Invoke-ProcessCheck       # every 2s — YARA scan on every new process

    if ($script:TickCount % 3 -eq 0) {
        Invoke-TaskCheck      # every 6s
    }

    Start-Sleep -Seconds 2
}
