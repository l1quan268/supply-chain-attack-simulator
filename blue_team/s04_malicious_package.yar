// ══════════════════════════════════════════════════════════════════════════
//  YARA RULES — HAI TẦNG
//  Tầng 1 (Generic): phát hiện hành vi bất kể malware family
//  Tầng 2 (S04-specific): IoC cụ thể của supply chain simulator
//
//  Metadata convention (detector đọc tự động, KHÔNG dùng danh sách riêng):
//    severity   = "info"     → chỉ ghi nhận, không nâng CRITICAL
//    severity   = "critical" → hành vi nguy hiểm, có thể downgrade nếu confidence thấp
//    confidence = "low"      → heuristic / generic, có thể downgrade nếu binary được ký
//    confidence = "medium"   → hành vi đáng ngờ nhưng có thể có false positive
//    confidence = "high"     → xác định hành vi cụ thể, chữ ký số KHÔNG override được
// ══════════════════════════════════════════════════════════════════════════

// ── TẦNG 1: GENERIC ──────────────────────────────────────────────────────

rule Generic_Python_Exfiltration {
    meta:
        description = "Python đọc file nhạy cảm và gửi qua HTTP"
        severity    = "high"
        confidence  = "medium"
        mitre       = "T1041, T1083"
    strings:
        $net1   = "urllib.request" ascii wide
        $net2   = "requests.post"  ascii wide
        $net3   = "requests.put"   ascii wide
        $walk   = "os.walk"        ascii wide
        $ext1   = ".env"           ascii wide
        $ext2   = ".pem"           ascii wide
        $ext3   = "id_rsa"         ascii wide
        $ext4   = ".key"           ascii wide
        $ext5   = "credentials"    ascii wide
    condition:
        any of ($net1, $net2, $net3) and $walk and any of ($ext1, $ext2, $ext3, $ext4, $ext5)
}

rule Generic_Python_Reverse_Shell {
    meta:
        description = "Python mở socket và thực thi lệnh shell nhận từ remote"
        severity    = "critical"
        confidence  = "high"
        mitre       = "T1059.006"
    strings:
        $sock    = "socket.socket"    ascii wide
        $connect = ".connect("        ascii wide
        $popen   = "subprocess.Popen" ascii wide
        $shell   = "shell=True"       ascii wide
        $recv    = ".recv("           ascii wide
    condition:
        $sock and $connect and $popen and $shell and $recv
}

rule Generic_Registry_Persistence {
    meta:
        description = "Code ghi vào Run key để tồn tại sau reboot"
        severity    = "critical"
        confidence  = "high"
        mitre       = "T1547.001"
    strings:
        $winreg = "winreg"               ascii wide
        $runkey = "CurrentVersion\\Run"  ascii wide
        $setval = "SetValueEx"           ascii wide
    condition:
        all of them
}

rule Generic_Setup_Py_Execution {
    meta:
        description = "setup.py spawn subprocess tại module-level (supply chain pattern)"
        severity    = "critical"
        confidence  = "high"
        mitre       = "T1195.001"
    strings:
        $setup   = "def setup("        ascii wide
        $popen   = "subprocess.Popen"  ascii wide
        $detach1 = "0x08000000"        ascii wide
        $detach2 = "start_new_session" ascii wide
        $detach3 = "DETACHED_PROCESS"  ascii wide
    condition:
        $setup and $popen and any of ($detach1, $detach2, $detach3)
}

rule Generic_LOLBin_PowerShell_Encoded {
    meta:
        description = "PowerShell chạy lệnh được encode/obfuscate"
        severity    = "critical"
        confidence  = "medium"
        mitre       = "T1059.001"
    strings:
        $enc1   = "-EncodedCommand"         ascii wide nocase
        $enc2   = "-enc "                   ascii wide nocase
        $b64    = "FromBase64String"        ascii wide
        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase
        $hidden = "-WindowStyle Hidden"     ascii wide nocase
        $noprof = "-NoProfile"              ascii wide nocase
    condition:
        ($enc1 or $enc2) or ($b64 and any of ($bypass, $hidden, $noprof))
}

rule Generic_LOLBin_Certutil {
    meta:
        description = "certutil dùng để tải hoặc decode payload"
        severity    = "critical"
        confidence  = "medium"
        mitre       = "T1140, T1105"
    strings:
        $cert   = "certutil"  ascii wide nocase
        $decode = "-decode"   ascii wide nocase
        $url    = "-urlcache" ascii wide nocase
        $split  = "-split"    ascii wide nocase
    condition:
        $cert and any of ($decode, $url, $split)
}

rule Generic_Credential_Harvesting {
    meta:
        description = "Đọc credential từ browser hoặc email client (AgentTesla-style)"
        severity    = "critical"
        confidence  = "high"
        mitre       = "T1555.003, T1056.001"
    strings:
        $chrome     = "Login Data"       ascii wide
        $firefox    = "logins.json"      ascii wide
        $keylog     = "GetAsyncKeyState" ascii wide
        $clipboard  = "GetClipboardData" ascii wide
        $screenshot = "CopyFromScreen"   ascii wide
        $smtp       = "SmtpClient"       ascii wide
        $fp_putty   = "PuTTY"            ascii wide nocase
    condition:
        filesize < 20MB and not $fp_putty and (
            ($chrome and $firefox) or
            ($keylog and $clipboard and $smtp) or
            ($smtp and $screenshot)
        )
}

rule Packer_UPX {
    meta:
        description = "Binary được nén bằng UPX"
        severity    = "info"
        confidence  = "low"
    strings:
        $upx0  = "UPX0" ascii
        $upx1  = "UPX1" ascii
        $magic = "UPX!" ascii
    condition:
        2 of them
}

rule Suspicious_UPX_Malware {
    meta:
        description = "UPX-packed binary co dau hieu malicious trong memory — packer che giau ma doc"
        severity    = "critical"
        confidence  = "high"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        // Keylogger / stealer (Agent Tesla, FormBook...)
        $mal1 = "GetAsyncKeyState"    ascii wide
        $mal2 = "GetClipboardData"    ascii wide
        $mal3 = "SmtpClient"          ascii wide
        // Process injection (RAT, Cobalt Strike...)
        $mal4 = "VirtualAllocEx"      ascii wide
        $mal5 = "CreateRemoteThread"  ascii wide
        // Supply chain IoC (S04 / DoAn)
        $mal6 = "WindowsSysUpdater"   ascii wide
        $mal7 = "run_marker"          ascii wide
        $mal8 = "WindowsUpdateHelper" ascii wide
    condition:
        ($upx0 and $upx1) and any of ($mal1, $mal2, $mal3, $mal4, $mal5, $mal6, $mal7, $mal8)
}

rule Packer_Aspack {
    meta:
        description = "Binary được pack bằng ASPack"
        severity    = "info"
        confidence  = "low"
    strings:
        $s1 = ".aspack" ascii nocase
        $s2 = "ASPack"  ascii
    condition:
        any of them
}

rule Generic_JS_Env_Exfiltration {
    meta:
        description = "Node.js thu thap bien moi truong chua secret va gui qua HTTP (npm supply chain)"
        severity    = "critical"
        confidence  = "medium"
        mitre       = "T1552.007, T1041"
    strings:
        $penv  = "process.env"   ascii wide
        $http1 = "http.request"  ascii wide
        $http2 = "https.request" ascii wide
        $b64   = "base64"        ascii wide
        $kw1   = "TOKEN"         ascii wide nocase
        $kw2   = "SECRET"        ascii wide nocase
        $kw3   = "PASSWORD"      ascii wide nocase
        $kw4   = "CREDENTIAL"    ascii wide nocase
    condition:
        $penv and any of ($http1, $http2) and $b64 and any of ($kw1, $kw2, $kw3, $kw4)
}

rule Generic_JS_StageLoader {
    meta:
        description = "Node.js tai stage2 tu mang, ghi file roi require() de thuc thi (write-then-require)"
        severity    = "critical"
        confidence  = "medium"
        mitre       = "T1059.007, T1105"
    strings:
        $write = "writeFileSync" ascii wide
        $req   = "require("      ascii wide
        $b64   = "Buffer.from"   ascii wide
        $get   = ".get("         ascii wide
    condition:
        $write and $req and $b64 and $get
}

rule Generic_JS_Schtasks_Persistence {
    meta:
        description = "Node.js goi schtasks tao Scheduled Task de persistence (T1053.005)"
        severity    = "critical"
        confidence  = "high"
        mitre       = "T1053.005"
    strings:
        $scht   = "schtasks"      ascii wide
        $create = "/Create"       ascii wide nocase
        $exec1  = "execSync"      ascii wide
        $exec2  = "child_process" ascii wide
    condition:
        $scht and $create and any of ($exec1, $exec2)
}

// ── TẦNG 2: S04-SPECIFIC & DoAn-SPECIFIC ─────────────────────────────────

rule S04_Supply_Chain_IoC {
    meta:
        description = "IoC đặc thù của S04 supply chain simulator"
        severity    = "critical"
        confidence  = "high"
        mitre       = "T1195.001"
    strings:
        $token  = "S04-SECRET-TOKEN"  ascii wide
        $regkey = "WindowsSysUpdater" ascii wide
        $mod1   = "corp_auth_utils"   ascii wide
        $mod2   = "corpx_utils"       ascii wide
        $marker = "run_marker"        ascii wide
    condition:
        any of them
}

rule DoAn_Supply_Chain_IoC {
    meta:
        description = "IoC dac thu cua DoAn npm supply chain attack"
        severity    = "critical"
        confidence  = "high"
        mitre       = "T1195.002"
    strings:
        $task   = "WindowsUpdateHelper"  ascii wide
        $exfil1 = "/exfil/secrets"       ascii wide
        $exfil2 = "/exfil/persist"       ascii wide
        $beacon = "svc-node-helper.js"   ascii wide
        $loader = "telemetry.js"         ascii wide
        $cron   = "system-update-helper" ascii wide
    condition:
        any of them
}
