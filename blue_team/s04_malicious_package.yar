// ══════════════════════════════════════════════════════════════════════════
//  YARA RULES — HAI TẦNG
//  Tầng 1 (Generic): phát hiện hành vi bất kể malware family
//  Tầng 2 (S04-specific): IoC cụ thể của supply chain simulator
// ══════════════════════════════════════════════════════════════════════════

// ── TẦNG 1: GENERIC ──────────────────────────────────────────────────────

rule Generic_Python_Exfiltration {
    meta:
        description = "Python đọc file nhạy cảm và gửi qua HTTP"
        severity    = "high"
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
        severity    = "high"
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
        severity    = "medium"
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
        severity    = "high"
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
        mitre       = "T1555.003, T1056.001"
    strings:
        $chrome    = "Login Data"       ascii wide
        $firefox   = "logins.json"      ascii wide
        $keylog    = "GetAsyncKeyState" ascii wide
        $clipboard = "GetClipboardData" ascii wide
        $screenshot = "CopyFromScreen"  ascii wide
        $smtp      = "SmtpClient"       ascii wide
    condition:
        ($chrome and $firefox) or
        ($keylog and $clipboard) or
        ($smtp and ($keylog or $clipboard or $screenshot))
}

rule Packer_UPX {
    meta:
        description = "Binary được nén bằng UPX"
        severity    = "info"
    strings:
        $upx0  = "UPX0" ascii
        $upx1  = "UPX1" ascii
        $magic = "UPX!" ascii
    condition:
        2 of them
}

rule Packer_Aspack {
    meta:
        description = "Binary được pack bằng ASPack"
        severity    = "info"
    strings:
        $s1 = ".aspack" ascii nocase
        $s2 = "ASPack"  ascii
    condition:
        any of them
}

// ── TẦNG 2: S04-SPECIFIC ─────────────────────────────────────────────────

rule S04_Supply_Chain_IoC {
    meta:
        description = "IoC đặc thù của S04 supply chain simulator"
        severity    = "critical"
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
