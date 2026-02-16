# AWAM - Bug Bounty Automation Framework (Enhanced)

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

**AWAM** (singkatan dari "Automatic Web Assessment Machine") adalah framework otomatisasi untuk bug bounty hunting dan penetration testing yang dirancang dengan fokus pada akurasi tinggi, false positive rendah, dan proof-of-exploit verification. Tool ini membantu security researcher dan penetration tester dalam mengidentifikasi potensi kerentanan keamanan pada aplikasi web secara efisien.

---

## 📋 Daftar Isi

- [Deskripsi Tool](#-deskripsi-tool)
- [Kelebihan](#-kelebihan)
- [Kekurangan](#-kekurangan)
- [Fungsi Utama](#-fungsi-utama)
- [Rencana Pengembangan](#-rencana-pengembangan)
- [Requirements](#-requirements)
- [Cara Penggunaan](#-cara-penggunaan)
- [Menindaklanjuti Output](#-menindaklanjuti-output)
- [Kebijakan Penggunaan](#-kebijakan-penggunaan)
- [Lisensi](#-lisensi)

---

## 🎯 Deskripsi Tool

AWAM adalah framework otomatisasi bug bounty yang dikembangkan dengan pendekatan modern untuk mengatasi tantangan utama dalam security automation: **false positive**. Berbeda dengan scanner konvensional yang hanya mengandalkan pattern matching, AWAM mengimplementasikan beberapa lapisan verifikasi:

- **Baseline Response Engine**: Membandingkan respons normal vs respons dengan payload
- **Proof-of-Exploit Verification**: Memverifikasi kerentanan dengan bukti eksploitasi nyata
- **Confidence Scoring System**: Menghitung tingkat kepercayaan berdasarkan multiple factors
- **False Positive Filtering**: Menyaring temuan dengan konteks dan validasi

Tool ini dirancang untuk membantu bug bounty hunter mempercepat proses reconnaissance dan identifikasi **potensi** kerentanan tanpa mengorbankan akurasi. **Penting untuk dipahami bahwa semua temuan dari tool ini WAJIB diverifikasi secara manual sebelum dilaporkan.**

---

## ✨ Kelebihan

### 1. **Akurasi Tinggi dengan False Positive Rendah**
- ✅ **Baseline Comparison**: Mengambil 5 sampel respons normal sebelum pengujian untuk deteksi anomali
- ✅ **PoE (Proof-of-Exploit) Verification**: Memverifikasi dampak nyata dengan analisis konteks (bukan sekadar refleksi payload)
- ✅ **Confidence Scoring**: Setiap temuan diberi skor kepercayaan (0-100%) berdasarkan multiple factors
- ✅ **False Positive Filter**: Filter kontekstual untuk LFI, XSS, dan Open Redirect

### 2. **Fitur Canggih**
- ✅ **WAF Detection**: Mendeteksi Cloudflare, AWS WAF, F5 BIG-IP dengan signature-based detection
- ✅ **Tech Stack Fingerprinting**: Mengidentifikasi teknologi yang digunakan dari headers dan konten
- ✅ **Rate Limiting Adaptive**: Menyesuaikan kecepatan request secara dinamis saat mendeteksi error
- ✅ **Scope Limiter**: Membatasi pengujian hanya pada domain yang diotorisasi dengan wildcard support

### 3. **Output Berkualitas**
- ✅ **CURL Command**: Setiap temuan dilengkapi perintah reproduksi untuk verifikasi manual
- ✅ **Multiple Output Format**: JSON (terstruktur), TXT (human-readable), dan CSV (analisis spreadsheet)
- ✅ **Evidence Details**: Menyertakan bukti verifikasi dan konteks dalam laporan
- ✅ **Severity Classification**: Klasifikasi tingkat keparahan berdasarkan CVSS-like scoring

### 4. **User Experience**
- ✅ **Color-coded Logging**: Output berwarna untuk memudahkan monitoring dan debugging
- ✅ **Progress Tracking**: Menampilkan progress scanning secara real-time dengan persentase
- ✅ **Legal Warning**: Pengingat etika dan legalitas penggunaan sebelum eksekusi
- ✅ **Graceful Shutdown**: Menangani interrupt (CTRL+C) dengan baik dan menyimpan progress

---

## ⚠️ Kekurangan

### 1. **Keterbatasan Teknis**
- ❌ **Hanya GET Requests**: Belum mendukung POST, PUT, DELETE methods untuk pengujian parameter
- ❌ **Parameter Terbatas**: Hanya menguji parameter umum (id, page, p, q, search) secara default
- ❌ **Payload Terbatas**: Jumlah payload terbatas untuk masing-masing kerentanan (5-8 per tipe)
- ❌ **No Authentication**: Belum mendukung pengujian dengan session/login/cookies secara otomatis

### 2. **Keterbatasan Coverage**
- ❌ **Tidak Mendeteksi**: Business logic flaws, IDOR kompleks, CSRF dengan token dinamis
- ❌ **XSS Stored**: Tidak bisa mendeteksi XSS stored yang memerlukan multiple steps/interaksi
- ❌ **API Testing**: Belum optimal untuk pengujian API dengan format JSON/XML/GraphQL
- ❌ **Header Injection**: Tidak menguji kerentanan pada headers (Host, User-Agent, Referer)

### 3. **False Negative Potensial**
- ❌ **Bypass Techniques**: Teknik bypass WAF masih terbatas pada pola umum
- ❌ **Deep Scanning**: Tidak melakukan crawling mendalam untuk menemukan semua endpoint
- ❌ **Complex Workflows**: Tidak bisa mengikuti workflow multi-step (login → action → verify)
- ❌ **DOM-based Vulnerabilities**: Tidak bisa mendeteksi kerentanan yang hanya muncul di client-side

### 4. **Performa**
- ❌ **Single Target**: Optimal untuk single target, bukan massive scanning (max 30 target)
- ❌ **Memory Usage**: Bisa tinggi jika banyak target (tergantung jumlah threads)
- ❌ **No Caching**: Tidak menyimpan cache respons untuk pengujian berulang

---

## 🛠️ Fungsi Utama

### 1. **Subdomain Discovery**
Menggunakan CRT.sh untuk menemukan subdomain dari target secara passive:
```python
subdomains = scanner.discover_subdomains()
# Output: ['api.target.com', 'dev.target.com', 'stage.target.com', ...]
```
**Keterbatasan**: Hanya mengambil 100 entry pertama dari CRT.sh

### 2. **Target Validation**
Memvalidasi ketersediaan target dan melakukan fingerprinting lengkap:
- Resolve domain ke IPv4/IPv6
- Deteksi status code (200, 403, 404, dll)
- Identifikasi WAF dengan signature matching
- Fingerprinting teknologi (server, framework, library)

### 3. **Endpoint Discovery**
Menemukan endpoint umum pada target dengan wordlist built-in:
- File sensitif: `.env`, `.git`, `robots.txt`, `sitemap.xml`
- Direktori umum: `/admin`, `/api`, `/login`, `/dashboard`
- File konfigurasi: `config.php`, `web.config`, `.htaccess`

### 4. **Vulnerability Scanning**

#### **Open Redirect Testing**
```python
Payload: //evil.com, https://evil.com, //evil.com@google.com
Verifikasi: 
- Cek Location header dalam respons
- Analisis apakah redirect ke domain eksternal
- Filter false positive: redirect ke domain sendiri/subdomain
Confidence: MEDIUM (65%) jika is_external, HIGH (85%) jika pattern terdeteksi
```

#### **LFI (Local File Inclusion) Testing**
```python
Payload: ../../../../etc/passwd, file:///etc/passwd, %2e%2e%2fetc/passwd
Verifikasi: 
- Cari pola file system (root:x:0:0, daemon:x:1:1, [fonts])
- Filter directory listing (Index of /, Parent Directory)
Confidence: Berdasarkan jumlah indicators ditemukan
```

#### **XSS (Cross-Site Scripting) Testing**
```python
Payload: <script>alert(1)</script>, <img src=x onerror=alert(1)>
Verifikasi: 
- Marker reflection dengan analisis konteks HTML
- Cek apakah marker berada di dalam tag script/event handler
Severity: CRITICAL (in script/event), MEDIUM (other contexts)
```

### 5. **Reporting**
- JSON report untuk integrasi dengan tools lain (Burp Suite, Metasploit)
- Text report untuk human reading dengan format rapi
- CSV export untuk analisis di Excel/Google Sheets
- CURL commands untuk reproduksi manual setiap temuan

---

## 🧭 Rencana Pengembangan

### 1. **Jangka Pendek**
- [ ] **POST Request Support**: Tambahkan pengujian parameter POST (form data, JSON)
- [ ] **More Payloads**: Perbanyak varian payload untuk setiap kerentanan (min 20 per tipe)
- [ ] **Custom Headers**: Dukungan untuk custom headers (Authorization, Cookie, X-Forwarded-For)
- [ ] **Better WAF Bypass**: Tambahkan teknik bypass WAF (encoding, comments, polyglot)
- [ ] **Improved Open Redirect Detection**: Fix false positive dengan mempertimbangkan subdomain dan domain induk

### 2. **Jangka Menengah**
- [ ] **SQL Injection Scanner**: Implementasi deteksi SQLi (error-based, time-based, boolean-based)
- [ ] **SSTI (Server-Side Template Injection)**: Deteksi template injection untuk berbagai engine
- [ ] **Command Injection**: Pengujian command injection dengan berbagai teknik
- [ ] **GraphQL Support**: Deteksi kerentanan pada GraphQL endpoints (introspection, injection)
- [ ] **WebSocket Testing**: Pengujian kerentanan pada koneksi WebSocket
- [ ] **Crawler Integration**: Integrasi dengan crawler untuk menemukan lebih banyak endpoint

### 3. **Jangka Panjang**
- [ ] **Headless Browser Integration**: Gunakan Selenium/Playwright untuk XSS DOM dan client-side testing
- [ ] **Machine Learning**: Implementasi ML untuk memprediksi false positive berdasarkan pattern
- [ ] **Distributed Scanning**: Dukungan untuk distributed/cloud scanning dengan message queue
- [ ] **Plugin System**: Arsitektur plugin modular untuk kerentanan kustom
- [ ] **CI/CD Integration**: Integrasi dengan pipeline CI/CD (GitHub Actions, GitLab CI)
- [ ] **Vulnerability Database**: Update otomatis dari CVE dan bug bounty writeups

### 4. **Improvement Ideas**
- [ ] **Wordlist Customization**: Kemampuan menggunakan wordlist kustom dari file
- [ ] **Recursive Scanning**: Scanning recursive pada endpoint yang ditemukan (depth configurable)
- [ ] **Session Management**: Manajemen session untuk authenticated testing (login form support)
- [ ] **Rate Limit Auto-adjust**: Adaptive rate limiting berdasarkan respons server (429, 503)
- [ ] **Output Diff**: Perbandingan hasil scan sebelumnya untuk regression testing
- [ ] **Proxy Support**: Dukungan untuk proxy (Burp, ZAP) untuk intercept dan replay
- [ ] **Timeout Handling**: Lebih baik dalam menangani timeout dan slow responses

---

## 📦 Requirements

### System Requirements
- Python 3.7 atau lebih baru (direkomendasikan Python 3.9+)
- Pip (Python package manager) versi terbaru
- Koneksi internet stabil (min 1 Mbps)
- RAM minimal 512MB (recommended 1GB+ untuk 20 threads)
- Storage minimal 100MB untuk logs dan output

### Python Dependencies

Buat file `requirements.txt` dengan konten berikut:

```txt
# Core Dependencies
requests>=2.31.0          # HTTP requests dengan session handling
urllib3>=2.0.0            # HTTP connection pooling

# Networking
dnspython>=2.4.0          # DNS resolution (A, AAAA records)

# Output Formatting
colorama>=0.4.6           # Cross-platform colored terminal output

# Data Processing
python-dateutil>=2.8.2    # Advanced date parsing
statistics>=1.0.3.5       # Statistical calculations (mean, median)

# Type Hints (optional for development)
typing-extensions>=4.5.0  # Backport of typing features

# Hashing
hashlib>=20081121         # Built-in, but ensure latest
```

### Install Dependencies

```bash
# Via pip dengan requirements file
pip install -r requirements.txt

# Atau install manual satu per satu
pip install requests urllib3 dnspython colorama python-dateutil

# Untuk pengembangan (optional)
pip install typing-extensions
```

### Optional Tools untuk Verifikasi Manual
- `curl`: Untuk verifikasi manual temuan (wajib)
- `jq`: Untuk memproses JSON output di terminal (optional)
- `screen`/`tmux`: Untuk menjalankan scan panjang di background (recommended)
- `firefox`/`chrome`: Untuk verifikasi XSS di browser (wajib)
- `burpsuite`: Untuk intercept dan replay request (optional)

---

## 🚀 Cara Penggunaan

### 1. **Basic Usage**

```bash
# Scan dasar dengan target (akan otomatis tambahkan https://)
python3 awam.py -t example.com

# Dengan rate limit lebih rendah (untuk menghindari blocking)
python3 awam.py -t example.com -r 2

# Dengan verbose output untuk debugging
python3 awam.py -t example.com -v
```

### 2. **Advanced Usage**

```bash
# Dengan scope tambahan (subdomain dan domain terkait)
python3 awam.py -t example.com --scope "api.example.com,dev.example.com,staging.example.com"

# Dengan user-agent kustom (untuk menghindari deteksi)
python3 awam.py -t example.com -u "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Kombinasi semua opsi untuk scan optimal
python3 awam.py -t example.com -r 3 -T 15 -v --scope "*.example.com"
```

### 3. **Command Line Options**

| Opsi | Deskripsi | Default | Contoh |
|------|-----------|---------|--------|
| `-t, --target` | Target domain (required) | - | `-t example.com` |
| `-r, --rate` | Max requests per second | 3 | `-r 5` (lebih cepat) |
| `-T, --threads` | Number of threads (max 20) | 10 | `-T 20` (maksimum) |
| `-u, --user-agent` | Custom User-Agent string | Random | `-u "CustomBot/1.0"` |
| `-v, --verbose` | Enable verbose output | False | `-v` (aktifkan) |
| `--scope` | Additional domains in scope | - | `--scope "api.com,dev.com"` |
| `-h, --help` | Show help message | - | `-h` |

### 4. **Contoh Skenario Penggunaan**

#### **Skenario 1: Quick Recon (15 menit)**
```bash
python3 awam.py -t target.com -r 10 -T 20
```
**Tujuan**: Mendapatkan gambaran cepat tentang permukaan serangan target.
**Hasil**: Subdomain, endpoint umum, dan potensi kerentanan low-hanging fruit.

#### **Skenario 2: Deep Scan (1-2 jam)**
```bash
python3 awam.py -t target.com -r 2 -T 5 -v --scope "*.target.com"
```
**Tujuan**: Scanning mendalam dengan rate rendah untuk menghindari deteksi.
**Hasil**: Semua potensi kerentanan dengan false positive minimal, lengkap dengan logs.

#### **Skenario 3: Bug Bounty Specific**
```bash
python3 awam.py -t target.com -r 3 -T 10 -v --scope "*.target.com,*.stage.target.com"
```
**Tujuan**: Scan sesuai scope bug bounty program.
**Hasil**: Laporan lengkap dengan CURL commands untuk setiap temuan.

#### **Skenario 4: Night Scan (Background)**
```bash
screen -S awam-scan
python3 awam.py -t target.com -r 2 -T 8 -v > scan_output.log 2>&1
# CTRL+A+D untuk detach
```
**Tujuan**: Menjalankan scan panjang di background semalaman.
**Hasil**: Output tersimpan di file log untuk dianalisis pagi hari.

---

## 📊 Menindaklanjuti Output

### 1. **Memahami Output**

AWAM menghasilkan 3 file output di direktori yang sama:

#### **awam_results.json** - Format utama untuk analisis programatik
```json
{
  "vulnerabilities": [
    {
      "type": "Open Redirect",
      "target": "https://target.com/robots.txt?id=//evil.com",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "confidence_score": 65.0,
      "curl": "curl -k -X GET 'https://target.com/robots.txt?id=//evil.com'",
      "poe_verified": true
    }
  ]
}
```

#### **awam_results.txt** - Format human-readable untuk laporan
```
================================================================================
                         AWAM - BUG BOUNTY SCAN RESULTS                         
================================================================================
Scan Time: 2026-02-16 15:51:16
Duration: 0:04:00

SCAN STATISTICS:
----------------------------------------
Requests Made: 374
Vulnerabilities Found: 20
False Positives Caught: 0
Detection Accuracy: 100.0%

VULNERABILITIES BY SEVERITY:
----------------------------------------
CRITICAL: 0
HIGH: 0
MEDIUM: 20
LOW: 0
```

#### **awam_log.txt** - Detailed logging untuk debugging
```
[15:51:20] [INFO] Target in scope: example.com
[15:52:22] [DEBUG] GET https://example.com/robots.txt?id=//evil.com -> 301
[15:52:22] [VULN] [!] Open Redirect on https://example.com/robots.txt?id=//evil.com
[15:52:22] [DEBUG] Reproduction: curl -k -X GET 'https://example.com/robots.txt?id=//evil.com'
```

### 2. **Workflow Verifikasi Manual (WAJIB!)**

> ⚠️ **Peringatan**: Semua temuan dari automated tool WAJIB diverifikasi manual. Jangan pernah melaporkan temuan tanpa verifikasi manual!

#### **Langkah 1: Prioritaskan Temuan**
- Urutkan berdasarkan severity (Critical → High → Medium → Low)
- Prioritaskan dengan confidence tinggi (>80%)
- Perhatikan temuan dengan PoE Verified sebagai indikasi awal

#### **Langkah 2: Verifikasi Manual dengan CURL**

**Untuk Open Redirect:**
```bash
# Gunakan curl persis seperti yang diberikan tool
curl -k -v -X GET 'https://target.com/robots.txt?id=//evil.com'

# Perhatikan output, terutama bagian:
< HTTP/2 301
< location: [cek ini!]

# Interpretasi hasil:
# ❌ Jika location = https://www.target.com/... → FALSE POSITIVE (redirect internal)
# ✅ Jika location = https://evil.com atau //evil.com → VALID (redirect eksternal)
# ✅ Jika location = https://evil.com@target.com → VALID (bypass attempt)
```

**Contoh Verifikasi REAL dari log:**
```bash
$ curl -k -v -X GET 'https://halodoc.com/robots.txt?id=//evil.com'
...
< HTTP/2 301
< location: https://www.halodoc.com/robots.txt   # ← INI FALSE POSITIVE!
...
```
**Kesimpulan**: Redirect ke domain sendiri (`www.halodoc.com`), BUKAN ke evil.com. Temuan TIDAK VALID.

**Untuk XSS:**
```bash
# Gunakan curl untuk lihat refleksi payload
curl -k -v 'https://target.com/page?q=%3Cscript%3Ealert(1)%3C/script%3E'

# Cek apakah payload muncul di respons
# Jika ya, verifikasi di browser
firefox 'https://target.com/page?q=%3Cscript%3Ealert(1)%3C/script%3E'

# Interpretasi:
# ❌ Jika payload muncul sebagai teks biasa (encoded) → FALSE POSITIVE
# ✅ Jika alert box muncul → VALID
# ✅ Jika payload muncul di dalam tag script/event → VALID (critical)
```

**Untuk LFI:**
```bash
# Coba baca file sensitif
curl -k -v 'https://target.com/page?file=../../../../etc/passwd'

# Periksa respons
# ❌ Jika halaman error 404/500 → FALSE POSITIVE
# ❌ Jika "Index of /" → Directory listing, BUKAN LFI
# ✅ Jika ada "root:x:0:0" → VALID (file inclusion)
```

#### **Langkah 3: Dokumentasi Temuan Valid**

Untuk setiap temuan yang TERBUKTI VALID, dokumentasikan:

```
## VULNERABILITY: [Type]
- **URL**: [Lengkap dengan payload]
- **Parameter**: [Parameter yang rentan]
- **Payload**: [Payload yang digunakan]

## VERIFICATION STEPS:
1. Jalankan perintah:
   ```bash
   curl -k -v -X GET 'URL_LENGKAP'
   ```
2. Output yang membuktikan kerentanan:
   ```
   [Tempel output relevan]
   ```
3. Screenshot (jika ada):
   [Sertakan screenshot]

## IMPACT:
[Jelaskan dampak jika dieksploitasi]

## CURL COMMAND FOR REPRODUCTION:
```bash
[Perintah curl lengkap]
```
```

#### **Langkah 4: Pelaporan ke Bug Bounty Program**

**Gunakan template berikut:**

```
# [Severity] [Vulnerability Type] on [Endpoint]

## Description
[Deskripsi singkat tentang kerentanan]

## Affected Endpoint
`https://target.com/path?param=value`

## Payload Used
`[payload]`

## Steps to Reproduce
1. Jalankan curl command:
   ```bash
   curl -k -v -X GET 'https://target.com/path?param=payload'
   ```
2. Amati respons:
   ```
   [Tempel respons]
   ```
3. [Langkah tambahan jika perlu]

## Proof of Concept
[URL lengkap dengan payload]
[Screenshot jika memungkinkan]

## Impact
[Penjelasan dampak]

## Remediation Suggestion
[Saran perbaikan]

## Additional Information
- Tool yang digunakan: AWAM v2.0.0
- Confidence: [High/Medium]
- Date found: [Tanggal]
```

#### **⚠️ PENTING: Contoh False Positive dari AWAM**

Berdasarkan pengujian nyata, berikut contoh false positive yang perlu diwaspadai:

**Tool AWAM Melaporkan:**
```
[15:52:22] [VULN] [!] Open Redirect on https://halodoc.com/robots.txt?id=//evil.com [MEDIUM]
[15:52:22] [POE]     ✓ PoE Verified
```

**Verifikasi Manual:**
```bash
curl -k -v -X GET 'https://halodoc.com/robots.txt?id=//evil.com'
# Respons:
< HTTP/2 301
< location: https://www.halodoc.com/robots.txt  # ← Redirect ke domain sendiri!
```

**Kesimpulan**: **FALSE POSITIVE**. Tool salah mengartikan redirect ke `www.halodoc.com` sebagai open redirect karena perbedaan netloc, padahal itu adalah canonical redirect yang sah.

**Pelajaran**: Jangan percaya label "PoE Verified" dari tool. Selalu verifikasi manual dengan melihat **isi** Location header, bukan hanya status code!

---

## ⚖️ Kebijakan Penggunaan

### 1. **Legal Disclaimer**

```
================================================================================
LEGAL DISCLAIMER AND WARNING
================================================================================

This tool is for authorized security testing and educational purposes ONLY.

By using this tool, you agree to:
1. ONLY test systems you own or have explicit written permission to test
2. Comply with all applicable laws and regulations
3. Respect bug bounty program scope and rules
4. Report findings responsibly through official channels
5. NOT use this tool for any illegal or unauthorized activities
6. Verify ALL findings manually before reporting
7. Accept full responsibility for your actions

UNAUTHORIZED USE IS STRICTLY PROHIBITED AND MAY RESULT IN:
- Criminal prosecution
- Civil liability
- Permanent ban from bug bounty programs
- Legal action from affected parties

Always verify scope and obtain proper authorization before testing.
================================================================================
```

### 2. **Etika Penggunaan**

#### **WAJIB (DO's):**
✅ Dapatkan izin tertulis SEBELUM testing  
✅ Patuhi scope dan rules of engagement bug bounty program  
✅ Laporkan temuan melalui official channels dengan sopan  
✅ Hentikan testing jika menyebabkan gangguan pada layanan  
✅ Hormati rate limit dan robots.txt  
✅ Verifikasi MANUAL semua temuan sebelum melaporkan  
✅ Dokumentasikan dengan jelas langkah reproduksi  
✅ Bersikap profesional dan kooperatif dengan tim security  

#### **DILARANG (DON'Ts):**
❌ Jangan testing tanpa izin (anggap ilegal)  
❌ Jangan eksploitasi lebih dari yang diperlukan untuk PoC  
❌ Jangan publikasikan data sensitif yang ditemukan  
❌ Jangan gunakan untuk extortion atau blackmail  
❌ Jangan merusak, mengubah, atau menghapus data  
❌ Jangan melaporkan temuan tanpa verifikasi manual  
❌ Jangan exaggerate severity untuk mendapatkan bounty lebih besar  
❌ Jangan share vulnerability details ke publik sebelum fix  

### 3. **Tanggung Jawab Pengguna**

Pengguna bertanggung jawab penuh atas:
- **Kepatuhan hukum**: Semua hukum lokal, nasional, dan internasional yang berlaku
- **Kepatuhan program**: Semua kebijakan dan scope program bug bounty
- **Konsekuensi**: Segala akibat dari penggunaan tool ini, termasuk namun tidak terbatas pada tuntutan hukum
- **Verifikasi**: Kebenaran semua temuan sebelum dilaporkan
- **Kerahasiaan**: Menjaga kerahasiaan data dan informasi yang ditemukan
- **Integritas**: Menjaga integritas sistem yang diuji

---

## 📚 Referensi

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Research](https://portswigger.net/research)
- [Bug Bounty Methodology](https://github.com/EdOverflow/bugbounty-cheatsheet)

---

**Dibuat dengan ❤️ untuk komunitas bug bounty Indonesia dan dunia**

---
*"Trust, but verify." - Setiap temuan automated tool harus diverifikasi manual.*
