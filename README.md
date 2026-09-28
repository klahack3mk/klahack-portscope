# klahack-portscope

**Portable TCP connect scanning by klahack · فحص محمول لمنافذ TCP من تطوير klahack**

[![Build](https://github.com/klahack/klahack-portscope/actions/workflows/build.yml/badge.svg)](https://github.com/klahack/klahack-portscope/actions/workflows/build.yml)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776ab)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-0b7285.svg)](LICENSE)
[![Runtime dependencies: zero](https://img.shields.io/badge/runtime%20dependencies-zero-198754)](klahack_portscope.py)

[English](#english) · [العربية](#العربية)

---

## English

`klahack-portscope` is a transparent command-line TCP port scanner for defensive audits of systems you own or are explicitly authorized to test. It uses one Python 3.8+ file and only the standard library, so the same source runs on Linux, Termux, macOS, Windows Terminal, and PowerShell.

> **Legal warning:** Scan only networks you own or have explicit written permission to test. You are responsible for complying with applicable law, contracts, and organizational policy. The tool intentionally provides no stealth, spoofing, raw-packet, evasion, or exploitation features.

### Features

- One auditable `klahack_portscope.py` file with zero runtime dependencies.
- IPv4 and IPv6 TCP connect scanning for IPs, hostnames, CIDRs, and comma-separated targets.
- Mixed port expressions, a built-in list of 100 prevalent ports, bounded worker threads, and optional throttling.
- Stable `open`, `closed`, and `filtered` state handling across POSIX and Windows socket error codes.
- Size-limited, terminal-safe banner collection with a simple HTTP fallback.
- Human-readable tables, JSON, and CSV; result data goes to stdout while branding, warnings, and progress go to stderr.
- Public-address authorization gate, bounded CIDR expansion, graceful Ctrl+C handling, and partial results.
- Automatic color safety for pipes, `NO_COLOR`, `TERM=dumb`, non-TTY output, and modern Windows terminals.

### Requirements

- Python **3.8 or newer**.
- No runtime `pip install` and no third-party Python package.
- TCP reachability to the explicitly authorized targets.

### Installation

The installers are idempotent, verify the downloaded scanner against `SHA256SUMS`, and install under the command name `klahack-portscope`.

#### Linux / Termux / macOS

```sh
curl -fsSL https://raw.githubusercontent.com/klahack/klahack-portscope/main/install.sh | bash
```

The installer uses `$PREFIX/bin` on Termux, `/usr/local/bin` where available, or `~/.local/bin` when `sudo` is unavailable.

#### Windows PowerShell

```powershell
irm https://raw.githubusercontent.com/klahack/klahack-portscope/main/install.ps1 | iex
```

Installation is per-user under `%LOCALAPPDATA%\klahack-portscope`; no Administrator privileges are needed. Open a new terminal after installation.

#### Safest installation method

Piping is convenient, but the safest workflow is:

1. Download `install.sh` or `install.ps1` and `SHA256SUMS` from this repository.
2. Inspect the entire installer.
3. Download `klahack_portscope.py` and verify its SHA256 digest against `SHA256SUMS`.
4. Run the inspected installer only after verification succeeds.

For a direct source run:

```sh
python3 klahack_portscope.py --version
python3 klahack_portscope.py -t 127.0.0.1 -p 22,80,443
```

### Usage

```text
klahack-portscope -t TARGET (-p PORTS | --top-ports N) [options]
```

Every invocation prints a compact brand banner to stderr unless `--quiet` is supplied. The responsible-use warning is always printed, including in quiet mode.

| Option | Description |
|---|---|
| `-t`, `--target TARGET` | IP, hostname, CIDR, or comma-separated targets. |
| `-p`, `--ports PORTS` | Mixed ports/ranges such as `22,80,443,8000-8100`; deduplicated and sorted. |
| `--top-ports N` | Scan the first `N` ports from the built-in prevalence list (`1` to `100`). |
| `--timeout SECONDS` | Per-socket timeout; default `1.0`. |
| `--threads N` | Worker count; default `100`, maximum `1000`. |
| `--delay SECONDS` | Delay between task submissions for throttling; default `0`. |
| `-4` / `-6` | Force IPv4 or IPv6; otherwise both are resolved with `getaddrinfo`. |
| `--banner` | Passively read up to 256 bytes; try a basic HTTP `HEAD` request when appropriate. |
| `--json` / `--csv` | Select machine-readable output. |
| `--output FILE` | Write selected output to a file instead of stdout. |
| `--quiet` | Suppress the ASCII brand banner and progress; the legal warning remains. |
| `--verbose` | Include open, closed, and filtered result rows. |
| `--open-only` | Include only open result rows. |
| `--no-color` | Disable ANSI result colors. |
| `--no-progress` | Disable progress output. |
| `--max-hosts N` | Limit expanded/resolved hosts; default `256`. |
| `--i-have-permission` | Confirm authorization for public targets in non-interactive use. |
| `--version` | Print `klahack-portscope 1.0.0 by klahack`. |
| `-h`, `--help` | Show command help. |

`--ports` and `--top-ports` are mutually exclusive. So are `-4`/`-6`, `--json`/`--csv`, and `--verbose`/`--open-only`.

### Examples

Scan selected loopback ports:

```sh
klahack-portscope -t 127.0.0.1 -p 22,80,443,8000-8010
```

Scan the 20 most prevalent ports on locally resolved `localhost` and emit JSON:

```sh
klahack-portscope -t localhost --top-ports 20 --json
```

Throttle an authorized private-network scan and save CSV:

```sh
klahack-portscope -t 192.168.1.0/24 -p 22,80,443 --delay 0.05 --csv --output audit.csv
```

A non-interactive scan containing any public address is refused unless authorization is asserted explicitly:

```sh
klahack-portscope -t 203.0.113.10 -p 443 --i-have-permission
```

The flag is an authorization confirmation, not a substitute for actual written permission.

### Sample terminal output

By default, open and filtered rows are shown; closed ports are still counted in the summary. Use `--verbose` to show every state.

```text
Target: 127.0.0.1 (127.0.0.1)
PORT   STATE      SERVICE          BANNER
-----  ---------  ---------------  ------
22     open       ssh              SSH-2.0-OpenSSH
443    filtered   https

Summary: open=1 closed=1 filtered=1 scanned=3 duration=1.008s
```

### JSON schema

JSON always contains tool identity, timestamps, duration, grouped targets, and a summary. Result visibility follows the default, `--verbose`, or `--open-only` mode; summary counts cover every completed attempt.

```json
{
  "tool": "klahack-portscope",
  "author": "klahack",
  "version": "1.0.0",
  "started_at": "2026-01-01T12:00:00.000Z",
  "finished_at": "2026-01-01T12:00:01.008Z",
  "duration_s": 1.008,
  "targets": [
    {
      "host": "127.0.0.1",
      "ip": "127.0.0.1",
      "results": [
        {
          "port": 22,
          "state": "open",
          "service": "ssh",
          "banner": "SSH-2.0-OpenSSH"
        }
      ]
    }
  ],
  "summary": {
    "open": 1,
    "closed": 1,
    "filtered": 1
  }
}
```

CSV columns are exactly:

```text
host,ip,port,protocol,state,service,banner
```

### How it works

The scanner performs a full TCP **connect scan** through the operating system's normal socket API. It does not craft raw packets.

- **open** — the TCP connection succeeded.
- **closed** — the connection was refused (`ECONNREFUSED` or Windows `WSAECONNREFUSED` 10061), so the host responded.
- **filtered** — the attempt timed out, had no route, or returned another non-refusal failure that cannot prove the port is closed.

Work is submitted to a `ThreadPoolExecutor` in bounded batches rather than materializing every host/port pair. Every socket is context-managed. Ctrl+C stops new work, waits for the small in-flight batch, emits completed partial results, and returns exit code 130.

For banner collection, the scanner first reads passively within the timeout. If no data arrives on a common HTTP port, it sends `HEAD / HTTP/1.0`. At most 256 bytes are decoded with replacement, then ANSI and control sequences are removed to prevent terminal injection.

### Authorization safeguard

Resolved addresses are checked with Python's `ipaddress` module. Private, loopback, and link-local targets proceed without an extra prompt. If any address falls outside those categories:

- an interactive terminal must answer `yes` to the explicit permission prompt; or
- non-interactive execution must include `--i-have-permission`.

Otherwise the command refuses to scan and returns exit code 2. `--max-hosts` also prevents accidental expansion of oversized ranges.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Scan completed successfully. |
| `1` | Runtime, filesystem, or unexpected socket error. |
| `2` | Invalid input or authorization not confirmed. |
| `130` | Interrupted with Ctrl+C; completed partial results are emitted when available. |

### Development and tests

The test suite uses `unittest` and binds only to `127.0.0.1`; it never scans an external network.

```sh
python -m unittest discover -s tests
```

CI runs Python 3.8 and 3.12 on Ubuntu, macOS, and Windows. Tagged releases also build standalone PyInstaller executables; PyInstaller is a build-time dependency only and is not used by the source distribution at runtime.

### Limitations

- TCP only; there is no UDP scanner.
- Connect scans complete the operating system TCP handshake; there is no SYN/raw-packet scan.
- Service names are port-based hints and banners are untrusted hints, not definitive service identification.
- Firewalls can make closed or unreachable ports appear filtered.
- DNS answers and local service databases can differ by operating system.
- This focused audit utility is **not a replacement for nmap** or a complete vulnerability assessment.

### Roadmap

- Additional deterministic report fixtures and output regression tests.
- Optional resumable scans without changing TCP connect semantics.
- More accessibility and localization improvements for the project page.

---

## العربية

`klahack-portscope` أداة سطر أوامر شفافة لفحص منافذ TCP في الأنظمة التي تملكها أو لديك تصريح صريح لاختبارها. تتكون من ملف Python واحد، وتستخدم المكتبة القياسية فقط، وتعمل بالشيفرة نفسها على Linux وTermux وmacOS وWindows Terminal وPowerShell.

> **تحذير قانوني:** افحص فقط الشبكات التي تملكها أو لديك إذن كتابي صريح لاختبارها. أنت مسؤول عن الالتزام بالقوانين والعقود وسياسات المؤسسة. لا تتضمن الأداة عمدًا أي ميزات للتخفي أو انتحال العناوين أو الحزم الخام أو المراوغة أو الاستغلال.

### المزايا

- ملف واحد قابل للتدقيق دون اعتماديات تشغيل خارجية.
- دعم IPv4 وIPv6 وعناوين IP وأسماء المضيفين ونطاقات CIDR والأهداف المفصولة بفواصل.
- صيغة مختلطة للمنافذ وقائمة مدمجة لأشهر 100 منفذ وعدد خيوط محدود وإبطاء اختياري.
- حالات ثابتة عبر الأنظمة: `open` و`closed` و`filtered`.
- جمع اختياري للافتة الخدمة بحد 256 بايت مع إزالة محارف التحكم وتسلسلات ANSI.
- جداول وJSON وCSV، مع فصل النتائج على stdout عن التنبيهات والتقدم على stderr.
- بوابة تصريح للأهداف العامة وحد أقصى لتوسيع الشبكات وإيقاف آمن عند Ctrl+C.

### المتطلبات والتثبيت

تحتاج إلى Python 3.8 أو أحدث، ولا تحتاج إلى `pip` أو أي حزمة تشغيل خارجية.

Linux أو Termux أو macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/klahack/klahack-portscope/main/install.sh | bash
```

Windows PowerShell دون صلاحيات المدير:

```powershell
irm https://raw.githubusercontent.com/klahack/klahack-portscope/main/install.ps1 | iex
```

افتح طرفية جديدة بعد التثبيت على Windows. يتحقق المثبّتان من بصمة SHA256 قبل تثبيت الماسح. والطريقة الأكثر أمانًا هي: تنزيل المثبّت و`SHA256SUMS`، ثم قراءة المثبّت كاملًا، ثم التحقق من البصمة، ثم التنفيذ.

### الخيارات

| الخيار | الوصف |
|---|---|
| `-t`, `--target` | عنوان IP أو اسم مضيف أو CIDR أو عدة أهداف مفصولة بفواصل. |
| `-p`, `--ports` | منافذ ومديات مثل `22,80,443,8000-8100`. |
| `--top-ports N` | أول N من قائمة أشهر 100 منفذ. |
| `--timeout` | مهلة المقبس بالثواني؛ الافتراضي 1.0. |
| `--threads` | عدد خيوط العمل؛ الافتراضي 100 والأقصى 1000. |
| `--delay` | تأخير بين إرسال المهام لتقليل السرعة. |
| `-4` / `-6` | فرض IPv4 أو IPv6. |
| `--banner` | جمع لافتة خدمة آمنة بحد أقصى 256 بايت. |
| `--json` / `--csv` | اختيار مخرجات قابلة للمعالجة آليًا. |
| `--output FILE` | كتابة النتائج في ملف. |
| `--quiet` | إخفاء الشعار والتقدم؛ يبقى التحذير القانوني ظاهرًا. |
| `--verbose` | عرض الحالات الثلاث كلها. |
| `--open-only` | عرض المنافذ المفتوحة فقط. |
| `--no-color` / `--no-progress` | تعطيل الألوان أو التقدم. |
| `--max-hosts` | الحد الأقصى للأهداف بعد التوسيع؛ الافتراضي 256. |
| `--i-have-permission` | تأكيد وجود تصريح للأهداف العامة في التشغيل غير التفاعلي. |
| `--version` | عرض اسم الأداة والإصدار والمطور. |

### أمثلة

```sh
klahack-portscope -t 127.0.0.1 -p 22,80,443
klahack-portscope -t localhost --top-ports 20 --json
klahack-portscope -t 192.168.1.0/24 -p 22,80,443 --delay 0.05 --csv --output audit.csv
```

افتراضيًا تظهر النتائج المفتوحة والمصفّاة، بينما يشمل الملخص جميع المحاولات المكتملة. استخدم `--verbose` لإظهار المنافذ المغلقة أيضًا.

### آلية العمل والحالات

تنفذ الأداة **TCP connect scan** عاديًا عبر واجهة المقابس في نظام التشغيل ولا تنشئ حزمًا خامًا:

- `open`: نجح اتصال TCP.
- `closed`: رفض المضيف الاتصال، ما يعني أنه استجاب.
- `filtered`: انتهت المهلة أو تعذر المسار أو لم يثبت فشل آخر أن المنفذ مغلق.

تُرسل المهام على دفعات محدودة إلى `ThreadPoolExecutor` لتجنب استهلاك الذاكرة عند ضرب عدد المضيفين في عدد المنافذ. عند ضغط Ctrl+C تتوقف المهام الجديدة وتظهر النتائج الجزئية المكتملة ويكون رمز الخروج 130.

### ضوابط التصريح

تسمح الأداة بالعناوين الخاصة والمحلية وعناوين link-local دون سؤال إضافي. إذا ظهر أي عنوان عام بعد تحليل الأسماء، فيلزم كتابة `yes` تفاعليًا، أو تمرير `--i-have-permission` في التشغيل غير التفاعلي. إذا لم يؤكد التصريح ترفض الأداة الفحص برمز 2. هذا التأكيد لا يحل محل الإذن الكتابي الفعلي.

### رموز الخروج

| الرمز | المعنى |
|---:|---|
| `0` | نجاح الفحص. |
| `1` | خطأ وقت التشغيل أو الملفات أو المقابس. |
| `2` | إدخال غير صالح أو عدم تأكيد التصريح. |
| `130` | إيقاف بواسطة Ctrl+C مع إظهار النتائج الجزئية المتاحة. |

### القيود

- لا يوجد فحص UDP.
- لا يوجد SYN scan أو حزم خام؛ اتصال TCP الكامل مقصود وشفاف.
- أسماء الخدمات واللافتات مؤشرات وليست إثباتًا لهوية الخدمة.
- قد تجعل الجدران النارية المنافذ المغلقة تبدو مصفّاة.
- الأداة ليست بديلًا عن nmap أو عن تقييم شامل للثغرات.

### خارطة طريق مختصرة

- توسيع اختبارات ثبات المخرجات.
- استئناف اختياري للفحوص دون تغيير طبيعة TCP connect.
- تحسينات إضافية لإتاحة الوصول والترجمة في صفحة المشروع.

## Security and license · الأمن والترخيص

See [SECURITY.md](SECURITY.md) for private vulnerability reporting through GitHub Security Advisories. Released under the [MIT License](LICENSE), copyright © 2026 klahack.
