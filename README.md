# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Emergency Mitigation Kit for PHP 7.x

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CVSS: 9.2 Critical](https://img.shields.io/badge/CVSS%20v4.0-9.2%20CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Affected: PHP 5.4 - 8.5](https://img.shields.io/badge/Affected-PHP%205.4%20to%208.5-orange.svg)](#threat-summary)
[![Target: PHP 7.0 - 7.4](https://img.shields.io/badge/Focus-PHP%207.x%20Legacy%20Workaround-blue.svg)](#why-php-7)

An open-source defense-in-depth mitigation kit and emergency action plan for systems running **PHP 7.0, 7.1, 7.2, 7.3, and 7.4** affected by the October 2026 **PHP2Shell** remote code execution vulnerabilities.

---

## ⚡ 60-Second Emergency Hotfix

If you are on shared hosting or running PHP-FPM, apply this **immediately**:

### Option A: Shared Hosting / cPanel (`.user.ini`)
Drop a `.user.ini` file into your website's root directory (`public_html`):
```ini
session.upload_progress.enabled = 0
session.upload_progress.cleanup = 1
```

### Option B: Apache Web Server (`.htaccess`)
Add this virtual patch to the top of your `.htaccess` file:
```apache
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{QUERY_STRING} (PHP_SESSION_UPLOAD_PROGRESS) [NC,OR]
  RewriteCond %{THE_REQUEST} (PHP_SESSION_UPLOAD_PROGRESS) [NC]
  RewriteRule .* - [F,L]
</IfModule>

<IfModule mod_php7.c>
  php_flag session.upload_progress.enabled Off
</IfModule>
```

### Option C: Global Server (`php.ini` / `/etc/php/7.4/fpm/php.ini`)
Open your global `php.ini` or `/etc/php/7.4/fpm/php.ini` and set:
```ini
session.upload_progress.enabled = 0
```
Then restart your PHP-FPM or Apache service:
```bash
sudo systemctl restart php7.4-fpm
# or
sudo systemctl restart apache2
# or on cPanel / CentOS:
/scripts/restartsrv_apache
```

> **⚠️ Critical Warning:** Do NOT attempt to fix this with `ini_set('session.upload_progress.enabled', 0)` inside your application's PHP scripts (e.g. `index.php`). The PHP core runtime processes multipart request headers and upload progress *before* userland PHP scripts are parsed and executed. The directive **must** be set at the server, `.user.ini`, or pool level.

---

## 🔍 Threat Summary: What is PHP2Shell?

Disclosed in October 2026, **PHP2Shell** consists of two interconnected critical flaws:
* **CVE-2026-109618 (Heap Memory Corruption):** Triggered during Out-Of-Memory (OOM) fatal runtime conditions while the PHP core interpreter parses multipart form requests.
* **CVE-2026-109619 (Use-After-Free in Upload Progress):** A Use-After-Free condition in the PHP core's `session.upload_progress` tracking engine. An unauthenticated attacker sends crafted multipart POST requests targeting `PHP_SESSION_UPLOAD_PROGRESS` to manipulate memory allocations and achieve arbitrary Remote Code Execution (RCE) with the privileges of the web server (`www-data`, `nobody`, etc.).

### Why PHP 7 is in Danger
Official patches were released by the PHP Group only for supported active branches:
* PHP 8.5.12+
* PHP 8.4.27+
* PHP 8.3.36+
* PHP 8.2.35+

Because **PHP 7 has reached End-of-Life (EOL)**, no standard upstream binary updates exist on `php.net`. However, millions of legacy production applications cannot be rewritten overnight. This toolkit provides the exact stopgaps, WAF virtual patches, and migration paths needed to secure PHP 7 systems.

---

## 📦 Repository Contents

```text
├── configs/
│   ├── .user.ini                   # Drop-in config for cPanel / FastCGI / PHP-FPM
│   ├── apache-.htaccess            # Apache mod_rewrite / mod_php virtual patch
│   ├── nginx-php2shell.conf        # Nginx reverse-proxy / FastCGI block
│   ├── php-security.ini            # Server-wide php.ini hardening snippet
│   ├── modsecurity-php2shell.conf  # ModSecurity WAF rule definition
│   └── cloudflare-waf-rule.txt     # Cloudflare Custom Firewall expression
├── scripts/
│   ├── audit_php2shell.php         # CLI and Web vulnerability audit scanner
│   └── apply_mitigation.sh         # Linux automated hardening script
├── LICENSE                         # MIT License
└── README.md                       # Comprehensive Guide & Implementation Plan
```

---

## 🧪 Diagnostic Scanner: `audit_php2shell.php`

This repository includes a diagnostic scanner you can run to test your live server:

### Via Terminal (CLI):
```bash
php scripts/audit_php2shell.php
```
Sample Output:
```text
====================================================================
  PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Audit Scanner
====================================================================
PHP Version        : 7.4.33 (PHP7_EOL)
Server SAPI        : fpm-fcgi
Operating System   : Linux
Upload Progress    : DISABLED (MITIGATED)
Upload Cleanup     : Enabled
File Uploads       : On
Memory Limit       : 256M
User INI Support   : .user.ini
--------------------------------------------------------------------
OVERALL STATUS     : [MITIGATED]
[+] MITIGATED: session.upload_progress.enabled is DISABLED.
    The primary PHP2Shell exploit loop is blocked. Plan upgrade to PHP 8.2+.
====================================================================
```

### Via Browser:
Upload `scripts/audit_php2shell.php` to your web root, access it at `https://your-domain.com/audit_php2shell.php`, inspect the visual report, and **delete it immediately** once verified.

---

## 🛡️ Multi-Layer Defense Matrix

| Layer | Technique | Protection Scope | Implementation |
| :--- | :--- | :--- | :--- |
| **Layer 1: Runtime** | Disable `session.upload_progress.enabled` | Neutralizes CVE-2026-109619 UAF trigger | `.user.ini` or `php.ini` |
| **Layer 2: Web Server** | Rewrite / Reject `PHP_SESSION_UPLOAD_PROGRESS` | Blocks exploit payloads before reaching PHP | `.htaccess` (Apache) or `nginx.conf` |
| **Layer 3: Edge WAF** | Drop malformed multipart headers | Stops probes at Cloudflare / CDN edge | WAF Firewall Rules |
| **Layer 4: OS Backport** | Install vendor enterprise patch | Replaces vulnerable C binary entirely | cPanel EA4 / CloudLinux / Ubuntu Pro |
| **Layer 5: Upgrade** | Migrate to PHP 8.2+ / 8.3+ | Permanent structural resolution | Codebase modernization |

---

## 🏢 Vendor Backports for PHP 7.4

If your server runs an enterprise Linux distribution or managed hosting control panel, check if a vendor security backport is available:

### 1. cPanel / CloudLinux (EasyApache 4)
cPanel has released security backports for `ea-php74` (version `7.4.33-19` or higher):
```bash
yum update ea-php74* -y
# or on AlmaLinux/RockyLinux 8/9:
dnf update ea-php74* -y
/scripts/restartsrv_apache
```

### 2. Ubuntu Pro (Extended Security Maintenance - ESM)
If using Ubuntu 18.04 or 20.04 with Ubuntu Pro:
```bash
sudo pro enable esm-apps
sudo apt update && sudo apt install --only-upgrade php7.4-fpm php7.4-cli
```

### 3. TuxCare / CloudLinux Extended Lifecycle Support (ELS)
If subscribed to TuxCare ELS:
```bash
yum update -y
systemctl restart php-fpm
```

---

## 🚀 Migration Roadmap: Moving from PHP 7.4 to PHP 8.2+

While configuration mitigations close the primary exploit vectors, long-term security requires upgrading to an actively maintained PHP release (PHP 8.2.35+ or 8.3.36+).

### Step 1: Compatibility Audit with Rector / PHPCompatibility
Run `phpcompatibility` via Composer to identify deprecated syntax in your code:
```bash
composer require --dev dealerdirect/phpcodesniffer-composer-installer
composer require --dev phpcompatibility/php-compatibility
./vendor/bin/phpcs -p . --standard=PHPCompatibility --runtime-set testVersion 8.2
```

### Step 2: Key Breaking Changes from PHP 7.4 to 8.2+
* **Fatal Error on Uncaught Type Exceptions:** PHP 8 treats internal parameter type mismatches as `TypeError` exceptions instead of notices/warnings.
* **Non-existent Array Keys:** Accessing undefined array keys triggers a notice/warning (`$row['undefined']`); use `$row['key'] ?? null`.
* **Countable:** Calling `count()` on non-countable types throws `TypeError`.
* **Curly Brace Array Indexing:** Deprecated `$arr{0}` is removed; replace with `$arr[0]`.
* **MySQL Extensions:** Ensure all database operations use `mysqli_*` or `PDO` with prepared statements.

---

## 🤝 Contributing

Contributions to improve WAF rules, test across edge hosting environments (LiteSpeed, OpenLiteSpeed, IIS, Docker), and provide backport recipes are welcome!
1. Fork this repository.
2. Create your feature branch (`git checkout -b feat/litespeed-mitigation`).
3. Commit your changes (`git commit -m 'Add LiteSpeed configuration rules'`).
4. Push to your branch (`git push origin feat/litespeed-mitigation`).
5. Open a Pull Request.

---

## 📄 License

This mitigation kit is distributed under the [MIT License](LICENSE).
