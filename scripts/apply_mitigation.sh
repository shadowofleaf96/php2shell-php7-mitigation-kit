#!/usr/bin/env bash
# ====================================================================
# PHP2Shell (CVE-2026-109618 & CVE-2026-109619) Automated Mitigation Script
# Target: Linux / cPanel / Apache / Nginx / PHP-FPM environments
# ====================================================================

set -e

echo "===================================================================="
echo "  Applying PHP2Shell Mitigation (Disabling session.upload_progress)"
echo "===================================================================="

# 1. Detect and patch global php.ini files
echo "[*] Searching for PHP 7.x php.ini files..."
INI_FILES=$(find /etc/php* -name "php.ini" 2>/dev/null || true)

for ini in $INI_FILES; do
    echo "    Found: $ini"
    if grep -q "session.upload_progress.enabled" "$ini"; then
        sed -i 's/^[; ]*session.upload_progress.enabled\s*=.*/session.upload_progress.enabled = 0/' "$ini"
    else
        echo -e "\n; PHP2Shell Emergency Mitigation\nsession.upload_progress.enabled = 0\nsession.upload_progress.cleanup = 1" >> "$ini"
    fi
    echo "    [+] Updated $ini"
done

# 2. Add drop-in INI for Ubuntu/Debian mods-available across PHP 7.x branches
for ver in 7.0 7.1 7.2 7.3 7.4; do
    if [ -d "/etc/php/$ver/mods-available" ]; then
        echo "[*] Creating Ubuntu/Debian mods-available drop-in for PHP $ver..."
        cat << 'EOF' > "/etc/php/$ver/mods-available/php2shell-hardening.ini"
; PHP2Shell Emergency Mitigation
session.upload_progress.enabled = 0
session.upload_progress.cleanup = 1
EOF
        phpenmod -v "$ver" php2shell-hardening 2>/dev/null || true
        echo "    [+] Enabled php2shell-hardening module for PHP $ver"
    fi
done

if [ -d "/etc/php.d" ]; then
    echo "[*] Creating RHEL/CentOS php.d drop-in..."
    cat << 'EOF' > /etc/php.d/99-php2shell.ini
; PHP2Shell Emergency Mitigation
session.upload_progress.enabled = 0
session.upload_progress.cleanup = 1
EOF
    echo "    [+] Created /etc/php.d/99-php2shell.ini"
fi

# 3. Create .user.ini in current directory if needed
if [ ! -f ".user.ini" ]; then
    echo "[*] Creating .user.ini in current directory..."
    cat << 'EOF' > .user.ini
; PHP2Shell Emergency Mitigation
session.upload_progress.enabled = 0
session.upload_progress.cleanup = 1
EOF
    echo "    [+] Created .user.ini"
else
    if ! grep -q "session.upload_progress.enabled" .user.ini; then
        echo -e "\n; PHP2Shell Emergency Mitigation\nsession.upload_progress.enabled = 0\nsession.upload_progress.cleanup = 1" >> .user.ini
        echo "    [+] Appended mitigation to existing .user.ini"
    fi
fi

# 4. Prompt / Restart services
echo "[*] Restarting PHP-FPM / Web services..."
for ver in 7.0 7.1 7.2 7.3 7.4; do
    if systemctl is-active --quiet "php${ver}-fpm" 2>/dev/null; then
        systemctl restart "php${ver}-fpm" && echo "    [+] Restarted php${ver}-fpm"
    fi
done
if systemctl is-active --quiet apache2 2>/dev/null; then
    systemctl restart apache2 && echo "    [+] Restarted apache2"
fi
if systemctl is-active --quiet httpd 2>/dev/null; then
    systemctl restart httpd && echo "    [+] Restarted httpd"
fi
if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx && echo "    [+] Reloaded nginx"
fi
if [ -x "/scripts/restartsrv_apache" ]; then
    /scripts/restartsrv_apache && echo "    [+] Restarted cPanel Apache"
fi

echo "===================================================================="
echo "  Mitigation Applied Successfully!"
echo "  Run 'php audit_php2shell.php' to verify the runtime configuration."
echo "===================================================================="
