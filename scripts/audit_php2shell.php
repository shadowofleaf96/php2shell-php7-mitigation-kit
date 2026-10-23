<?php
/**
 * PHP2Shell (CVE-2026-109618 & CVE-2026-109619) Vulnerability & Configuration Auditor
 * 
 * Works on CLI and Web environments.
 * Checks PHP version, runtime directives, and session upload progress status.
 */

$isCli = (php_sapi_name() === 'cli' || defined('STDIN'));

// Gather system information
$phpVersion = PHP_VERSION;
$phpMajorMinor = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$phpRelease = PHP_RELEASE_VERSION;
$sapi = php_sapi_name();
$os = PHP_OS;

// Directives
$uploadProgressEnabled = (bool)ini_get('session.upload_progress.enabled');
$uploadProgressCleanup = (bool)ini_get('session.upload_progress.cleanup');
$uploadProgressName = ini_get('session.upload_progress.name');
$fileUploads = (bool)ini_get('file_uploads');
$memoryLimit = ini_get('memory_limit');
$postMaxSize = ini_get('post_max_size');
$uploadMaxFilesize = ini_get('upload_max_filesize');
$userIniFilename = ini_get('user_ini.filename');

// Vulnerability evaluation
$isPatchedCore = false;
$versionStatus = 'EOL_LEGACY';

if (version_compare($phpVersion, '8.5.12', '>=')) {
    $isPatchedCore = true;
    $versionStatus = 'PATCHED_UPSTREAM';
} elseif (version_compare($phpVersion, '8.4.27', '>=') && version_compare($phpVersion, '8.5.0', '<')) {
    $isPatchedCore = true;
    $versionStatus = 'PATCHED_UPSTREAM';
} elseif (version_compare($phpVersion, '8.3.36', '>=') && version_compare($phpVersion, '8.4.0', '<')) {
    $isPatchedCore = true;
    $versionStatus = 'PATCHED_UPSTREAM';
} elseif (version_compare($phpVersion, '8.2.35', '>=') && version_compare($phpVersion, '8.3.0', '<')) {
    $isPatchedCore = true;
    $versionStatus = 'PATCHED_UPSTREAM';
} elseif (PHP_MAJOR_VERSION === 7) {
    $versionStatus = 'PHP7_EOL';
} elseif (PHP_MAJOR_VERSION < 7) {
    $versionStatus = 'LEGACY_EOL';
} else {
    $versionStatus = 'UNPATCHED_BRANCH';
}

// Risk scoring
$riskLevel = 'LOW';
if (!$isPatchedCore && $uploadProgressEnabled) {
    $riskLevel = 'CRITICAL';
} elseif (!$isPatchedCore && !$uploadProgressEnabled) {
    $riskLevel = 'MITIGATED';
} elseif ($isPatchedCore) {
    $riskLevel = 'SECURE';
}

// Output rendering
if ($isCli) {
    echo "====================================================================\n";
    echo "  PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Audit Scanner\n";
    echo "====================================================================\n";
    echo "PHP Version        : " . $phpVersion . " (" . $versionStatus . ")\n";
    echo "Server SAPI        : " . $sapi . "\n";
    echo "Operating System   : " . $os . "\n";
    echo "Upload Progress    : " . ($uploadProgressEnabled ? "ENABLED (VULNERABLE VECTOR ACTIVE)" : "DISABLED (MITIGATED)") . "\n";
    echo "Upload Cleanup     : " . ($uploadProgressCleanup ? "Enabled" : "Disabled") . "\n";
    echo "File Uploads       : " . ($fileUploads ? "On" : "Off") . "\n";
    echo "Memory Limit       : " . $memoryLimit . "\n";
    echo "User INI Support   : " . ($userIniFilename ?: "None") . "\n";
    echo "--------------------------------------------------------------------\n";
    echo "OVERALL STATUS     : [" . $riskLevel . "]\n";
    if ($riskLevel === 'CRITICAL') {
        echo "[!] CRITICAL: session.upload_progress.enabled is ON on an unpatched runtime!\n";
        echo "    Action: Immediately set 'session.upload_progress.enabled = 0' in php.ini / .user.ini\n";
    } elseif ($riskLevel === 'MITIGATED') {
        echo "[+] MITIGATED: session.upload_progress.enabled is DISABLED.\n";
        echo "    The primary PHP2Shell exploit loop is blocked. Plan upgrade to PHP 8.2+.\n";
    } else {
        echo "[+] SECURE: Your PHP runtime includes official upstream security patches.\n";
    }
    echo "====================================================================\n";
    exit(0);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Security Auditor</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --critical: #ef4444;
            --critical-bg: rgba(239, 68, 68, 0.15);
            --mitigated: #f59e0b;
            --mitigated-bg: rgba(245, 158, 11, 0.15);
            --secure: #10b981;
            --secure-bg: rgba(16, 185, 129, 0.15);
            --accent: #38bdf8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg-color); color: var(--text-main); min-height: 100vh; padding: 2rem 1rem; display: flex; justify-content: center; align-items: flex-start; }
        .container { max-width: 820px; width: 100%; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 2.5rem; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 1.5rem; margin-bottom: 2rem; }
        .badge-status { font-weight: 700; font-size: 0.95rem; padding: 0.4rem 1rem; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.05em; display: inline-flex; align-items: center; gap: 0.5rem; }
        .badge-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
        .badge-mitigated { background: var(--mitigated-bg); color: var(--mitigated); border: 1px solid var(--mitigated); }
        .badge-secure { background: var(--secure-bg); color: var(--secure); border: 1px solid var(--secure); }
        h1 { font-size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 0.25rem; }
        .subtitle { color: var(--text-muted); font-size: 0.9rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .metric { background: #0f172a; border: 1px solid var(--border-color); padding: 1rem; border-radius: 8px; }
        .metric-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.35rem; }
        .metric-val { font-size: 1.1rem; font-weight: 600; color: #fff; }
        .metric-val.alert { color: var(--critical); }
        .metric-val.ok { color: var(--secure); }
        .section-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; color: var(--accent); }
        .info-box { background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; line-height: 1.6; font-size: 0.95rem; }
        .code-snippet { background: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 0.75rem 1rem; font-family: monospace; font-size: 0.85rem; color: #38bdf8; margin-top: 0.5rem; overflow-x: auto; }
        .footer { text-align: center; font-size: 0.8rem; color: var(--text-muted); border-top: 1px solid var(--border-color); padding-top: 1.5rem; margin-top: 2rem; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>PHP2Shell Security Auditor</h1>
            <div class="subtitle">CVE-2026-109618 &bull; CVE-2026-109619 Diagnostics</div>
        </div>
        <div>
            <?php if ($riskLevel === 'CRITICAL'): ?>
                <span class="badge-status badge-critical">&#9888; Critical Risk</span>
            <?php elseif ($riskLevel === 'MITIGATED'): ?>
                <span class="badge-status badge-mitigated">&#10004; Mitigated</span>
            <?php else: ?>
                <span class="badge-status badge-secure">&#10004; Secure</span>
            <?php endif; ?>
        </div>
    </div>

    <div class="grid">
        <div class="metric">
            <div class="metric-label">PHP Runtime</div>
            <div class="metric-val"><?= htmlspecialchars($phpVersion) ?></div>
        </div>
        <div class="metric">
            <div class="metric-label">Server SAPI</div>
            <div class="metric-val"><?= htmlspecialchars($sapi) ?></div>
        </div>
        <div class="metric">
            <div class="metric-label">Session Upload Progress</div>
            <div class="metric-val <?= $uploadProgressEnabled ? 'alert' : 'ok' ?>">
                <?= $uploadProgressEnabled ? 'ENABLED' : 'DISABLED' ?>
            </div>
        </div>
        <div class="metric">
            <div class="metric-label">File Uploads</div>
            <div class="metric-val"><?= $fileUploads ? 'Enabled' : 'Disabled' ?></div>
        </div>
        <div class="metric">
            <div class="metric-label">Memory Limit</div>
            <div class="metric-val"><?= htmlspecialchars($memoryLimit) ?></div>
        </div>
        <div class="metric">
            <div class="metric-label">User INI Config</div>
            <div class="metric-val"><?= htmlspecialchars($userIniFilename ?: 'N/A') ?></div>
        </div>
    </div>

    <div class="section-title">Diagnostic Findings & Recommendations</div>

    <?php if ($riskLevel === 'CRITICAL'): ?>
        <div class="info-box" style="border-color: var(--critical); background: var(--critical-bg);">
            <strong style="color: var(--critical);">ACTION REQUIRED: System is vulnerable to PHP2Shell RCE!</strong><br>
            Your PHP runtime is <strong><?= htmlspecialchars($phpVersion) ?></strong> and <code>session.upload_progress.enabled</code> is active. Remote unauthenticated attackers can send crafted multipart requests to trigger a Use-After-Free condition in core PHP memory.<br><br>
            <strong>Immediate Fix:</strong> Disable the upload progress feature in your <code>.user.ini</code> or <code>php.ini</code>:
            <div class="code-snippet">session.upload_progress.enabled = 0<br>session.upload_progress.cleanup = 1</div>
        </div>
    <?php elseif ($riskLevel === 'MITIGATED'): ?>
        <div class="info-box" style="border-color: var(--mitigated); background: var(--mitigated-bg);">
            <strong style="color: var(--mitigated);">STATUS: Mitigated via Configuration!</strong><br>
            While your PHP version (<strong><?= htmlspecialchars($phpVersion) ?></strong>) does not have upstream patches, <code>session.upload_progress.enabled</code> is currently <strong>DISABLED (0)</strong>. This closes the primary attack vector for CVE-2026-109619.<br><br>
            <strong>Next Steps:</strong> Check if your hosting provider/OS vendor (e.g. cPanel EasyApache <code>ea-php74</code>, CloudLinux, Ubuntu ESM) has applied security backports, and schedule migration to PHP 8.2+.
        </div>
    <?php else: ?>
        <div class="info-box" style="border-color: var(--secure); background: var(--secure-bg);">
            <strong style="color: var(--secure);">STATUS: Upstream Patched Core!</strong><br>
            Your system is running PHP <strong><?= htmlspecialchars($phpVersion) ?></strong> which includes the official emergency security patches for PHP2Shell.
        </div>
    <?php endif; ?>

    <div class="footer">
        PHP2Shell Defense Auditor &bull; For Community Protection on PHP 7.x &bull; Delete this file after audit if in public production.
    </div>
</div>
</body>
</html>
