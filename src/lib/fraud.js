const geoip = require('geoip-lite');
const chalk = require('chalk');

let config = {};

// Safe config loading
try {
    config = require('../config');
} catch (e) {
    config = {
        fraud: {
            datacenterAsn: [],
            allowedCountries: [],
            thresholds: { medium: 40, high: 80 }
        }
    };
}

const DATACENTER_ASN = new Set(config.fraud.datacenterAsn || []);

// --- IP Velocity Tracking ---
// Tracks how many requests each IP has made in a sliding window.
// Prevents rapid-fire bot attacks that pass individual checks.
// Threshold is intentionally generous — this only tracks fraud analysis calls,
// not all HTTP requests. Legitimate users rarely trigger >20 tracking hits/min.
const ipVelocity = new Map();
const VELOCITY_WINDOW_MS = 60 * 1000; // 1-minute sliding window
const VELOCITY_THRESHOLD = (config.fraud && config.fraud.velocityThreshold) || 20;
const MAX_VELOCITY_ENTRIES = 50000;    // Cap to prevent memory bloat

// Periodic cleanup for velocity tracker (every 2 minutes)
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of ipVelocity) {
        if (now - data.windowStart > VELOCITY_WINDOW_MS * 2) {
            ipVelocity.delete(ip);
        }
    }
}, 2 * 60 * 1000);

// Known VPN/proxy detection headers
const PROXY_HEADERS = [
    'x-forwarded-for',       // Multiple proxies
    'via',                   // HTTP proxy
    'forwarded',             // Standard proxy header
    'x-real-ip',             // Nginx proxy
];

/**
 * Advanced Fraud Analysis v2.0
 * Evaluates Client Signals + Server Data with full detection enabled.
 * 
 * Checks performed:
 *  1. IP & Geo analysis (ASN, country allowlist)
 *  2. User-Agent bot string detection
 *  3. Client-side automation signals (webdriver, phantom, etc.)
 *  4. OS/platform mismatch analysis
 *  5. Canvas fingerprint weakness
 *  6. Headless browser plugin count
 *  7. Timezone vs. geo mismatch
 *  8. IP velocity / rate tracking
 *  9. Proxy/VPN header detection
 * 10. Browser fingerprint consistency (screen, memory, concurrency)
 */
async function analyze(req, body = {}) {
    const ip = req.clientIp || req.ip || '127.0.0.1';
    const clientSignals = body.s || {};
    const details = [];
    let score = 0;

    // 1. IP & Geo Analysis
    const geo = geoip.lookup(ip);

    if (geo) {
        // Datacenter ASN check — flags IPs from known cloud/hosting providers
        if (geo.asn && DATACENTER_ASN.has(geo.asn)) {
            score += 100;
            details.push(`Datacenter IP (ASN ${geo.asn})`);
        }

        // Country Allowlist
        if (config.fraud.allowedCountries &&
            config.fraud.allowedCountries.length > 0 &&
            !config.fraud.allowedCountries.includes(geo.country)) {
            score += 100;
            details.push(`Country Block: ${geo.country}`);
        }
    }

    const userAgent = (req.headers['user-agent'] || '').toLowerCase();

    // 2. Explicit Bot Strings
    if (/bot|crawler|spider|scanner|curl|wget|python|java|headless/i.test(userAgent)) {
        score += 100;
        details.push('Bot User-Agent');
    }

    // 2b. Missing or empty User-Agent
    if (!userAgent || userAgent.length < 10) {
        score += 60;
        details.push('Missing/Short User-Agent');
    }

    // 3. Client-Side Automation Detection (From JS)
    if (clientSignals.wd === true) {
        score += 100;
        details.push('Navigator.webdriver detected');
    }

    if (clientSignals.bot) {
        score += 100;
        details.push(`Automation detected (Type ${clientSignals.bot})`);
    }

    // 4. Mismatch Analysis
    // Check 1: User Agent says Mac, but Platform says Win (or vice versa)
    if (clientSignals.pf) {
        const platformLower = clientSignals.pf.toLowerCase();
        if (userAgent.includes('mac os') && platformLower.includes('win')) {
            score += 60;
            details.push('OS Mismatch: UA=Mac, Platform=Win');
        } else if (userAgent.includes('windows') && platformLower.includes('mac')) {
            score += 60;
            details.push('OS Mismatch: UA=Win, Platform=Mac');
        }
    }

    // Check 2: Missing or weak Canvas Fingerprint (bots often fail to render canvas)
    if (clientSignals.cv !== undefined) {
        if (!clientSignals.cv || (typeof clientSignals.cv === 'string' && clientSignals.cv.length < 50)) {
            score += 40;
            details.push('Missing/Weak Canvas Fingerprint');
        }
    }

    // Check 3: Headless Chrome often has 0 plugins on desktop
    if (userAgent.includes('chrome') && clientSignals.pl === 0 && !userAgent.includes('mobile')) {
        score += 30;
        details.push('Chrome with 0 Plugins (Suspicious)');
    }

    // 5. Timezone Check — geo vs reported timezone offset
    if (geo && clientSignals.tm !== undefined) {
        const offset = parseInt(clientSignals.tm, 10);
        if (!isNaN(offset)) {
            if (geo.country === 'US' && (offset < 240 || offset > 600)) {
                score += 20;
                details.push('Timezone/IP Mismatch: US IP with non-US offset');
            } else if (geo.country === 'GB' && (offset < -60 || offset > 60)) {
                score += 20;
                details.push('Timezone/IP Mismatch: GB IP with unexpected offset');
            }
        }
    }

    // 6. IP Velocity Tracking — detect rapid-fire requests from same IP
    const now = Date.now();
    if (ipVelocity.size < MAX_VELOCITY_ENTRIES || ipVelocity.has(ip)) {
        if (!ipVelocity.has(ip)) {
            ipVelocity.set(ip, { count: 0, windowStart: now });
        }
        const vel = ipVelocity.get(ip);
        if (now - vel.windowStart > VELOCITY_WINDOW_MS) {
            vel.count = 1;
            vel.windowStart = now;
        } else {
            vel.count++;
        }
        if (vel.count > VELOCITY_THRESHOLD) {
            score += 40;
            details.push(`High Velocity: ${vel.count} hits/min`);
        }
    }

    // 7. Proxy/VPN Header Detection
    let proxyHeaderCount = 0;
    for (const header of PROXY_HEADERS) {
        if (req.headers[header]) {
            proxyHeaderCount++;
        }
    }
    // Multiple proxy headers suggest chained proxies (common with bots/VPNs)
    if (proxyHeaderCount >= 3) {
        score += 25;
        details.push(`Multiple proxy headers detected (${proxyHeaderCount})`);
    }

    // 8. Browser Fingerprint Consistency Checks
    // Real browsers report non-zero screen dimensions and reasonable hardware
    if (clientSignals.screenW !== undefined && clientSignals.screenH !== undefined) {
        const sw = parseInt(clientSignals.screenW, 10) || 0;
        const sh = parseInt(clientSignals.screenH, 10) || 0;
        if (sw === 0 || sh === 0) {
            score += 50;
            details.push('Zero screen dimensions');
        } else if (sw < 200 || sh < 200) {
            score += 30;
            details.push(`Implausible screen size: ${sw}x${sh}`);
        }
    }

    if (clientSignals.hardwareConcurrency !== undefined) {
        const cores = parseInt(clientSignals.hardwareConcurrency, 10) || 0;
        if (cores === 0) {
            score += 20;
            details.push('Zero hardware concurrency');
        }
    }

    if (clientSignals.colorDepth !== undefined) {
        const depth = parseInt(clientSignals.colorDepth, 10) || 0;
        if (depth > 0 && depth < 8) {
            score += 25;
            details.push(`Unusual color depth: ${depth}`);
        }
    }

    // Determine Risk Level
    const highThreshold = (config.fraud.thresholds && config.fraud.thresholds.high) || 80;
    const mediumThreshold = (config.fraud.thresholds && config.fraud.thresholds.medium) || 40;

    let risk = 'low';
    if (score >= highThreshold) {
        risk = 'high';
    } else if (score >= mediumThreshold) {
        risk = 'medium';
    }

    // Log fraud analysis result for observability
    if (score > 0) {
        console.log(chalk.yellow(`[FRAUD] IP=${ip} Score=${score} Risk=${risk} Details=[${details.join(', ')}]`));
    }

    return { score, risk, details };
}

module.exports = analyze;
