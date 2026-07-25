/**
 * Bot Detector v6.0 (Hardened+)
 * Multi-layer detection: UA patterns, HTTP headers, Sec-Fetch analysis,
 * email scanner signatures, prefetch detection, AI bot detection,
 * header entropy analysis, client signals, JA3/TLS fingerprint hints,
 * datacenter ASN scoring, and per-IP arrival velocity.
 */

// Safe config loading (tunable thresholds via config.botDetection)
let _config = {};
try {
    _config = require('../config');
} catch (e) { /* config not present in some test envs */ }

const BOT_THRESHOLD = (_config.botDetection && _config.botDetection.threshold) || 50;
const HIGH_CONFIDENCE_THRESHOLD = (_config.botDetection && _config.botDetection.highConfidenceThreshold) || 80;
const DATACENTER_ASN = new Set(((_config.fraud && _config.fraud.datacenterAsn) || []));

// ---------- Per-IP arrival velocity (in-memory sliding window) ----------
// A real human does not click the same redirector >5 times in 10 seconds.
// Scanner sandboxes that explore links via multiple URL variants will trip this.
const VELOCITY_WINDOW_MS = 10 * 1000;
const VELOCITY_THRESHOLD = 5;
const VELOCITY_MAX_ENTRIES = 50000;
const _ipHits = new Map(); // ip -> [timestamps]

function _trackIpVelocity(ip) {
    if (!ip) return 0;
    const now = Date.now();
    let arr = _ipHits.get(ip);
    if (!arr) {
        if (_ipHits.size >= VELOCITY_MAX_ENTRIES) {
            // Drop oldest entry to bound memory
            const firstKey = _ipHits.keys().next().value;
            _ipHits.delete(firstKey);
        }
        arr = [];
        _ipHits.set(ip, arr);
    }
    // Trim entries outside the window
    while (arr.length && now - arr[0] > VELOCITY_WINDOW_MS) arr.shift();
    arr.push(now);
    return arr.length;
}

// Periodic cleanup
setInterval(() => {
    const now = Date.now();
    for (const [ip, arr] of _ipHits) {
        while (arr.length && now - arr[0] > VELOCITY_WINDOW_MS) arr.shift();
        if (arr.length === 0) _ipHits.delete(ip);
    }
}, 60 * 1000).unref?.();

// ---------- Substring patterns (matched with .includes) ----------
// These are unambiguous tokens — they will not appear in a real-browser UA.
const BOT_PATTERNS = [
    // Generic bot tokens (unambiguous substrings)
    'bot', 'crawler', 'spider', 'scraper', 'checker', 'monitor',
    'fetch/', 'archiv', 'harvest',
    // HTTP Libraries & Tools
    'curl', 'wget', 'python', 'java/', 'java ', 'axios', 'got/', 'node-fetch', 'guzzle',
    'libwww', 'http_client', 'postman', 'insomnia', 'httpie', 'okhttp', 'jersey',
    'restsharp', 'httpclient', 'go-http-client', 'ruby/', 'perl/', 'php/',
    'mechanize', 'scrapy', 'aiohttp', 'httpx', 'undici', 'request/',
    'http.rb', 'typhoeus', 'faraday', 'excon', 'patron', 'lwp-',
    // Headless/Automation
    'headless', 'phantom', 'selenium', 'puppeteer', 'playwright', 'webdriver',
    'chrome-lighthouse', 'gtmetrix', 'pingdom', 'uptimerobot', 'freshping',
    'sitemonitor', 'monit', 'nagios', 'zabbix', 'datadog',
    // Search Engines & Social Media
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot',
    'sogou', 'exabot', 'facebot', 'ia_archiver',
    'facebookexternalhit', 'facebookcatalog', 'twitterbot', 'linkedinbot',
    'slackbot', 'discordbot', 'whatsapp', 'telegrambot', 'pinterest',
    'tumblr', 'skypeuripreview', 'viberbot', 'kakaotalk', 'snapchat',
    'redditbot', 'applebot', 'petalbot', 'semrushbot', 'ahrefsbot',
    'dotbot', 'mj12bot', 'seokicks', 'rogerbot', 'seznambot',
    // AI Bots & LLM Crawlers (critical for blocking AI scrapers)
    'gptbot', 'chatgpt-user', 'chatgpt', 'openai', 'oai-searchbot',
    'claudebot', 'claude-web', 'anthropic',
    'google-extended', 'bard', 'gemini',
    'perplexitybot', 'perplexity',
    'cohere-ai', 'cohere',
    'bytespider', 'bytedance',
    'ccbot', 'commoncrawl',
    'diffbot', 'youbot', 'meta-externalagent',
    'amazonbot', 'ai2bot', 'omgili', 'omgilibot',
    'iaskspider', 'friendlycrawler', 'timpibot', 'velenpublicwebcrawler',
    'webzio-extended', 'imagesiftbot', 'kangaroo bot',
    // Newer AI / search crawlers
    'meta-externalfetcher', 'applebot-extended', 'mistralai-user',
    'phindbot', 'pangubot', 'cotoyogi', 'qwantify', 'seekr',
    'internet-measurement', 'duckassistbot', 'pangu-crawler',
    'novaact', 'youbot', 'zhipu',
    // Email Security Scanners (critical for email link protection)
    'barracuda', 'proofpoint', 'mimecast', 'messagelabs', 'forcepoint',
    'fireeye', 'trendmicro', 'sophos', 'symantec', 'norton', 'mcafee',
    'kaspersky', 'avast', 'avg', 'bitdefender', 'clamav', 'comodo',
    'eset', 'gdata', 'malwarebytes', 'panda', 'zonealarm',
    'fortiguard', 'fortinet', 'paloalto', 'zscaler', 'websense',
    'bluecoat', 'brightcloud', 'netskope', 'cyvelle', 'sailpoint',
    'safebrowsing', 'phishtank', 'virustotal', 'virus', 'urldefense',
    'safelinks', 'safelink',
    // URL Scanners & Validators
    'urlchecker', 'linkchecker', 'link-preview', 'safeguard',
    'sandbox', 'urlscan', 'scanalert', 'sitecheck', 'securl', 'sucuri',
    'detectify', 'qualys', 'acunetix', 'netsparker', 'burp',
    'owasp', 'nikto', 'nmap', 'masscan', 'censys', 'shodan',
    // Cloud/Hosting
    'amazonaws', 'azure', 'google-cloud', 'cloudflare-', 'fastly',
    'akamai', 'cloudfront',
    // Microsoft/Office link preview
    'microsoft office', 'ms-office', 'ms office',
    // Link Expanders/Previewers
    'embedly', 'quora', 'outbrain', 'paperli', 'flipboard',
    'nuzzel', 'newsblur', 'feedly'
];

// Word-boundary regex patterns — fired only when the token appears as a standalone
// word (e.g. "scan" matches "scan/1.0" but NOT "indexedDB"). This eliminates
// false-positives we used to get from substrings like "index" or "scan".
const BOT_REGEX_PATTERNS = [
    /\bscan(?:ner|ning)?\b/i,
    /\bprobe\b/i,
    /\bindexer\b/i,
    /\b(?:auto|head)less\b/i,
    /\b(?:python|java|ruby|perl|php|go)-(?:requests|http|urllib|httpclient)\b/i
];

// Email scanner-known referers — when these referers appear together with weak
// browser signals it strongly indicates a link being followed by an email security
// product rather than the human recipient.
const SCANNER_REFERERS = [
    'mail.google.com', 'outlook.live.com', 'outlook.office.com',
    'mail.yahoo.com', 'mail.aol.com', 'mail.protonmail.com',
    'mail.zoho.com', 'mail.proton.me', 'webmail.', 'safelinks.protection.outlook.com'
];

function detectBot(req, clientSignals = {}) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    let score = 0;
    const reasons = [];

    // ====== Layer 1: User-Agent Signature Analysis ======

    // 1. Empty or malformed User-Agent (Immediate high risk)
    if (!ua || ua === '' || ua.length < 10) {
        score += 85;
        reasons.push('Empty/Short UA');
    }

    // 2. Pattern Matching against comprehensive bot signatures
    for (const pattern of BOT_PATTERNS) {
        if (ua.includes(pattern)) {
            score += 100;
            reasons.push(`Signature matched: ${pattern}`);
            break;
        }
    }

    // 2b. Word-boundary regex matches (avoids false positives from common substrings)
    for (const re of BOT_REGEX_PATTERNS) {
        if (re.test(ua)) {
            score += 100;
            reasons.push(`Regex bot signature: ${re.source}`);
            break;
        }
    }

    // ====== Layer 2: HTTP Headers Analysis ======

    // 1. Missing Accept-Language (All real browsers send this)
    if (!req.headers['accept-language']) {
        score += 45;
        reasons.push('Missing Accept-Language');
    }

    // 2. Missing Accept header
    if (!req.headers['accept']) {
        score += 30;
        reasons.push('Missing Accept header');
    }

    // 3. Sec-Fetch-* headers analysis (CRITICAL for catching modern scanners)
    // Modern browsers (Chrome 76+, Firefox 90+, Edge 79+, Safari 17.4+) ALWAYS send these.
    // Their absence strongly indicates a non-browser HTTP client or scanner.
    const hasSecFetchDest = !!req.headers['sec-fetch-dest'];
    const hasSecFetchMode = !!req.headers['sec-fetch-mode'];
    const hasSecFetchSite = !!req.headers['sec-fetch-site'];

    if (!hasSecFetchDest && !hasSecFetchMode && !hasSecFetchSite) {
        score += 40;
        reasons.push('Missing all Sec-Fetch headers');
    } else if (!hasSecFetchDest || !hasSecFetchMode) {
        score += 15;
        reasons.push('Incomplete Sec-Fetch headers');
    }

    // 4. Prefetch / Preview headers (explicit scanner signals)
    const purpose = (req.headers['purpose'] || req.headers['x-purpose'] || '').toLowerCase();
    if (purpose.includes('prefetch') || purpose.includes('preview')) {
        score += 100;
        reasons.push('Prefetch/Preview purpose header');
    }
    if (req.headers['x-moz'] === 'prefetch') {
        score += 100;
        reasons.push('Mozilla prefetch');
    }

    // 5. Pragma/Cache-Control behavior
    if (req.headers['pragma'] === 'no-cache' || req.headers['cache-control'] === 'no-cache') {
        score += 10;
    }

    // 6. Via header (proxy/scanner chains)
    if (req.headers['via']) {
        score += 15;
        reasons.push('Via proxy header present');
    }

    // 7. Known scanner-specific request headers
    if (req.headers['x-scanner'] || req.headers['x-scan-type'] || req.headers['x-security-scan']) {
        score += 100;
        reasons.push('Scanner header detected');
    }

    // ====== Layer 3: Client Signals (If available) ======
    if (clientSignals && typeof clientSignals === 'object') {

        // WebDriver is the "smoking gun" for automation
        if (clientSignals.webdriver === true || clientSignals.webdriver === 'true') {
            score += 100;
            reasons.push('WebDriver detected (Client-side)');
        }

        // Headless Chrome check
        if (clientSignals.headless === true) {
            score += 100;
            reasons.push('Headless Browser detected');
        }

        // Human Signals (Reduces score moderately)
        if (clientSignals.jsExecuted === true) {
            score -= 15; // Reduced deduction since bots can execute JS too
        }

        if (clientSignals.hasInteraction === true) {
            score -= 30; // Mouse moved/Clicked, likely human
        }

        // Enhanced client-side signals
        // No languages in JS environment — strong bot indicator
        if (clientSignals.languages === 0) {
            score += 35;
            reasons.push('Zero navigator.languages (Client)');
        }

        // Desktop Chrome with 0 plugins — suspicious for non-mobile
        if (clientSignals.plugins === 0 && clientSignals.touchSupport === false) {
            score += 25;
            reasons.push('Desktop with 0 plugins (Client)');
        }

        // Empty or very small canvas data URL — bots often fail canvas rendering
        // Real browsers produce data URLs of 2000+ chars; below 100 indicates render failure
        if (clientSignals.canvasHash !== undefined && clientSignals.canvasHash < 100) {
            score += 30;
            reasons.push('Failed canvas fingerprint (Client)');
        }
    }

    // ====== Layer 4: Heuristics ======

    // Linux without Android or X11 often indicates a server/headless linux bot
    if (ua.includes('linux') && !ua.includes('android') && !ua.includes('x11')) {
        score += 30;
        reasons.push('Suspicious OS (Linux non-Android/X11)');
    }

    // Browser UA but missing Connection header
    if (ua.includes('mozilla') && !req.headers['connection']) {
        score += 15;
        reasons.push('Browser UA but missing Connection header');
    }

    // ====== Layer 5: Advanced Hardened Bot Detection ======

    // 1. Header entropy check — real browsers send a consistent set of headers.
    // Bots that spoof UA but forget other headers expose themselves.
    const headerCount = Object.keys(req.headers).length;
    if (ua.includes('mozilla') && headerCount < 5) {
        score += 35;
        reasons.push(`Suspiciously few headers (${headerCount}) for browser UA`);
    }

    // 2. Accept header consistency — real browsers include specific mime types
    const acceptHeader = (req.headers['accept'] || '').toLowerCase();
    if (ua.includes('mozilla') && acceptHeader && !acceptHeader.includes('text/html') && !acceptHeader.includes('*/*')) {
        score += 25;
        reasons.push('Browser UA with non-browser Accept header');
    }

    // 3. Accept-Encoding analysis — real browsers always send compression support
    if (!req.headers['accept-encoding'] && ua.includes('mozilla')) {
        score += 30;
        reasons.push('Browser UA missing Accept-Encoding');
    }

    // 4. Sec-Ch-UA analysis — Chromium 89+ sends Client Hints automatically
    // Their absence with a Chrome 89+ UA is a strong bot signal
    if (ua.includes('chrome/')) {
        const chromeVersionMatch = ua.match(/chrome\/(\d+)/);
        if (chromeVersionMatch && parseInt(chromeVersionMatch[1]) >= 89 && !req.headers['sec-ch-ua']) {
            score += 35;
            reasons.push('Modern Chrome UA missing Sec-Ch-UA hints');
        }
    }

    // 5. Upgrade-Insecure-Requests — real browsers on HTTP pages send this
    if (ua.includes('mozilla') && req.headers['sec-fetch-dest'] === 'document' && !req.headers['upgrade-insecure-requests']) {
        score += 15;
        reasons.push('Document request missing Upgrade-Insecure-Requests');
    }

    // 6. Suspicious Sec-Fetch combinations
    const secFetchDest = (req.headers['sec-fetch-dest'] || '').toLowerCase();
    const secFetchMode = (req.headers['sec-fetch-mode'] || '').toLowerCase();
    if (secFetchDest && secFetchMode) {
        // A document navigating with 'cors' mode is unusual (bots misconfigure this)
        if (secFetchDest === 'document' && secFetchMode === 'cors') {
            score += 30;
            reasons.push('Invalid Sec-Fetch combination (document+cors)');
        }
    }

    // 7. Forwarded header chains — scanner proxies often leave these
    if (req.headers['x-forwarded-for'] && req.headers['x-forwarded-for'].split(',').length > 3) {
        score += 20;
        reasons.push('Deep proxy chain detected');
    }

    // 8. Request timing anomaly — X-Request-Start or unusual timing headers from scanners
    if (req.headers['x-request-start'] || req.headers['x-queue-start']) {
        score += 15;
        reasons.push('Scanner timing header detected');
    }

    // ====== Layer 6: Network/Infrastructure Signals ======

    // 1. JA3 / TLS fingerprint hints (when behind Cloudflare or a CDN that exposes them)
    // A blank or unusual JA3 from a "Mozilla" UA strongly suggests a non-browser client.
    const tlsFp = req.headers['cf-ja3-hash'] || req.headers['cf-ja3'] || req.headers['x-tls-fingerprint'];
    if (tlsFp && ua.includes('mozilla')) {
        // Known curl/python/go default hashes — not exhaustive, but useful examples.
        // Any short or empty hash with a real-browser UA is itself a strong signal.
        const fp = String(tlsFp).toLowerCase();
        const KNOWN_NON_BROWSER_JA3 = [
            // common curl JA3 hashes (publicly documented)
            '472d8e04f47cf1d5071dd0ff61cd0fbd', // curl
            'e7d705a3286e19ea42f587b344ee6865', // curl alt
            'a0e9f5d64349fb13191bc781f81f42e1', // python-requests
            '54328bd36c14bd82ddaa0c04b25ed9ad'  // openssl/golang
        ];
        if (KNOWN_NON_BROWSER_JA3.includes(fp) || fp.length < 16) {
            score += 60;
            reasons.push('Non-browser TLS fingerprint');
        }
    }

    // 2. Datacenter ASN — Cloudflare/CDN sets cf-ipcountry / cf-iplongitude;
    // some setups also forward the source ASN. Also accept geoip-lite lookup result
    // when the caller passes it in via clientSignals.geo (kept generic to avoid
    // double-fetching geo here).
    const asnHeader = req.headers['cf-asn'] || req.headers['x-ip-asn'];
    const asn = parseInt(asnHeader, 10);
    if (asn && DATACENTER_ASN.has(asn)) {
        score += 35;
        reasons.push(`Datacenter ASN ${asn}`);
    }

    // 3. Per-IP arrival velocity — too many requests in a short window
    const ip = req.clientIp || req.ip || (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const velocityCount = _trackIpVelocity(ip);
    if (velocityCount > VELOCITY_THRESHOLD) {
        score += 30;
        reasons.push(`High IP velocity (${velocityCount}/${VELOCITY_WINDOW_MS / 1000}s)`);
    }

    // 4. Email-scanner referer + no client-side JS execution — classic email scanner pattern.
    // Real recipients click and load the page, so jsExecuted should be true on subsequent
    // unlock submission. Initial GETs from scanner referers without any browser hints get flagged.
    const referer = (req.headers['referer'] || req.headers['referrer'] || '').toLowerCase();
    if (referer) {
        const isScannerReferer = SCANNER_REFERERS.some(s => referer.includes(s));
        if (isScannerReferer && !clientSignals.jsExecuted && !req.headers['sec-fetch-dest']) {
            score += 35;
            reasons.push('Email-scanner referer without browser hints');
        }
    }

    // 5. Honeypot-flagged IP (set by upstream scanner-probe middleware in server.js)
    if (req.headers['x-honeypot-flagged']) {
        score += 80;
        reasons.push('IP previously hit honeypot path');
    }

    // Normalize score
    score = Math.max(0, Math.min(100, score));

    // Strict thresholds: configurable via config.botDetection.threshold (default 50)
    const isBot = score >= BOT_THRESHOLD;
    const confidence = score >= HIGH_CONFIDENCE_THRESHOLD ? 'high' : (score >= BOT_THRESHOLD ? 'medium' : 'low');

    return {
        isBot,
        score,
        confidence,
        signals: reasons
    };
}

module.exports = detectBot;
// Expose internals for testing and dashboard introspection
module.exports.BOT_THRESHOLD = BOT_THRESHOLD;
module.exports.HIGH_CONFIDENCE_THRESHOLD = HIGH_CONFIDENCE_THRESHOLD;
