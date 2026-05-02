/**
 * Bot Detector v5.0 (Hardened)
 * Multi-layer detection: UA patterns, HTTP headers, Sec-Fetch analysis,
 * email scanner signatures, prefetch detection, AI bot detection,
 * header entropy analysis, and client signals.
 */

// Comprehensive list of bot/crawler/scanner signatures (all lowercase)
const BOT_PATTERNS = [
    // Generic bot tokens
    'bot', 'crawler', 'spider', 'scraper', 'checker', 'monitor',
    'fetch/', 'scan', 'probe', 'index', 'archiv', 'harvest',
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

    // Normalize score
    score = Math.max(0, Math.min(100, score));

    // Strict thresholds: score >= 50 is treated as a bot
    const isBot = score >= 50;
    const confidence = score >= 80 ? 'high' : (score >= 50 ? 'medium' : 'low');

    return {
        isBot,
        score,
        confidence,
        signals: reasons
    };
}

module.exports = detectBot;
