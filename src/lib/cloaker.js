const crypto = require('crypto');

// Attempt to load secret from config, otherwise use a safe default for development
let SECRET = 'change-this-secret-in-production-immediately';
let FALLBACK_URL = 'https://www.google.com';
try {
    const config = require('../config');
    if (config.redirector && config.redirector.secret) {
        SECRET = config.redirector.secret;
    }
    if (config.redirector && config.redirector.fallbackUrl) {
        FALLBACK_URL = config.redirector.fallbackUrl;
    }
} catch (e) { 
    // Config might not exist in all environments, ignore error
}

// Generate a short alphanumeric token (used for randomized JS variable names so
// every served HTML page differs and cannot be statically fingerprinted).
// Uses `crypto.randomInt` to avoid the modulo-bias caused by `randomBytes()[i] % 52`.
function _rndId(len = 6) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let out = '';
    for (let i = 0; i < len; i++) out += alphabet[crypto.randomInt(0, alphabet.length)];
    return out;
}

// JSON-escape for safe embedding in a JS string literal wrapped in double quotes.
function _jsStringEscape(str) {
    return String(str).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

// ==================== PERFORMANCE FIX ====================
// CRITICAL OPTIMIZATION:
// We derive the key ONCE at startup and cache it.
// Previously, this was running on every single request, causing high CPU usage
// and multi-second delays for every click.
const CACHED_KEY = crypto.scryptSync(SECRET, 'salt', 32);

/**
 * Encrypts the destination URL so it's not visible in source code
 * Uses AES-256-GCM for authenticated encryption
 */
function encryptPayload(text) {
    const iv = crypto.randomBytes(16);
    
    // Use the cached key instead of deriving it again
    const cipher = crypto.createCipheriv('aes-256-gcm', CACHED_KEY, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
        content: encrypted,
        iv: iv.toString('hex'),
        tag: tag.toString('hex')
    };
}

/**
 * Decrypts the payload server-side
 */
function decryptPayload(encryptedData) {
    try {
        // Use the cached key instead of deriving it again
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm', 
            CACHED_KEY, 
            Buffer.from(encryptedData.iv, 'hex')
        );
        
        decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
        
        let decrypted = decipher.update(encryptedData.content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (e) {
        return null;
    }
}

/**
 * Generate the "Invisible" Wrapper Page
 * This serves a blank page that immediately executes client-side bot checks. 
 * If passed, it performs a hidden POST submission to the unlock endpoint.
 */
exports.generateInvisibleWrapper = (finalUrl, linkId) => {
    // Encrypt the real URL so bots reading source code see garbage
    const encrypted = encryptPayload(finalUrl);
    
    // Embed the payload directly into the HTML
    // We escape backslashes and quotes to prevent JS syntax errors
    const payloadSafe = JSON.stringify(encrypted).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title></title>
<style>html,body{margin:0;padding:0;height:100%;width:100%;overflow:hidden;background:#ffffff;}</style>
</head>
<body>
<script>
(function() {
    // Configuration embedded from server
    var P = JSON.parse("${payloadSafe}");
    var LID = "${linkId}";
    
    // --- SILENT BOT DETECTION (Hardened v2) ---
    // Multi-check bot detection: mechanical signals, environment probing, rendering tests
    function isBot() {
        var s = 0; // Accumulate suspicion score
        
        // Check 1: WebDriver — most common flag for Selenium/Puppeteer
        if (navigator.webdriver) s += 100;
        
        // Check 2: PhantomJS properties
        if (window.callPhantom || window._phantom) s += 100;
        
        // Check 3: Headless Chrome often has 0 languages defined
        if (navigator.languages && navigator.languages.length === 0) s += 80;
        
        // Check 4: HeadlessChrome in UA string
        if (navigator.userAgent && navigator.userAgent.indexOf('HeadlessChrome') !== -1) s += 100;
        
        // Check 5: Missing permissions API (bots often lack this)
        try { if (!navigator.permissions) s += 30; } catch(e) {}
        
        // Check 6: Notification permission — headless environments throw or lack this
        try {
            if (typeof Notification === 'undefined') s += 25;
        } catch(e) { s += 25; }
        
        // Check 7: Desktop with 0 plugins — suspicious for non-touch devices
        if (navigator.plugins && navigator.plugins.length === 0 && !('ontouchstart' in window)) s += 30;
        
        // Check 8: Screen dimensions — headless often uses specific default sizes
        if (screen.width === 0 || screen.height === 0) s += 80;
        
        // Check 9: Color depth — bots may report 0 or unusual values
        if (screen.colorDepth && screen.colorDepth < 8) s += 40;
        
        // Check 10: Canvas Fingerprinting (Lightweight)
        try {
            var c = document.createElement('canvas');
            var ctx = c.getContext('2d');
            if (!ctx) { s += 80; } else {
                ctx.textBaseline = "top";
                ctx.font = "14px 'Arial'";
                ctx.textBaseline = "alphabetic";
                ctx.fillStyle = "#f60";
                ctx.fillRect(125,1,62,20);
                ctx.fillStyle = "#069";
                ctx.fillText("BrowserCheck", 2, 15);
                ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
                ctx.fillText("BrowserCheck", 4, 17);
                if (c.toDataURL().length < 100) s += 60;
            }
        } catch(e) { s += 60; }
        
        // Check 11: WebGL presence — real browsers have this
        try {
            var gl = document.createElement('canvas').getContext('webgl');
            if (!gl) s += 20;
        } catch(e) { s += 20; }
        
        // Check 12: Chrome-specific automation properties
        // Real Chrome has window.chrome object; headless/automated Chrome often lacks it
        if (navigator.userAgent.indexOf('Chrome') !== -1 && !(window.chrome && window.chrome.app)) s += 40;
        
        return s >= 50;
    }

    // --- EXECUTION ---
    // We wrap in a tiny timeout to ensure the browser environment is fully loaded
    setTimeout(function() {
        if (isBot()) {
            // FAIL: Silent redirect to fallback
            window.location.replace("${_jsStringEscape(FALLBACK_URL)}");
        } else {
            // PASS: Silent redirect to Real Destination
            // We use a POST request to a special endpoint that decrypts and redirects.
            // This keeps the final URL out of the source code until the very last second.
            
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '/tr/v2/unlock'; // The Unlock Endpoint
            form.style.display = 'none';
            
            var i1 = document.createElement('input');
            i1.type = 'hidden'; 
            i1.name = 'payload'; 
            i1.value = JSON.stringify(P);
            form.appendChild(i1);
            
            var i2 = document.createElement('input');
            i2.type = 'hidden'; 
            i2.name = 'lid'; 
            i2.value = LID;
            form.appendChild(i2);
            
            document.body.appendChild(form);
            form.submit();
        }
    }, 50);
})();
</script>
</body>
</html>`;
};

// ==================== CHALLENGE PAGE (Used by api/routes.js) ====================
// These functions are called from the legacy api/routes.js redirect handler.
// generateChallengePage: Creates a challenge page with encrypted URL + client-side bot detection.
// verifyChallenge: Verifies a challenge token and returns the decrypted URL.

/**
 * Generate a challenge token containing the encrypted URL and link ID.
 * The token is a signed JWT that expires in 5 minutes.
 * @param {string} url - The destination URL to encrypt
 * @param {string} linkId - The link identifier
 * @returns {string} JWT challenge token
 */
function createChallengeToken(url, linkId) {
    const jwt = require('jsonwebtoken');
    let jwtSecret = 'challenge-fallback-secret';
    try {
        const config = require('../config');
        jwtSecret = config.jwt.secret || jwtSecret;
    } catch (e) { /* ignore */ }

    const encrypted = encryptPayload(url);
    return jwt.sign(
        { enc: encrypted, lid: linkId, t: 'ch' },
        jwtSecret,
        { expiresIn: '5m' }
    );
}

/**
 * Generate a Challenge Page — serves a page with embedded client-side bot detection.
 * If the visitor passes the bot check, it POSTs to the verification endpoint
 * with a signed challenge token. Bots are redirected to a fallback.
 * 
 * Called by api/routes.js for the legacy /tr/v1/:id redirect handler.
 * 
 * @param {string} finalUrl - The real destination URL
 * @param {string} linkId - The link identifier
 * @returns {string} Full HTML challenge page
 */
exports.generateChallengePage = (finalUrl, linkId) => {
    const challengeToken = createChallengeToken(finalUrl, linkId);
    const tokenSafe = _jsStringEscape(challengeToken);
    const fallbackSafe = _jsStringEscape(FALLBACK_URL);
    const linkIdSafe = _jsStringEscape(linkId);

    // Randomize identifiers for each page render so static fingerprinting fails.
    const fnIsBot = '_' + _rndId(7);
    const fnSignals = '_' + _rndId(7);
    const fnSubmit = '_' + _rndId(7);
    const varTok = '_' + _rndId(5);
    const varLid = '_' + _rndId(5);
    const varInteracted = '_' + _rndId(5);
    const varFallback = '_' + _rndId(5);
    const noiseId = _rndId(10);
    // Random delay between 350ms and 850ms so timing-based scanners can't pattern-match
    const delay1 = 250 + Math.floor(Math.random() * 250); // 250-500ms
    const delay2 = 350 + Math.floor(Math.random() * 500); // 350-850ms

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verifying</title>
<!-- ${noiseId} -->
<style>
html,body{margin:0;padding:0;height:100%;width:100%;overflow:hidden;background:#f5f5f5;}
.center{display:flex;justify-content:center;align-items:center;min-height:100vh;}
.box{text-align:center;font-family:-apple-system,system-ui,sans-serif;color:#666;}
.spinner{width:32px;height:32px;margin:0 auto 1rem;border:3px solid #ddd;border-top-color:#4f46e5;border-radius:50%;animation:spin 1s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="center"><div class="box"><div class="spinner"></div><p>Verifying your connection...</p></div></div>
<script>
(function() {
    var ${varTok} = "${tokenSafe}";
    var ${varLid} = "${linkIdSafe}";
    var ${varFallback} = "${fallbackSafe}";
    var ${varInteracted} = false;

    // Track human interaction (mouse/pointer/touch). Real users move at least
    // a tiny bit between page render and submit; headless scanners do not.
    function _onMove() { ${varInteracted} = true; }
    try {
        document.addEventListener('mousemove', _onMove, { passive: true, once: true });
        document.addEventListener('pointermove', _onMove, { passive: true, once: true });
        document.addEventListener('touchstart', _onMove, { passive: true, once: true });
        document.addEventListener('keydown', _onMove, { passive: true, once: true });
    } catch (e) { /* ignore */ }

    function ${fnIsBot}() {
        var s = 0;
        // Mechanical signals
        if (navigator.webdriver) s += 100;
        if (window.callPhantom || window._phantom) s += 100;
        if (navigator.languages && navigator.languages.length === 0) s += 80;
        if (navigator.userAgent && navigator.userAgent.indexOf('HeadlessChrome') !== -1) s += 100;

        // Permissions / Notification API (headless often missing)
        try { if (!navigator.permissions) s += 30; } catch(e) {}
        try { if (typeof Notification === 'undefined') s += 25; } catch(e) { s += 25; }

        // Plugins on non-touch desktop
        if (navigator.plugins && navigator.plugins.length === 0 && !('ontouchstart' in window)) s += 30;

        // Screen / display sanity
        if (!screen.width || !screen.height) s += 80;
        if (screen.colorDepth && screen.colorDepth < 8) s += 40;

        // Hardware sanity
        try { if (navigator.hardwareConcurrency === 0) s += 30; } catch(e) {}

        // Timezone — every real browser exposes one
        try {
            var tz = (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || '';
            if (!tz) s += 30;
        } catch(e) { s += 30; }

        // Iframe sandbox detection — if our page is loaded inside a probing iframe
        try { if (window.top !== window.self) s += 50; } catch(e) { s += 50; }

        // Canvas fingerprint
        try {
            var c = document.createElement('canvas');
            var ctx = c.getContext('2d');
            if (!ctx) { s += 80; } else {
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(125,1,62,20);
                ctx.fillStyle = '#069';
                ctx.fillText('Check', 2, 15);
                if (c.toDataURL().length < 100) s += 60;
            }
        } catch(e) { s += 60; }

        // WebGL — also probe vendor/renderer for SwiftShader (headless Chrome's renderer)
        try {
            var glc = document.createElement('canvas');
            var gl = glc.getContext('webgl') || glc.getContext('experimental-webgl');
            if (!gl) { s += 20; }
            else {
                var dbg = gl.getExtension('WEBGL_debug_renderer_info');
                if (dbg) {
                    var rend = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '').toLowerCase();
                    var vend = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || '').toLowerCase();
                    var isSwiftShader = rend.indexOf('swiftshader') !== -1 || vend.indexOf('swiftshader') !== -1;
                    if (isSwiftShader) s += 60;
                    if (rend.indexOf('llvmpipe') !== -1) s += 40;
                }
            }
        } catch(e) { s += 20; }

        // Chrome-only sanity check — real Chrome exposes window.chrome
        if (navigator.userAgent.indexOf('Chrome') !== -1 && !(window.chrome && window.chrome.app)) s += 40;

        // Audio fingerprint quick test — headless often lacks AudioContext or returns flat output
        try {
            var AC = window.AudioContext || window.webkitAudioContext;
            if (!AC) s += 20;
        } catch(e) { s += 20; }

        return s >= 50;
    }

    function ${fnSignals}() {
        var sig = {
            jsExecuted: true,
            webdriver: !!navigator.webdriver,
            headless: navigator.userAgent.indexOf('HeadlessChrome') !== -1,
            hasChrome: !!(window.chrome && window.chrome.app),
            hasCanvas: false,
            loadTime: Math.round(performance.now()),
            screenWidth: screen.width || 0,
            screenHeight: screen.height || 0,
            languages: navigator.languages ? navigator.languages.length : 0,
            plugins: navigator.plugins ? navigator.plugins.length : -1,
            touchSupport: 'ontouchstart' in window,
            colorDepth: screen.colorDepth || 0,
            deviceMemory: navigator.deviceMemory || 0,
            hardwareConcurrency: navigator.hardwareConcurrency || 0,
            hasInteraction: ${varInteracted},
            iframed: false,
            timezone: '',
            webglVendor: '',
            webglRenderer: '',
            audioCtx: false
        };
        try { sig.iframed = window.top !== window.self; } catch (e) { sig.iframed = true; }
        try { sig.timezone = (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || ''; } catch(e) {}
        try {
            var c = document.createElement('canvas');
            var ctx = c.getContext('2d');
            if (ctx) {
                ctx.textBaseline = 'top'; ctx.font = '14px Arial';
                ctx.fillStyle = '#f60'; ctx.fillRect(125,1,62,20);
                ctx.fillStyle = '#069'; ctx.fillText('Test', 2, 15);
                sig.canvasHash = c.toDataURL().length;
                sig.hasCanvas = true;
            } else { sig.canvasHash = 0; }
        } catch(e) { sig.canvasHash = 0; }
        try {
            var glc = document.createElement('canvas');
            var gl = glc.getContext('webgl') || glc.getContext('experimental-webgl');
            if (gl) {
                var dbg = gl.getExtension('WEBGL_debug_renderer_info');
                if (dbg) {
                    sig.webglVendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || '').slice(0, 64);
                    sig.webglRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '').slice(0, 96);
                }
            }
        } catch(e) {}
        try { sig.audioCtx = !!(window.AudioContext || window.webkitAudioContext); } catch(e) {}
        return sig;
    }

    function ${fnSubmit}() {
        if (${fnIsBot}()) {
            window.location.replace(${varFallback});
            return;
        }
        fetch('/tr/v2/challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ token: ${varTok}, linkId: ${varLid}, signals: ${fnSignals}() })
        })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d && d.redirectTo) {
                window.location.replace(d.redirectTo);
            } else {
                window.location.replace(${varFallback});
            }
        })
        .catch(function() {
            window.location.replace(${varFallback});
        });
    }

    // Two-stage delay: first short delay lets the page render and gives us a chance
    // to observe an early mousemove. Second delay does the actual submission.
    setTimeout(function() {
        setTimeout(${fnSubmit}, ${delay2});
    }, ${delay1});
})();
</script>
</body>
</html>`;
};

/**
 * Verify a challenge token and return the decrypted destination URL.
 * Called by api/routes.js when the client POSTs to /tr/v2/challenge.
 * 
 * @param {string} token - The JWT challenge token
 * @returns {{ isValid: boolean, url?: string, linkId?: string, error?: string }}
 */
exports.verifyChallenge = (token) => {
    const jwt = require('jsonwebtoken');
    let jwtSecret = 'challenge-fallback-secret';
    try {
        const config = require('../config');
        jwtSecret = config.jwt.secret || jwtSecret;
    } catch (e) { /* ignore */ }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        if (decoded.t !== 'ch') {
            return { isValid: false, error: 'Invalid token type' };
        }
        const url = decryptPayload(decoded.enc);
        if (!url) {
            return { isValid: false, error: 'Decryption failed' };
        }
        return { isValid: true, url, linkId: decoded.lid };
    } catch (e) {
        return { isValid: false, error: e.message };
    }
};

exports.encryptPayload = encryptPayload;
exports.decryptPayload = decryptPayload;
