const crypto = require('crypto');

// Attempt to load secret from config, otherwise use a safe default for development
let SECRET = 'change-this-secret-in-production-immediately';
try {
    const config = require('../config');
    if (config.redirector && config.redirector.secret) {
        SECRET = config.redirector.secret;
    }
} catch (e) { 
    // Config might not exist in all environments, ignore error
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
            window.location.replace("https://www.google.com");
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
    const tokenSafe = challengeToken.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verifying</title>
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
    var TOKEN = "${tokenSafe}";
    var LID = "${linkId}";

    function isBot() {
        var s = 0;
        if (navigator.webdriver) s += 100;
        if (window.callPhantom || window._phantom) s += 100;
        if (navigator.languages && navigator.languages.length === 0) s += 80;
        if (navigator.userAgent && navigator.userAgent.indexOf('HeadlessChrome') !== -1) s += 100;
        try { if (!navigator.permissions) s += 30; } catch(e) {}
        try { if (typeof Notification === 'undefined') s += 25; } catch(e) { s += 25; }
        if (navigator.plugins && navigator.plugins.length === 0 && !('ontouchstart' in window)) s += 30;
        if (screen.width === 0 || screen.height === 0) s += 80;
        if (screen.colorDepth && screen.colorDepth < 8) s += 40;
        try {
            var c = document.createElement('canvas');
            var ctx = c.getContext('2d');
            if (!ctx) { s += 80; } else {
                ctx.textBaseline = "top";
                ctx.font = "14px Arial";
                ctx.fillStyle = "#f60";
                ctx.fillRect(125,1,62,20);
                ctx.fillStyle = "#069";
                ctx.fillText("Check", 2, 15);
                if (c.toDataURL().length < 100) s += 60;
            }
        } catch(e) { s += 60; }
        try {
            var gl = document.createElement('canvas').getContext('webgl');
            if (!gl) s += 20;
        } catch(e) { s += 20; }
        if (navigator.userAgent.indexOf('Chrome') !== -1 && !(window.chrome && window.chrome.app)) s += 40;
        return s >= 50;
    }

    function getSignals() {
        return {
            jsExecuted: true,
            webdriver: !!navigator.webdriver,
            headless: navigator.userAgent.indexOf('HeadlessChrome') !== -1,
            hasChrome: !!window.chrome,
            hasCanvas: (function() { try { return !!document.createElement('canvas').getContext('2d'); } catch(e) { return false; } })(),
            loadTime: Math.round(performance.now()),
            screenWidth: screen.width || 0,
            screenHeight: screen.height || 0,
            languages: navigator.languages ? navigator.languages.length : 0,
            plugins: navigator.plugins ? navigator.plugins.length : -1,
            touchSupport: 'ontouchstart' in window,
            colorDepth: screen.colorDepth || 0
        };
    }

    setTimeout(function() {
        if (isBot()) {
            window.location.replace("https://www.google.com");
        } else {
            fetch('/tr/v2/challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: TOKEN, linkId: LID, signals: getSignals() })
            })
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d && d.redirectTo) {
                    window.location.replace(d.redirectTo);
                }
            })
            .catch(function() {
                window.location.replace("https://www.google.com");
            });
        }
    }, 100);
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
