/**
 * Safe Redirect Chain v1.0
 * 
 * PURPOSE:
 * When a bot, crawler, AI scraper, or email scanner hits a tracking link,
 * instead of showing a static page, this module generates an UNLIMITED
 * chain of safe-looking redirect pages. Each page looks like a legitimate
 * web experience (security checks, loading pages, verification screens)
 * and automatically forwards to the next page in the chain.
 * 
 * The chain is infinite — bots never reach the real destination URL.
 * Each hop is cryptographically signed, so bots cannot skip ahead or
 * predict the next URL in the sequence.
 * 
 * FLOW:
 *   Bot hits /p/:token  →  bot detected  →  302 to /sr/:chainToken
 *   /sr/:chainToken  →  serves safe page  →  auto-redirects to next /sr/:chainToken2
 *   /sr/:chainToken2  →  serves different safe page  →  auto-redirects to /sr/:chainToken3
 *   ... (unlimited — chain wraps around page themes forever)
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Load secret from config, fallback for dev
let CHAIN_SECRET = 'chain-secret-change-in-production';
try {
    const config = require('../config');
    CHAIN_SECRET = config.jwt.secret || CHAIN_SECRET;
} catch (e) { /* ignore */ }

// Progress bar simulation constants — deliberately chosen so the bar never reaches 100%,
// giving bots the impression the page is still "loading" and encouraging them to wait/follow.
const PROGRESS_BASE = 15;       // Starting position (%)
const PROGRESS_STEP = 17;       // Increment per hop (prime number for visual variety)
const PROGRESS_MAX_RANGE = 75;  // Maximum range for modular wrapping
const PROGRESS_CAP = 92;        // Hard cap — never reaches 100% to imply "still loading"

/**
 * Safe page templates — each represents a different "legitimate" looking page.
 * Bots cycle through these endlessly. Each has:
 * - title: Page title
 * - heading: Main heading
 * - message: Body text
 * - icon: Emoji for visual distinction
 * - delay: Seconds before meta-refresh to next hop
 */
const SAFE_PAGE_THEMES = [
    {
        title: 'Security Verification',
        heading: 'Security Check',
        message: 'We are verifying your connection. Please wait while we ensure a secure browsing experience.',
        icon: '🔒',
        delay: 3
    },
    {
        title: 'Access Verification',
        heading: 'Verifying Access',
        message: 'Your request is being processed. This additional step helps protect against unauthorized access.',
        icon: '🛡️',
        delay: 4
    },
    {
        title: 'Loading Resource',
        heading: 'Loading...',
        message: 'The requested resource is being prepared. You will be redirected shortly.',
        icon: '⏳',
        delay: 3
    },
    {
        title: 'Connection Check',
        heading: 'Checking Connection',
        message: 'We are performing a routine connection check. This helps maintain service quality.',
        icon: '🔍',
        delay: 5
    },
    {
        title: 'DDoS Protection',
        heading: 'DDoS Protection',
        message: 'This site is protected. Your browser is being verified before you can access the content.',
        icon: '🌐',
        delay: 4
    },
    {
        title: 'Bot Protection',
        heading: 'Checking your browser',
        message: 'This process is automatic. Your browser will redirect you to the requested content shortly.',
        icon: '✅',
        delay: 3
    },
    {
        title: 'Content Delivery',
        heading: 'Optimizing Delivery',
        message: 'We are routing your request through our content delivery network for the best experience.',
        icon: '🚀',
        delay: 4
    },
    {
        title: 'Privacy Check',
        heading: 'Privacy Verification',
        message: 'We take privacy seriously. Your request is being securely processed.',
        icon: '🔐',
        delay: 5
    }
];

/**
 * Create a signed chain token for a specific hop in the redirect chain.
 * 
 * Token expiry is set to 30 minutes to allow long-running bot crawls.
 * When a token expires, the chain falls back to the static scanner-safe page —
 * the bot still never sees the real destination URL. New visits start a fresh chain.
 * 
 * @param {string} linkId - The original tracking link ID
 * @param {number} hopIndex - Current hop number in the chain
 * @returns {string} JWT token encoding the chain hop
 */
function createChainToken(linkId, hopIndex) {
    return jwt.sign(
        {
            lid: linkId,
            hop: hopIndex,
            t: 'sr', // type: safe redirect
            ts: Date.now()
        },
        CHAIN_SECRET,
        { expiresIn: '30m' } // 30-minute window per hop; chain restarts on new visits
    );
}

/**
 * Verify and decode a chain token.
 * 
 * @param {string} token - The JWT chain token
 * @returns {{ valid: boolean, linkId?: string, hopIndex?: number, error?: string }}
 */
function verifyChainToken(token) {
    try {
        const decoded = jwt.verify(token, CHAIN_SECRET);
        if (decoded.t !== 'sr') {
            return { valid: false, error: 'Invalid token type' };
        }
        return {
            valid: true,
            linkId: decoded.lid,
            hopIndex: decoded.hop
        };
    } catch (e) {
        return { valid: false, error: e.message };
    }
}

/**
 * Generate the HTML for a specific hop in the safe redirect chain.
 * 
 * Each page looks like a legitimate security/verification page.
 * It contains a meta-refresh that automatically redirects to the next hop.
 * The next hop token is embedded in the page.
 * 
 * @param {string} linkId - The original tracking link ID
 * @param {number} hopIndex - Current hop number (0-based, wraps around themes)
 * @param {string} nextHopUrl - The URL for the next hop in the chain
 * @returns {string} Full HTML page for this hop
 */
function generateHopPage(linkId, hopIndex, nextHopUrl) {
    // Cycle through themes infinitely
    const theme = SAFE_PAGE_THEMES[hopIndex % SAFE_PAGE_THEMES.length];
    
    // Generate a unique "ray ID" for each hop to look authentic
    const rayId = crypto.randomBytes(8).toString('hex');
    
    // Vary the progress percentage based on hop (never reaches 100%)
    const progress = Math.min(PROGRESS_BASE + ((hopIndex * PROGRESS_STEP) % PROGRESS_MAX_RANGE), PROGRESS_CAP);

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<meta http-equiv="refresh" content="${theme.delay};url=${escapeAttr(nextHopUrl)}">
<title>${escapeHtml(theme.title)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;overflow:hidden}
.container{text-align:center;padding:2rem;max-width:480px}
.icon{font-size:3rem;margin-bottom:1rem;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.1);opacity:.8}}
h1{font-size:1.5rem;font-weight:600;margin-bottom:.75rem}
p{font-size:.95rem;color:rgba(255,255,255,.85);line-height:1.6;margin-bottom:1.5rem}
.progress-bar{width:100%;height:4px;background:rgba(255,255,255,.2);border-radius:2px;overflow:hidden;margin-bottom:1rem}
.progress-fill{height:100%;background:#fff;border-radius:2px;animation:loading ${theme.delay}s ease-in-out forwards}
@keyframes loading{0%{width:${progress - 10}%}100%{width:${progress}%}}
.meta{font-size:.7rem;color:rgba(255,255,255,.45);margin-top:2rem}
.spinner{width:40px;height:40px;margin:0 auto 1rem;border:3px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
<div class="icon">${theme.icon}</div>
<div class="spinner"></div>
<h1>${escapeHtml(theme.heading)}</h1>
<p>${escapeHtml(theme.message)}</p>
<div class="progress-bar"><div class="progress-fill"></div></div>
<div class="meta">Ray ID: ${rayId} &bull; Performance &amp; security by SafeGuard</div>
</div>
<noscript><p style="text-align:center;margin:2rem;">If you are not redirected, <a href="${escapeAttr(nextHopUrl)}" style="color:#fff;">click here</a>.</p></noscript>
</body>
</html>`;
}

/**
 * Start a new redirect chain for a detected bot.
 * Returns the URL for the first hop.
 * 
 * @param {string} linkId - The original tracking link ID
 * @param {string} baseUrl - The base URL (protocol + domain)
 * @returns {{ chainUrl: string, token: string }}
 */
function startChain(linkId, baseUrl) {
    const token = createChainToken(linkId, 0);
    const chainUrl = `${baseUrl}/sr/${token}`;
    return { chainUrl, token };
}

/**
 * Process a chain hop request.
 * Verifies the current token, generates the next hop, and returns the page HTML.
 * 
 * @param {string} token - Current hop's JWT token
 * @param {string} baseUrl - The base URL (protocol + domain)
 * @returns {{ html: string, linkId: string, hopIndex: number, nextUrl: string } | null}
 */
function processHop(token, baseUrl) {
    const verification = verifyChainToken(token);
    if (!verification.valid) {
        return null;
    }

    const { linkId, hopIndex } = verification;
    const nextHopIndex = hopIndex + 1;
    
    // Create the next hop token
    const nextToken = createChainToken(linkId, nextHopIndex);
    const nextUrl = `${baseUrl}/sr/${nextToken}`;
    
    // Generate the HTML page for the current hop
    const html = generateHopPage(linkId, hopIndex, nextUrl);
    
    return {
        html,
        linkId,
        hopIndex,
        nextUrl
    };
}

// HTML escape helpers
function escapeHtml(str) {
    return (str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

function escapeAttr(str) {
    return escapeHtml(str);
}

module.exports = {
    createChainToken,
    verifyChainToken,
    generateHopPage,
    startChain,
    processHop,
    SAFE_PAGE_THEMES
};
