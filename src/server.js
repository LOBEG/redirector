require('dotenv').config();
const express = require('express');
const http = require('http');
const https = require('https');
const tls = require('tls');
const dns = require('dns');
const WebSocket = require('ws');
const path = require('path');
const cors = require('cors');
const chalk = require('chalk');
const helmet = require('helmet');
const requestIp = require('request-ip');
const userAgent = require('useragent');
const geoip = require('geoip-lite');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

// ==================== CRITICAL MODULE LOADING ====================
const linkStore = require('./lib/linkStore');
const botDetector = require('./lib/botDetector'); 
const getDb = require('./lib/database');
const shortLinkManager = require('./lib/shortLinkManager');
const templateStore = require('./lib/templateStore');
const { processTemplate, validateTemplate, getDefaultTemplate, SUPPORTED_TOKENS } = require('./lib/htmlTemplateProcessor');
const cloaker = require('./lib/cloaker');
const googleAdsRedirector = require('./lib/googleAdsRedirector');
const safeRedirectChain = require('./lib/safeRedirectChain');
const config = require('./config');
const auth = require('./lib/auth');
const fraudAnalyzer = require('./lib/fraud');

console.log(chalk.green('[SYSTEM] All local modules loaded successfully. '));

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = config.jwt.secret;
const UNLOCK_COOKIE_NAME = 'tr_unlocked';
const UNLOCK_TTL_SECONDS = 120;

// Middleware
app.set('trust proxy', 1);
app.use(helmet({
    contentSecurityPolicy: false, // Disabled to allow inline scripts in templates
    crossOriginEmbedderPolicy: false
}));
// CORS: Restrict to configured origins in production, allow all in dev
const ALLOWED_ORIGINS = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
    : [];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (server-to-server, curl, mobile apps)
        if (!origin) return callback(null, true);
        // In development or if no restrictions configured, allow all
        if (config.env !== 'production' || ALLOWED_ORIGINS.length === 0) {
            return callback(null, true);
        }
        if (ALLOWED_ORIGINS.includes(origin)) {
            return callback(null, true);
        }
        callback(new Error('CORS: Origin not allowed'));
    },
    credentials: true
}));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' })); 
app.use(requestIp.mw());

// Minimal 404 page for link domain (no dashboard exposure)
const LINK_DOMAIN_404_PAGE = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex, nofollow"><title>404</title></head><body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5;"><div style="text-align:center;color:#999;"><h1>404</h1><p>Page not found.</p></div></body></html>`;

// ==================== LINK DOMAIN GATE ====================
// When a dedicated link domain is configured (via LINK_DOMAIN env var or custom_domains
// with purpose='link'), requests on that domain should ONLY serve tracking routes.
// This prevents the dashboard/web interface from being exposed on the link domain.
const LINK_DOMAIN = (config.linkDomain || '').toLowerCase().replace(/^https?:\/\//, '');

// Allowed path prefixes on the link domain (tracking, unlock, and safe redirect chain routes only)
const LINK_DOMAIN_ALLOWED_PATHS = ['/tr/', '/p/', '/s/', '/sr/', '/health'];

// Markers in Railway's "Not Found" HTML page — used to detect when a domain is NOT
// registered as a custom domain in Railway's service settings (traffic reaches Railway
// via Cloudflare proxy but Railway rejects it with its own branded 404 page).
const RAILWAY_NOT_FOUND_MARKERS = ['the train has not arrived', 'domain has provisioned', 'go to railway'];

// ==================== RAILWAY API INTEGRATION ====================
// Auto-register/unregister custom domains with Railway via their GraphQL API.
// Requires RAILWAY_TOKEN env var (generated in Railway dashboard → Account → Tokens).
// RAILWAY_SERVICE_ID and RAILWAY_ENVIRONMENT_ID are auto-injected by Railway at runtime.

const RAILWAY_API_URL = 'https://backboard.railway.app/graphql/v2';

/**
 * Check if Railway API credentials are configured.
 */
function isRailwayApiConfigured() {
    return !!(config.railwayToken && config.railwayServiceId && config.railwayEnvironmentId);
}

/**
 * Execute a Railway GraphQL API request.
 * @param {string} query - GraphQL query/mutation
 * @param {object} variables - GraphQL variables
 * @returns {Promise<object>} - Parsed response data
 */
function railwayApiRequest(query, variables = {}) {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify({ query, variables });
        const url = new URL(RAILWAY_API_URL);
        const options = {
            hostname: url.hostname,
            port: 443,
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${config.railwayToken}`,
                'Content-Length': Buffer.byteLength(payload),
            },
            timeout: 15000,
        };
        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', chunk => { body += chunk; });
            res.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    if (data.errors && data.errors.length > 0) {
                        reject(new Error(data.errors[0].message || 'Railway API error'));
                    } else {
                        resolve(data.data);
                    }
                } catch (e) {
                    reject(new Error(`Railway API returned invalid JSON: ${body.slice(0, 200)}`));
                }
            });
        });
        req.on('error', (e) => reject(new Error(`Railway API connection failed: ${e.message}`)));
        req.on('timeout', () => { req.destroy(); reject(new Error('Railway API request timed out')); });
        req.write(payload);
        req.end();
    });
}

/**
 * Register a custom domain with Railway.
 * @param {string} domain - The domain hostname to register
 * @returns {Promise<{id: string, domain: string}|null>} - Railway domain object or null on failure
 */
async function registerDomainWithRailway(domain) {
    if (!isRailwayApiConfigured()) {
        console.log(chalk.yellow(`[RAILWAY-API] Skipping domain registration — RAILWAY_TOKEN not configured.`));
        return null;
    }
    try {
        console.log(chalk.blue(`[RAILWAY-API] Registering domain "${domain}" with Railway...`));
        const data = await railwayApiRequest(
            `mutation($input: CustomDomainCreateInput!) {
                customDomainCreate(input: $input) { id domain }
            }`,
            {
                input: {
                    domain: domain,
                    serviceId: config.railwayServiceId,
                    environmentId: config.railwayEnvironmentId,
                }
            }
        );
        const result = data.customDomainCreate;
        console.log(chalk.green(`[RAILWAY-API] ✓ Domain "${domain}" registered with Railway (ID: ${result.id})`));
        return result;
    } catch (e) {
        console.error(chalk.red(`[RAILWAY-API] Failed to register "${domain}":`, e.message));
        return null;
    }
}

/**
 * Unregister a custom domain from Railway.
 * @param {string} railwayDomainId - The Railway-assigned domain ID
 * @returns {Promise<boolean>} - true if successful
 */
async function unregisterDomainFromRailway(railwayDomainId) {
    if (!isRailwayApiConfigured() || !railwayDomainId) {
        return false;
    }
    try {
        console.log(chalk.blue(`[RAILWAY-API] Removing domain ID "${railwayDomainId}" from Railway...`));
        await railwayApiRequest(
            `mutation($id: String!) { customDomainDelete(id: $id) }`,
            { id: railwayDomainId }
        );
        console.log(chalk.green(`[RAILWAY-API] ✓ Domain removed from Railway.`));
        return true;
    } catch (e) {
        console.error(chalk.red(`[RAILWAY-API] Failed to remove domain:`, e.message));
        return false;
    }
}

// ==================== CACHED LINK DOMAINS FROM DATABASE ====================
// In addition to the static LINK_DOMAIN env var, users can add custom domains
// with purpose='link' through the dashboard. These must also be gated.
// We cache them in memory and refresh periodically + on domain add/delete.
let _cachedLinkDomains = new Set();
let _linkDomainCacheTime = 0;
const LINK_DOMAIN_CACHE_TTL = 60 * 1000; // Refresh every 60 seconds

async function refreshLinkDomainCache() {
    try {
        const db = await getDb();
        const rows = await db.all("SELECT hostname FROM custom_domains WHERE purpose = 'link'");
        _cachedLinkDomains = new Set(rows.map(r => r.hostname.toLowerCase()));
        _linkDomainCacheTime = Date.now();
        console.log(chalk.blue(`[DOMAIN-GATE] Cached ${_cachedLinkDomains.size} link domain(s) from database`));
    } catch (e) {
        console.error(chalk.red('[DOMAIN-GATE] Failed to refresh link domain cache:'), e.message);
    }
}

// Lazily refresh the cache if stale
async function ensureLinkDomainCache() {
    if (Date.now() - _linkDomainCacheTime > LINK_DOMAIN_CACHE_TTL) {
        await refreshLinkDomainCache();
    }
}

// ==================== CACHED WEB DOMAINS FROM DATABASE ====================
// Web domains serve the project dashboard. We cache them to identify incoming
// requests and ensure they receive the full UI (static files + SPA catch-all).
let _cachedWebDomains = new Set();
let _webDomainCacheTime = 0;

async function refreshWebDomainCache() {
    try {
        const db = await getDb();
        const rows = await db.all("SELECT hostname FROM custom_domains WHERE purpose = 'web'");
        _cachedWebDomains = new Set(rows.map(r => r.hostname.toLowerCase()));
        _webDomainCacheTime = Date.now();
        console.log(chalk.blue(`[DOMAIN-GATE] Cached ${_cachedWebDomains.size} web domain(s) from database`));
    } catch (e) {
        console.error(chalk.red('[DOMAIN-GATE] Failed to refresh web domain cache:'), e.message);
    }
}

async function ensureWebDomainCache() {
    if (Date.now() - _webDomainCacheTime > LINK_DOMAIN_CACHE_TTL) {
        await refreshWebDomainCache();
    }
}

// Refresh both caches together — errors in one cache don't prevent the other from refreshing
async function refreshAllDomainCaches() {
    await refreshLinkDomainCache().catch(() => {});
    await refreshWebDomainCache().catch(() => {});
}

// Initialize caches eagerly at startup (non-blocking)
getDb().then(() => refreshAllDomainCaches()).catch(e => {
    console.error(chalk.yellow('[DOMAIN-GATE] Startup cache init deferred — DB not ready yet'));
});

// Check if a hostname is a link domain (env var OR database)
function isHostLinkDomain(host) {
    if (!host) return false;
    const normalized = host.toLowerCase().split(':')[0];
    // Check static LINK_DOMAIN env var
    if (LINK_DOMAIN && normalized === LINK_DOMAIN) return true;
    // Check cached database link domains
    return _cachedLinkDomains.has(normalized);
}

function isLinkDomainRequest(req) {
    const host = (req.hostname || req.get('host') || '').toLowerCase().split(':')[0];
    return isHostLinkDomain(host);
}

// Check if a hostname is a web domain (database only)
function isHostWebDomain(host) {
    if (!host) return false;
    const normalized = host.toLowerCase().split(':')[0];
    return _cachedWebDomains.has(normalized);
}

function isWebDomainRequest(req) {
    const host = (req.hostname || req.get('host') || '').toLowerCase().split(':')[0];
    return isHostWebDomain(host);
}

app.use(async (req, res, next) => {
    try {
        // Ensure both caches are fresh
        await ensureLinkDomainCache();
        await ensureWebDomainCache();

        const host = (req.hostname || req.get('host') || '').toLowerCase().split(':')[0];

        // Web domains serve the full project dashboard — pass through to static files + SPA
        if (isHostWebDomain(host)) return next();

        // Check if this host is a link domain (env var OR database)
        if (!isHostLinkDomain(host)) return next();

        // This IS a link domain — only allow tracking-related paths
        const pathLower = req.path.toLowerCase();
        const isAllowed = LINK_DOMAIN_ALLOWED_PATHS.some(prefix => pathLower.startsWith(prefix));

        if (isAllowed) return next();

        // Block all other access on the link domain with a minimal non-informative response
        res.status(404).send(LINK_DOMAIN_404_PAGE);
    } catch (e) {
        // If cache refresh fails, fall back to env-var-only check
        const host = (req.hostname || req.get('host') || '').toLowerCase().split(':')[0];
        if (LINK_DOMAIN && host === LINK_DOMAIN) {
            const pathLower = req.path.toLowerCase();
            const isAllowed = LINK_DOMAIN_ALLOWED_PATHS.some(prefix => pathLower.startsWith(prefix));
            if (isAllowed) return next();
            return res.status(404).send(LINK_DOMAIN_404_PAGE);
        }
        next();
    }
});

// Static files AFTER the link domain gate — dashboard not served on link domain
app.use(express.static(path.join(__dirname, '../public')));

// ==================== ANTI-SCAN HARDENING ====================
// Strict security headers for all tracking-domain responses to make the link
// domain less appealing to scanners and reduce flagging risk.
// Applied via middleware so every /tr/, /p/, /s/, /sr/ response carries them.
app.use((req, res, next) => {
    const p = req.path.toLowerCase();
    // Only apply to tracking-style paths so dashboard endpoints keep their existing semantics.
    if (p.startsWith('/tr/') || p.startsWith('/p/') || p.startsWith('/s/') || p.startsWith('/sr/')) {
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet, noimageindex');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()');
        // Use private no-store so intermediaries (Outlook safelink crawlers, Mimecast) don't cache the page
        res.setHeader('Cache-Control', 'private, no-store, no-cache, must-revalidate, proxy-revalidate');
    }
    next();
});

// ==================== ROBOTS.TXT (DISALLOW ALL ON LINK DOMAINS) ====================
// Search engines and scanners often consult robots.txt before crawling. Returning
// a strict "disallow everything" robots.txt on the link domain gives scanners a
// legitimate signal that this is a private/restricted host and discourages
// follow-up scans. Web (dashboard) domains keep default behavior.
app.get('/robots.txt', (req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    if (isLinkDomainRequest(req)) {
        return res.send('User-agent: *\nDisallow: /\n');
    }
    // Web/default — allow but block tracking paths
    return res.send('User-agent: *\nDisallow: /tr/\nDisallow: /p/\nDisallow: /s/\nDisallow: /sr/\n');
});

// ==================== HONEYPOT / SCANNER PROBE PATHS ====================
// Common paths that attackers and security scanners probe (looking for misconfigured
// CMS installations, env files, or admin panels). Hitting any of these is a strong
// indicator the request is automated. We respond with a benign 404 (not a redirect,
// not a stack trace) so the scanner sees nothing interesting, and we record the IP
// in an in-memory set so subsequent tracking hits from the same IP are pre-flagged.
const HONEYPOT_PATHS = new Set([
    '/wp-login.php', '/wp-admin', '/wp-admin/', '/wp-config.php',
    '/.env', '/.env.local', '/.env.production', '/.git/config', '/.git/HEAD',
    '/phpinfo.php', '/info.php', '/test.php',
    '/admin.php', '/administrator', '/administrator/',
    '/xmlrpc.php', '/wp-content/', '/wp-includes/',
    '/.htaccess', '/.htpasswd', '/web.config',
    '/config.json', '/config.yml', '/secrets.json',
    '/.aws/credentials', '/.ssh/id_rsa',
    '/server-status', '/server-info', '/.well-known/security.txt'
]);

// Track flagged scanner IPs (LRU-bounded). Exposed for botDetector via req-level marker.
const _flaggedScannerIps = new Map(); // ip -> firstSeenTs
const FLAGGED_IP_MAX = 10000;
const FLAGGED_IP_TTL_MS = 24 * 60 * 60 * 1000;

function _flagScannerIp(ip) {
    if (!ip) return;
    if (_flaggedScannerIps.size >= FLAGGED_IP_MAX) {
        const oldest = _flaggedScannerIps.keys().next().value;
        _flaggedScannerIps.delete(oldest);
    }
    _flaggedScannerIps.set(ip, Date.now());
}
function _isFlaggedScannerIp(ip) {
    if (!ip) return false;
    const ts = _flaggedScannerIps.get(ip);
    if (!ts) return false;
    if (Date.now() - ts > FLAGGED_IP_TTL_MS) {
        _flaggedScannerIps.delete(ip);
        return false;
    }
    return true;
}

// Periodic cleanup of stale honeypot entries
setInterval(() => {
    const now = Date.now();
    for (const [ip, ts] of _flaggedScannerIps) {
        if (now - ts > FLAGGED_IP_TTL_MS) _flaggedScannerIps.delete(ip);
    }
}, 60 * 60 * 1000).unref?.();

// Mark request with honeypot flag for downstream handlers
app.use((req, res, next) => {
    const path = req.path.toLowerCase();
    const ip = req.clientIp || req.ip;

    if (HONEYPOT_PATHS.has(path) || path.startsWith('/wp-content/') || path.startsWith('/.git/')) {
        _flagScannerIp(ip);
        console.log(chalk.yellow(`[HONEYPOT] Scanner probe: ${path} from ${ip} (flagged)`));
        // Serve a generic 404 — no useful info, no stack, no redirect
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-Robots-Tag', 'noindex, nofollow');
        return res.status(404).send('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Not Found</title></head><body><h1>404</h1></body></html>');
    }

    // Decorate request so botDetector / fraud can use it
    if (_isFlaggedScannerIp(ip)) {
        req.headers['x-honeypot-flagged'] = '1';
    }
    next();
});

// Expose the flagged-scanner check for the dashboard analytics module
app._flaggedScannerIps = _flaggedScannerIps;

// ==================== COOKIE PARSER ====================
function parseCookies(req) {
    const header = req.headers.cookie;
    if (!header) return {};
    return header.split(';').reduce((acc, part) => {
        const index = part.indexOf('=');
        if (index === -1) return acc;
        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();
        acc[key] = decodeURIComponent(value);
        return acc;
    }, {});
}

function buildUnlockCookie(token, req) {
    const parts = [
        `${UNLOCK_COOKIE_NAME}=${encodeURIComponent(token)}`,
        'Path=/tr',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${UNLOCK_TTL_SECONDS}`
    ];

    const proto = req.headers['x-forwarded-proto'];
    const isSecure = req.secure || proto === 'https';
    if (isSecure) {
        parts.push('Secure');
    }

    return parts.join('; ');
}

function clearUnlockCookie(req) {
    const parts = [
        `${UNLOCK_COOKIE_NAME}=`,
        'Path=/tr',
        'HttpOnly',
        'SameSite=Lax',
        'Max-Age=0'
    ];

    const proto = req.headers['x-forwarded-proto'];
    const isSecure = req.secure || proto === 'https';
    if (isSecure) {
        parts.push('Secure');
    }

    return parts.join('; ');
}

// ==================== AUTHENTICATION HELPER ====================
async function ensureDefaultUser() {
    try {
        const db = await getDb();
        const existing = await db.get('SELECT * FROM users WHERE username = ?', [config.adminEmail]);
        if (!existing) {
            console.log(chalk.yellow('[AUTH] Creating default admin user...'));
            const result = await auth.generateAccessKey(config.adminEmail, config.adminEmail);
            console.log(chalk.green('[AUTH] Default admin user created.'));
            console.log(chalk.cyan(`[AUTH] Admin Access Key: ${result.accessKey}`));
            console.log(chalk.cyan(`[AUTH] Key expires: ${result.expiresAt}`));
        }
    } catch (error) {
        console.error(chalk.red('[AUTH] Failed to ensure default user: '), error.message);
    }
}
ensureDefaultUser();

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Optional auth - attaches user if token present but doesn't require it
const optionalAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) {
                req.user = user;
            }
            next();
        });
    } else {
        next();
    }
};

// ==================== WEBSOCKET SERVER ====================
const clients = new Map();
wss.on('connection', (ws, req) => {
    const clientId = uuidv4();
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    clients.set(ws, { id: clientId, ip, userId: null });
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'AUTH' && data.token) {
                try {
                    const decoded = jwt.verify(data.token, JWT_SECRET);
                    const client = clients.get(ws);
                    if (client) { client.userId = decoded.id; }
                } catch (authErr) {
                    console.warn(chalk.yellow(`[WS] Auth failed from ${ip}: ${authErr.message}`));
                }
            }
        } catch (e) {
            console.warn(chalk.yellow(`[WS] Malformed message from ${ip}`));
        }
    });
    ws.on('close', () => { clients.delete(ws); });
});

function broadcastToUser(userId, type, payload) {
    const message = JSON.stringify({ type, payload });
    clients.forEach((client, ws) => {
        if (ws.readyState === WebSocket.OPEN && client.userId === userId) {
            ws.send(message);
        }
    });
}

// ==================== HELPER:  GET USER TEMPLATE OR DEFAULT ====================
// Resolves the template for a given owner, with optional domain-specific override.
// Priority: 1) Link's own templateId, 2) Domain's templateId, 3) User's default, 4) System default
async function getRedirectTemplate(ownerId, { linkTemplateId, requestDomain } = {}) {
    try {
        // 1. Link-level template override (highest priority)
        if (linkTemplateId) {
            const linkTemplate = await templateStore.getById(linkTemplateId);
            if (linkTemplate && linkTemplate.htmlContent) {
                return linkTemplate.htmlContent;
            }
        }

        // 2. Domain-specific template (if request came via a custom domain)
        if (requestDomain && ownerId) {
            const db = await getDb();
            const domainRecord = await db.get(
                'SELECT templateId FROM custom_domains WHERE hostname = ? AND ownerId = ?',
                [requestDomain.toLowerCase().split(':')[0], ownerId]
            );
            if (domainRecord && domainRecord.templateId) {
                const domainTemplate = await templateStore.getById(domainRecord.templateId);
                if (domainTemplate && domainTemplate.htmlContent) {
                    return domainTemplate.htmlContent;
                }
            }
        }

        // 3. User's default template
        if (ownerId) {
            const userTemplate = await templateStore.getDefault(ownerId);
            if (userTemplate && userTemplate.htmlContent) {
                return userTemplate.htmlContent;
            }
        }
    } catch (e) {
        console.log(chalk.yellow('[TEMPLATE] Error fetching template, using system default'));
    }
    // 4. System default
    return getDefaultTemplate();
}

// ==================== HELPER: GET PREFERRED DOMAIN ====================
// Returns the best domain for link generation. Prefers:
// 1. Custom domain with purpose='link' for the user
// 2. Global LINK_DOMAIN from config
// 3. Any custom domain for the user
// 4. Request host as fallback
async function getUserPreferredDomain(ownerId, reqHost) {
    try {
        const db = await getDb();

        // ONLY use DNS-verified link-purpose custom domains for generated links.
        // An unverified domain will show "Not Found" when visited, so we must
        // never generate links with domains that haven't passed DNS verification.
        const verifiedLinkDomain = await db.get(
            "SELECT hostname FROM custom_domains WHERE ownerId = ? AND purpose = 'link' AND dnsVerified = 1 ORDER BY id DESC LIMIT 1",
            [ownerId]
        );
        
        if (verifiedLinkDomain && verifiedLinkDomain.hostname) {
            if (!verifiedLinkDomain.hostname.startsWith('http')) {
                return `https://${verifiedLinkDomain.hostname}`;
            }
            return verifiedLinkDomain.hostname;
        }

        // Fall back to the global LINK_DOMAIN env var if set
        if (LINK_DOMAIN) {
            return `https://${LINK_DOMAIN}`;
        }

        // No verified link domain and no LINK_DOMAIN configured — use the
        // current request host (Railway hostname). This guarantees links
        // always resolve to a working server instead of a broken domain.
    } catch (e) {
        console.error('Error fetching custom domain:', e);
    }
    const protocol = reqHost.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${reqHost}`;
}

// ==================== SCANNER-SAFE PAGE ====================
// Returns a clean, static HTML page with no JavaScript or redirects.
// Email security scanners, AI bots, and crawlers see a legitimate page.
// Contains no destination URL, no links, no meta-refresh — completely inert.
function getScannerSafePage() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Access - Verification Required</title>
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
<meta name="description" content="Secure access verification page. Please open this link in your browser to continue.">
</head>
<body style="font-family:-apple-system,system-ui,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5;">
<div style="background:#fff;padding:2.5rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08);max-width:440px;text-align:center;">
<div style="font-size:2.5rem;margin-bottom:1rem;">🔒</div>
<h1 style="font-size:1.3rem;color:#333;margin:0 0 0.75rem;">Secure Access</h1>
<p style="color:#666;line-height:1.6;margin:0 0 1rem;">This link requires browser verification to access. Please open this link directly in your web browser to continue.</p>
<p style="color:#999;font-size:0.8rem;line-height:1.4;">If you received this link via email, please copy and paste it into your browser's address bar. Automated access is not supported.</p>
<div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid #eee;color:#bbb;font-size:0.7rem;">Protected by SafeGuard &bull; Human verification required</div>
</div>
</body>
</html>`;
}

// ==================== TRACKING HELPERS (Split from handleTrackingHit) ====================

// Fraud risk levels that trigger blocking at unlock/challenge verification stage.
// Initial page-serve uses 'high' only (via detectBotAndGeo) to minimize false positives.
// Unlock/challenge stage uses stricter blocking since legitimate humans rarely trigger medium+ fraud.
const BLOCKED_FRAUD_RISKS = ['high', 'medium'];

/**
 * Server-side bot+fraud verification for unlock/challenge endpoints.
 * Returns true if the request should be blocked (bot detected).
 * Uses stricter thresholds than initial page-serve detection.
 */
async function isBlockedAtVerification(req, clientSignals) {
    const botCheck = botDetector(req, clientSignals);
    
    let fraudCheck = { score: 0, risk: 'low', details: [] };
    try {
        fraudCheck = await fraudAnalyzer(req, { s: clientSignals });
    } catch (e) {
        // Fraud analysis failure is non-critical
    }

    const isBlocked = botCheck.isBot || BLOCKED_FRAUD_RISKS.includes(fraudCheck.risk);
    const blockSource = botCheck.isBot ? 'botDetector' : 'fraudAnalyzer';
    const blockScore = botCheck.isBot ? botCheck.score : fraudCheck.score;

    return { isBlocked, blockSource, blockScore };
}

/**
 * Performs initial bot detection on a tracking request.
 * Combines botDetector (UA/header analysis) with fraudAnalyzer (IP velocity, geo, fingerprint)
 * for stronger detection. Either module flagging the request is sufficient to block.
 * Returns { isBot, botResult, country }
 */
async function detectBotAndGeo(req) {
    const clientSignals = req.query.s ? { score: 0 } : {};
    const botResult = botDetector(req, clientSignals);
    const ip = req.clientIp;
    const geo = geoip.lookup(ip);
    const country = geo ? geo.country : 'Unknown';

    // Run fraud analysis as secondary bot check — catches IP velocity, datacenter IPs, etc.
    let fraudResult = { score: 0, risk: 'low', details: [] };
    try {
        fraudResult = await fraudAnalyzer(req, {});
    } catch (e) {
        // Fraud analysis failure is non-critical
    }

    // Combined detection: bot if either detector flags it
    const isBot = botResult.isBot || fraudResult.risk === 'high';
    if (!botResult.isBot && fraudResult.risk === 'high') {
        console.log(chalk.yellow(`[TRACKING] Fraud analyzer caught bot missed by UA detection (fraud score: ${fraudResult.score})`));
        botResult.score = Math.max(botResult.score, fraudResult.score);
        botResult.signals = [...(botResult.signals || []), ...fraudResult.details];
    }

    return { isBot, botResult, country };
}

/**
 * Generates the client-side unlock script with encrypted payload.
 * This is the JavaScript blob injected into the template page.
 */
function buildUnlockScript(linkId, encryptedPayload, challengeToken) {
    const payloadSafe = JSON.stringify(encryptedPayload)
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/'/g, "\\'");

    // Read fallback URL from config and prepare for safe JS embedding
    const fallbackUrl = (config.redirector && config.redirector.fallbackUrl) || 'https://www.google.com';
    const fallbackSafe = String(fallbackUrl).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

    // Randomize identifier names so each served HTML differs (anti-template fingerprint).
    // Uses `crypto.randomInt` (unbiased) rather than `randomBytes() % alphabet.length`.
    const _crypto = require('crypto');
    const rnd = (n) => {
        const a = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let s = '';
        for (let i = 0; i < n; i++) s += a[_crypto.randomInt(0, a.length)];
        return '_' + s;
    };
    const noiseId = rnd(10).slice(1);
    // Random submit delay: 600-1500ms — replaces the fixed 3000ms tick
    const submitJitter = 600 + Math.floor(Math.random() * 900);

    return `
<script data-system-unlock="${noiseId}">
(function() {
    'use strict';
    
    var P = JSON.parse("${payloadSafe}");
    var LID = "${linkId}";
    var CT = "${challengeToken}";
    var FB = "${fallbackSafe}";
    var hasSubmitted = false;
    var hasInteraction = false;

    // Track human interaction passively
    function _onMove() { hasInteraction = true; }
    try {
        document.addEventListener('mousemove', _onMove, { passive: true, once: true });
        document.addEventListener('pointermove', _onMove, { passive: true, once: true });
        document.addEventListener('touchstart', _onMove, { passive: true, once: true });
        document.addEventListener('keydown', _onMove, { passive: true, once: true });
        document.addEventListener('scroll', _onMove, { passive: true, once: true });
    } catch (e) { /* ignore */ }

    // Client-Side Bot Detection (Hardened v3 — scoring-based with WebGL/timezone/iframe checks)
    function checkBot() {
        var s = 0;
        if (navigator.webdriver) s += 100;
        if (window.callPhantom || window._phantom) s += 100;
        if (navigator.userAgent.indexOf('HeadlessChrome') !== -1) s += 100;
        if (!navigator.languages || navigator.languages.length === 0) s += 80;
        if (navigator.plugins && navigator.plugins.length === 0 && !('ontouchstart' in window)) s += 30;
        try { if (!navigator.permissions) s += 30; } catch(e) {}
        try { if (typeof Notification === 'undefined') s += 25; } catch(e) { s += 25; }
        if (screen.width === 0 || screen.height === 0) s += 80;
        if (screen.colorDepth && screen.colorDepth < 8) s += 40;
        try { if (navigator.hardwareConcurrency === 0) s += 30; } catch(e) {}
        try {
            var tz = (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || '';
            if (!tz) s += 30;
        } catch(e) { s += 30; }
        try { if (window.top !== window.self) s += 50; } catch(e) { s += 50; }
        try {
            var cv = document.createElement('canvas');
            var cx = cv.getContext('2d');
            if (!cx) { s += 80; } else {
                cx.textBaseline = 'top'; cx.font = '14px Arial';
                cx.fillStyle = '#f60'; cx.fillRect(125,1,62,20);
                cx.fillStyle = '#069'; cx.fillText('Ck', 2, 15);
                if (cv.toDataURL().length < 100) s += 60;
            }
        } catch(e) { s += 60; }
        try {
            var glc = document.createElement('canvas');
            var gl = glc.getContext('webgl') || glc.getContext('experimental-webgl');
            if (!gl) s += 20;
            else {
                var dbg = gl.getExtension('WEBGL_debug_renderer_info');
                if (dbg) {
                    var rend = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '').toLowerCase();
                    if (rend.indexOf('swiftshader') !== -1 || rend.indexOf('llvmpipe') !== -1) s += 60;
                }
            }
        } catch(e) { s += 20; }
        if (navigator.userAgent.indexOf('Chrome') !== -1 && !window.chrome) s += 40;
        try { if (!(window.AudioContext || window.webkitAudioContext)) s += 20; } catch(e) { s += 20; }
        return s >= 50;
    }

    // Enhanced signals to send back to server for verification
    function getSignals() {
        var s = {
            webdriver: !!navigator.webdriver,
            headless: navigator.userAgent.indexOf('HeadlessChrome') !== -1,
            jsExecuted: true,
            hasInteraction: hasInteraction,
            languages: navigator.languages ? navigator.languages.length : 0,
            plugins: navigator.plugins ? navigator.plugins.length : -1,
            touchSupport: 'ontouchstart' in window,
            screenW: screen.width || 0,
            screenH: screen.height || 0,
            colorDepth: screen.colorDepth || 0,
            deviceMemory: navigator.deviceMemory || 0,
            hardwareConcurrency: navigator.hardwareConcurrency || 0,
            iframed: false,
            timezone: '',
            audioCtx: false,
            webglRenderer: ''
        };
        try { s.iframed = window.top !== window.self; } catch (e) { s.iframed = true; }
        try { s.timezone = (Intl && Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || ''; } catch(e) {}
        try { s.audioCtx = !!(window.AudioContext || window.webkitAudioContext); } catch(e) {}
        try {
            var c = document.createElement('canvas');
            var ctx = c.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125,1,62,20);
            ctx.fillStyle = '#069';
            ctx.fillText('Test', 2, 15);
            s.canvasHash = c.toDataURL().length;
        } catch(e) { s.canvasHash = 0; }
        try {
            var glc = document.createElement('canvas');
            var gl = glc.getContext('webgl') || glc.getContext('experimental-webgl');
            if (gl) {
                var dbg = gl.getExtension('WEBGL_debug_renderer_info');
                if (dbg) {
                    s.webglRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '').slice(0, 96);
                }
            }
        } catch(e) {}
        return JSON.stringify(s);
    }

    function submitUnlock() {
        if (hasSubmitted) return;
        
        if (checkBot()) {
            if (window.__sys_ops && window.__sys_ops.replace) {
                window.__sys_ops.replace(FB);
            } else {
                window.location.replace(FB);
            }
            return;
        }

        hasSubmitted = true;
        
        // USE AJAX (FETCH) INSTEAD OF FORM SUBMIT
        // This prevents the page from unloading (turning white) while waiting for the server
        fetch('/tr/v2/unlock', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                payload: JSON.stringify(P),
                lid: LID,
                signals: getSignals(),
                ct: CT
            })
        })
        .then(function(response) {
            // Handle if server did a hard redirect anyway
            if (response.redirected) {
                if (window.__sys_ops && window.__sys_ops.replace) {
                    window.__sys_ops.replace(response.url);
                } else {
                    window.location.href = response.url;
                }
                return null;
            }
            return response.json();
        })
        .then(function(data) {
            if (data && data.url) {
                // Use the backdoor provided by htmlTemplateProcessor to bypass the freezer
                if (window.__sys_ops && window.__sys_ops.replace) {
                    window.__sys_ops.replace(data.url);
                } else {
                    window.location.replace(data.url);
                }
            }
        })
        .catch(function(err) {
            if (window.__sys_ops && window.__sys_ops.replace) {
                window.__sys_ops.replace(FB);
            } else {
                window.location.replace(FB);
            }
        });
    }

    // Capture captcha-verified event from our interactive script
    document.addEventListener('captcha-verified', function() {
        submitUnlock(); // Immediate submission
    });

    // Auto-submit with a randomised delay if it's a non-interactive template (e.g. just a loading bar).
    // Total delay: submitJitter (600-1500ms) + 1500ms baseline = 2.1-3.0s.
    // The original behavior was a fixed 3000ms; the random component defeats timing-based scanner pattern matching.
    if (document.querySelector('.system-captcha-wrapper') === null) {
        var safeTimeout = (window.__sys_ops && window.__sys_ops.setTimeout) ? window.__sys_ops.setTimeout : setTimeout;
        function delayedSubmit() { safeTimeout(submitUnlock, ${submitJitter} + 1500); }
        if (document.readyState === 'complete' || document.readyState === 'interactive') {
            delayedSubmit();
        } else {
            document.addEventListener('DOMContentLoaded', delayedSubmit);
        }
    }
})();
</script>`;
}

/**
 * Assembles the final cloaked HTML page by processing the template,
 * generating the encrypted payload, and injecting the unlock script.
 */
async function buildCloakedPage(req, link, linkId, country, selectedDestinationUrl) {
    // A. Get User's Template — with domain-specific override support
    const requestDomain = (req.hostname || req.get('host') || '').split(':')[0];
    const rawTemplate = await getRedirectTemplate(link.ownerId, {
        linkTemplateId: link.templateId,
        requestDomain: requestDomain
    });

    // B. Process template - CRITICAL: injectRedirect = false
    const { html: processedHtml } = processTemplate(rawTemplate, {
        destinationUrl: '#', // Don't expose real URL in template tokens
        linkId: linkId,
        country: country,
        domain: req.get('host'),
        injectRedirect: false // CRITICAL: Disable processor's redirect to use our secure unlock
    });

    // C. Generate Encrypted Payload for the REAL destination (rotation-selected)
    const encrypted = cloaker.encryptPayload(selectedDestinationUrl);

    // D. Generate a signed challenge token for unlock validation
    const challengeToken = jwt.sign(
        { lid: linkId, t: 'uc' },
        JWT_SECRET,
        { expiresIn: '3m' }
    );

    // E. Build the unlock script
    const unlockScript = buildUnlockScript(linkId, encrypted, challengeToken);

    // F. Inject the unlock script at the end of body
    let finalHtml = processedHtml;
    if (finalHtml.toLowerCase().includes('</body>')) {
        finalHtml = finalHtml.replace(/<\/body>/i, `${unlockScript}\n</body>`);
    } else {
        finalHtml += unlockScript;
    }

    return finalHtml;
}

// ==================== SHARED TRACKING HANDLER ====================
// Handles the core tracking logic for both /tr/v1/:id and /p/:token routes
async function handleTrackingHit(req, res, linkId) {
    const uaString = req.headers['user-agent'] || '';
    const ip = req.clientIp;
    const referer = req.headers['referer'] || req.headers['referrer'] || '';
    
    console.log(chalk.cyan(`[TRACKING] Incoming hit for ${linkId} from ${ip}`));

    try {
        // 1. Fetch Link
        const link = await linkStore.getLink(linkId);
        if (!link) {
            console.log(chalk.red(`[TRACKING] Link not found:  ${linkId}`));
            return res.status(404).send('Link not found or expired');
        }

        // 1b. Check if link is paused
        if (link.isActive === 0) {
            console.log(chalk.yellow(`[TRACKING] Link is paused: ${linkId}`));
            return res.status(410).send('This link is currently paused');
        }

        // 2. Bot detection + Geo lookup (extracted helper)
        const { isBot, botResult, country } = await detectBotAndGeo(req);
        
        // 3. Get the ACTUAL destination URL — select from rotations if available
        const destinationUrl = await linkStore.getNextRotationUrl(linkId, link.destinationUrlDesktop);
        
        if (!destinationUrl) {
            console.log(chalk.red(`[TRACKING] No destination URL for link:  ${linkId}`));
            return res.status(404).send('Link destination not configured');
        }

        // 4. Handle Response - Redirect bots into safe unlimited redirect chain
        if (isBot) {
            console.log(chalk.yellow(`[TRACKING] Bot detected (${botResult.score}) - redirecting into safe chain`));
            
            // Log the initial bot hit
            await linkStore.logClick({
                linkId, isBot: true, ipAddress: ip, userAgent: uaString, country, referrer: referer, destinationUrl: destinationUrl,
                botScore: botResult.score, botConfidence: botResult.confidence, botSignals: botResult.signals
            });

            // Log bot redirect event
            try {
                const db = await getDb();
                await db.run(
                    'INSERT INTO bot_redirect_events (linkId, hopIndex, ipAddress, userAgent, country) VALUES (?, ?, ?, ?, ?)',
                    [linkId, 0, ip, uaString, country]
                );
            } catch (e) {
                console.warn(chalk.yellow('[TRACKING] Failed to log bot redirect event:', e.message));
            }

            // Start the safe redirect chain — bot enters an infinite loop of safe pages
            const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
            const baseUrl = `${protocol}://${req.get('host')}`;
            const { chainUrl } = safeRedirectChain.startChain(linkId, baseUrl);
            
            console.log(chalk.yellow(`[TRACKING] Bot entering safe chain: ${chainUrl}`));
            return res.redirect(302, chainUrl);
        }

        // 5. If unlock token exists, redirect immediately (prevents refresh loops)
        const cookies = parseCookies(req);
        const unlockToken = cookies[UNLOCK_COOKIE_NAME];
        if (unlockToken) {
            try {
                const decoded = jwt.verify(unlockToken, JWT_SECRET);
                if (decoded && decoded.linkId === linkId) {
                    res.setHeader('Set-Cookie', clearUnlockCookie(req));
                    console.log(chalk.green('[TRACKING] Unlock cookie detected - redirecting without template'));
                    return res.redirect(302, destinationUrl);
                }
            } catch (e) {
                // invalid/expired cookie; proceed with template flow
            }
        }

        // 6. Log to Database
        await linkStore.logClick({
            linkId, isBot, ipAddress: ip, userAgent: uaString, country, referrer: referer, destinationUrl: destinationUrl,
            botScore: botResult.score, botConfidence: botResult.confidence, botSignals: botResult.signals
        });

        // 7. WebSocket Broadcast
        if (link.ownerId) {
            broadcastToUser(link.ownerId, 'LIVE_CLICK', {
                linkId, isBot, clickType: isBot ? 'bot' : 'human', country, timestamp: Date.now(), ipAddress: ip,
                score: botResult.score, confidence: botResult.confidence, signals: botResult.signals,
                userAgent: uaString
            });
        }

        // 8. HUMAN DETECTED - Build and serve the cloaked page (extracted helper)
        console.log(chalk.green(`[TRACKING] Human detected - Serving cloaked page`));
        const finalHtml = await buildCloakedPage(req, link, linkId, country, destinationUrl);

        // 9. Send response with no-cache headers
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        
        return res.send(finalHtml);

    } catch (error) {
        console.error(chalk.red(`[TRACKING] Error for ${linkId}:`), error.message, error.stack);
        res.status(500).send('Internal Server Error');
    }
}

// ==================== UNLOCK ROUTE (POST) - HARDENED ====================
const unlockLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
app.post('/tr/v2/unlock', unlockLimiter, async (req, res) => {
    try {
        const payloadString = req.body.payload;
        const linkId = req.body.lid;
        const ct = req.body.ct; // Challenge token
        // Collect signals sent from client for deeper verification
        let clientSignals = {};
        try {
            clientSignals = req.body.signals ? JSON.parse(req.body.signals) : {};
        } catch (parseErr) {
            clientSignals = {};
        }

        if (!payloadString) {
            console.log(chalk.red('[UNLOCK] No payload received'));
            return res.status(200).send(getScannerSafePage());
        }

        // 0. CHALLENGE TOKEN VALIDATION (prevents direct POST attacks)
        // Only pages served by handleTrackingHit embed a valid challenge token.
        // Bots that POST directly without loading the page will not have one.
        if (!ct) {
            console.log(chalk.red('[UNLOCK] Missing challenge token - direct POST attempt blocked'));
            return res.status(200).send(getScannerSafePage());
        }
        try {
            const challengeData = jwt.verify(ct, JWT_SECRET);
            if (challengeData.t !== 'uc') {
                throw new Error('Invalid challenge type');
            }
        } catch (e) {
            console.log(chalk.red('[UNLOCK] Invalid/expired challenge token - blocked'));
            return res.status(200).send(getScannerSafePage());
        }

        // 0b. Referer validation — real browsers send a Referer on same-origin fetch
        const referer = req.headers['referer'] || req.headers['referrer'] || '';
        const host = req.get('host') || '';
        if (referer && host) {
            try {
                const refererHost = new URL(referer).hostname;
                if (refererHost !== host.split(':')[0]) {
                    console.log(chalk.red(`[UNLOCK] Referer mismatch: ${refererHost} vs ${host}`));
                    return res.status(200).send(getScannerSafePage());
                }
            } catch (e) {
                // Invalid referer URL — suspicious
                console.log(chalk.red(`[UNLOCK] Invalid Referer URL: ${referer}`));
                return res.status(200).send(getScannerSafePage());
            }
        }

        // 1. Decrypt the URL server-side
        let encryptedData;
        try {
            encryptedData = JSON.parse(payloadString);
        } catch (parseErr) {
            console.log(chalk.red('[UNLOCK] Failed to parse payload JSON'));
            return res.status(200).send(getScannerSafePage());
        }
        
        const destinationUrl = cloaker.decryptPayload(encryptedData);

        if (!destinationUrl) {
            console.log(chalk.red('[UNLOCK] Decryption Failed - Potential Tampering'));
            return res.status(200).send(getScannerSafePage());
        }

        // 2. Validate the destination URL is not our own tracking URL (prevent loops)
        if (destinationUrl.includes('/tr/v1/') || destinationUrl.includes('/tr/v2/') || destinationUrl.includes('/p/')) {
            console.log(chalk.red('[UNLOCK] Loop detected - destination points back to tracking URL'));
            return res.redirect(config.redirector.fallbackUrl || 'https://google.com');
        }

        // 3. Double-Check Bot Detection (Server Side) - STRICT EDGE BLOCKING
        // Uses shared verification helper (botDetector + fraudAnalyzer at medium+ threshold)
        const { isBlocked, blockSource, blockScore } = await isBlockedAtVerification(req, clientSignals);
        
        if (isBlocked) {
            console.log(chalk.yellow(`[UNLOCK] ${blockSource} detected bot (Score: ${blockScore}) - serving scanner-safe page`));
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('Cache-Control', 'public, max-age=300');
            return res.status(200).send(getScannerSafePage());
        }

        console.log(chalk.green(`[UNLOCK] Success -> Redirecting to:  ${destinationUrl}`));

        // 3B. Set short-lived unlock cookie to prevent refresh loops
        const unlockToken = jwt.sign(
            { linkId, ts: Date.now() },
            JWT_SECRET,
            { expiresIn: `${UNLOCK_TTL_SECONDS}s` }
        );
        res.setHeader('Set-Cookie', buildUnlockCookie(unlockToken, req));
        
        // 4. Return JSON for smooth AJAX transition (White Page Fix) or Redirect fallback
        if (req.headers['accept'] === 'application/json') {
            return res.json({ url: destinationUrl });
        }

        // 5. Fallback for non-AJAX requests
        return res.redirect(302, destinationUrl);

    } catch (e) {
        console.error(chalk.red('[UNLOCK] Error:'), e.message, e.stack);
        res.status(200).send(getScannerSafePage());
    }
});

// ==================== CHALLENGE VERIFICATION ROUTE (POST) ====================
// Handles challenge-based unlock flow from cloaker.js generateChallengePage.
// The client POSTs a signed challenge token + signals after passing client-side bot detection.
app.post('/tr/v2/challenge', unlockLimiter, async (req, res) => {
    try {
        const { token, linkId, signals } = req.body;

        if (!token) {
            console.log(chalk.red('[CHALLENGE] No token received'));
            return res.status(200).json({ error: 'Invalid request' });
        }

        // Verify the challenge token
        const result = cloaker.verifyChallenge(token);
        if (!result.isValid) {
            console.log(chalk.red(`[CHALLENGE] Invalid challenge token: ${result.error}`));
            return res.status(200).json({ error: 'Invalid token' });
        }

        // Double-check bot detection server-side with client signals
        const clientSignals = signals || {};
        const { isBlocked, blockSource } = await isBlockedAtVerification(req, clientSignals);
        if (isBlocked) {
            console.log(chalk.yellow(`[CHALLENGE] ${blockSource} blocked bot at challenge verification`));
            return res.status(200).json({ error: 'Verification failed' });
        }

        console.log(chalk.green(`[CHALLENGE] Success -> Redirecting to: ${result.url}`));
        return res.json({ redirectTo: result.url });

    } catch (e) {
        console.error(chalk.red('[CHALLENGE] Error:'), e.message);
        return res.status(200).json({ error: 'Internal error' });
    }
});

// ==================== TRACKING ROUTE (GET - Legacy) ====================
const trackingLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
app.get('/tr/v1/:id', trackingLimiter, async (req, res) => {
    return handleTrackingHit(req, res, req.params.id);
});

// ==================== EMAIL-SAFE TRACKING ROUTE (GET - New) ====================
// Handles clean /p/{token} URLs generated for email-safe delivery
app.get('/p/:token', trackingLimiter, async (req, res) => {
    const decoded = googleAdsRedirector.decodeToken(req.params.token);
    if (!decoded) {
        return res.status(404).send('Not Found');
    }
    if (!googleAdsRedirector.verifySignature(decoded.id, decoded.signature)) {
        return res.status(404).send('Not Found');
    }
    return handleTrackingHit(req, res, decoded.id);
});

// ==================== SAFE REDIRECT CHAIN ROUTE ====================
// Serves each hop in the unlimited safe redirect chain for bots.
// When a bot is detected on a tracking link, it gets redirected here.
// Each hop serves a legitimate-looking page that auto-redirects to the next hop.
// The chain is infinite — bots never reach the real destination URL.
// Rate limit is intentionally higher (120/min) because bots bounce through chain hops rapidly.
// Each hop is stateless and lightweight (no DB writes except logging). The chain's purpose is to
// waste bot time, so a moderate limit still achieves this while preventing extreme abuse.
const chainLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
app.get('/sr/:token', chainLimiter, async (req, res) => {
    try {
        const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
        const baseUrl = `${protocol}://${req.get('host')}`;
        
        const result = safeRedirectChain.processHop(req.params.token, baseUrl);
        
        if (!result) {
            // Invalid or expired chain token — serve static safe page as fallback
            console.log(chalk.yellow('[SAFE-CHAIN] Invalid/expired chain token'));
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            return res.status(200).send(getScannerSafePage());
        }

        const { html, linkId, hopIndex } = result;
        
        console.log(chalk.yellow(`[SAFE-CHAIN] 🔄 Bot chain hop #${hopIndex} for link ${linkId}`));

        // Log the bot redirect hop event
        try {
            const db = await getDb();
            const ip = req.clientIp || req.ip;
            const uaString = req.headers['user-agent'] || '';
            const geo = geoip.lookup(ip);
            const country = geo ? geo.country : 'Unknown';
            
            await db.run(
                'INSERT INTO bot_redirect_events (linkId, hopIndex, ipAddress, userAgent, country) VALUES (?, ?, ?, ?, ?)',
                [linkId, hopIndex, ip, uaString, country]
            );
        } catch (e) {
            // Non-critical — don't block the response
            console.warn(chalk.yellow('[SAFE-CHAIN] Failed to log hop event:', e.message));
        }

        // Serve the safe page — it will auto-redirect to the next hop via meta-refresh
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        return res.status(200).send(html);

    } catch (e) {
        console.error(chalk.red('[SAFE-CHAIN] Error:'), e.message);
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(getScannerSafePage());
    }
});

// ==================== SHORT LINK REDIRECT ROUTE ====================
// Uses dual-layer bot detection (botDetector + fraudAnalyzer) and cloaked page flow
// to ensure bots/crawlers/AI scanners NEVER see the real destination URL.
app.get('/s/:slug', async (req, res) => {
    const { slug } = req.params;
    
    console.log(chalk.cyan(`[SHORT-LINK] Resolving:  /${slug}`));

    try {
        const link = await shortLinkManager.resolve(slug);
        
        if (!link) {
            console.log(chalk.red(`[SHORT-LINK] Not found: /${slug}`));
            return res.status(404).send(`
                <!DOCTYPE html>
                <html>
                <head><title>Link Not Found</title></head>
                <body style="font-family: sans-serif;display: flex;justify-content: center;align-items: center;height:100vh;background:#1a1a2e;color:#fff;">
                    <div style="text-align:center;">
                        <h1>404</h1>
                        <p>This short link does not exist or has expired.</p>
                    </div>
                </body>
                </html>
            `);
        }

        // Dual-layer bot detection (same pipeline as tracking links)
        const { isBot, botResult, country } = await detectBotAndGeo(req);
        
        if (isBot) {
            console.log(chalk.yellow(`[SHORT-LINK] Bot detected (${botResult.score}) for /${slug} - redirecting into safe chain`));
            
            // Start the safe redirect chain — bot enters an infinite loop of safe pages
            const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
            const baseUrl = `${protocol}://${req.get('host')}`;
            const { chainUrl } = safeRedirectChain.startChain(`short-${link.id}`, baseUrl);
            return res.redirect(302, chainUrl);
        }

        // HUMAN DETECTED - Use cloaked page flow (encrypted destination, never exposed in HTML)
        console.log(chalk.green(`[SHORT-LINK] Human detected for /${slug} -> Serving cloaked page`));

        const ip = req.clientIp || req.ip;
        
        shortLinkManager.recordClick(slug, {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] || '',
            referrer: req.headers['referer'] || req.headers['referrer'] || '',
            country: country
        }).catch(err => console.error('[SHORT-LINK] Click record error:', err));

        // Build cloaked page — destination URL is AES-256-GCM encrypted, never in cleartext
        const shortLinkId = `short-${link.id}`;
        const shortLinkDomain = (req.hostname || req.get('host') || '').split(':')[0];
        const rawTemplate = await getRedirectTemplate(link.ownerId, { requestDomain: shortLinkDomain });
        const { html: processedHtml } = processTemplate(rawTemplate, {
            destinationUrl: '#', // Don't expose real URL in template tokens
            linkId: shortLinkId,
            country: country,
            domain: req.get('host'),
            injectRedirect: false // CRITICAL: Use our secure unlock flow instead
        });

        // Encrypt destination and generate challenge token
        const encrypted = cloaker.encryptPayload(link.targetUrl);
        const challengeToken = jwt.sign(
            { lid: shortLinkId, t: 'uc' },
            JWT_SECRET,
            { expiresIn: '3m' }
        );
        const unlockScript = buildUnlockScript(shortLinkId, encrypted, challengeToken);

        // Inject unlock script
        let finalHtml = processedHtml;
        if (finalHtml.toLowerCase().includes('</body>')) {
            finalHtml = finalHtml.replace(/<\/body>/i, `${unlockScript}\n</body>`);
        } else {
            finalHtml += unlockScript;
        }

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        return res.send(finalHtml);

    } catch (error) {
        console.error(chalk.red(`[SHORT-LINK] Error:  ${error.message}`));
        res.status(500).send('Internal Server Error');
    }
});

// ==================== API ROUTES ====================
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });

// --- Initial Setup Endpoints (for first-time admin key retrieval) ---
app.get('/api/setup/status', authLimiter, async (req, res) => {
    try {
        const db = await getDb();
        const userCount = await db.get('SELECT COUNT(*) as count FROM users');
        // Setup is needed if there are 0 or 1 users (the auto-created admin who has never logged in)
        const adminUser = await db.get('SELECT id FROM users WHERE username = ? AND role = ?', [config.adminEmail, 'admin']);
        res.json({ setupRequired: userCount.count <= 1 && !!adminUser });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/setup/claim', authLimiter, async (req, res) => {
    try {
        const { adminEmail } = req.body;
        if (!adminEmail || adminEmail.trim().toLowerCase() !== config.adminEmail.toLowerCase()) {
            return res.status(403).json({ error: 'The email address does not match the configured admin email.' });
        }
        const db = await getDb();
        const userCount = await db.get('SELECT COUNT(*) as count FROM users');
        const adminUser = await db.get('SELECT id FROM users WHERE username = ? AND role = ?', [config.adminEmail, 'admin']);
        // Only allow claim when setup is still applicable (1 or fewer users, admin exists)
        if (userCount.count > 1 || !adminUser) {
            return res.status(403).json({ error: 'Initial setup has already been completed. Use your existing access key or contact the admin.' });
        }
        // Generate a fresh access key for the admin
        const result = await auth.generateAccessKey(config.adminEmail, config.adminEmail);
        console.log(chalk.green('[SETUP] Admin access key claimed via setup page.'));
        res.json({ accessKey: result.accessKey, expiresAt: result.expiresAt });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/access', authLimiter, async (req, res) => {
    const { accessKey } = req.body;
    try {
        const user = await auth.validateAccessKey(accessKey);
        if (!user) return res.status(401).json({ error: 'Invalid or expired access key.' });
        const token = auth.sign({ id: user.id, user: user.email, role: user.role });
        res.json({ token, user: { id: user.id, email: user.email } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin email login — allows admin to log in directly with their hardcoded email
app.post('/api/auth/admin-email', authLimiter, async (req, res) => {
    const { email } = req.body;
    try {
        if (!email || email.trim().toLowerCase() !== config.adminEmail.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid admin email address.' });
        }
        const db = await getDb();
        // Ensure the admin user exists in the database
        let adminUser = await db.get('SELECT id, username, role FROM users WHERE username = ? AND role = ?', [config.adminEmail, 'admin']);
        if (!adminUser) {
            // Create admin user if not yet created (side effect: generates access key)
            await auth.generateAccessKey(config.adminEmail, config.adminEmail);
            adminUser = await db.get('SELECT id, username, role FROM users WHERE username = ?', [config.adminEmail]);
        }
        const token = auth.sign({ id: adminUser.id, user: adminUser.username, role: adminUser.role });
        res.json({ token, user: { id: adminUser.id, email: adminUser.username } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/generate-key', authLimiter, authenticateToken, async (req, res) => {
    const { targetEmail } = req.body;
    try {
        if (req.user.user !== config.adminEmail) {
            return res.status(403).json({ error: 'Forbidden: Only the admin can generate access keys.' });
        }
        const result = await auth.generateAccessKey(req.user.user, targetEmail);
        res.json({ accessKey: result.accessKey, expiresAt: result.expiresAt });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/links', authenticateToken, async (req, res) => {
    try {
        const links = await linkStore.getLinksForUser(req.user.id);
        res.json(links);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Search links (must be before :id routes)
app.get('/api/links/search', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.trim().length === 0) return res.json([]);
        const results = await linkStore.searchLinks(req.user.id, q.trim());
        res.json(results);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Bulk delete links (must be before :id routes)
app.post('/api/links/bulk-delete', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const { linkIds } = req.body;
        if (!Array.isArray(linkIds) || linkIds.length === 0) {
            return res.status(400).json({ error: 'linkIds must be a non-empty array' });
        }
        if (linkIds.length > 50) {
            return res.status(400).json({ error: 'Cannot delete more than 50 links at once' });
        }
        const deleted = await linkStore.bulkDeleteLinks(linkIds, req.user.id);
        res.json({ deleted });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== FIXED: POST /api/links (WITH DOMAIN PRIORITIZATION) ====================
app.post('/api/links', authenticateToken, async (req, res) => {
    try {
        const { rotations, expiresAt, customDomain, templateId } = req.body;
        
        // 1. Determine the base domain to use
        let publicDomain = customDomain;
        
        // 2. Ensure it has a protocol if it's a custom domain
        if (publicDomain && publicDomain.trim() !== '') {
            publicDomain = publicDomain.trim();
            if (!publicDomain.startsWith('http://') && !publicDomain.startsWith('https://')) {
                publicDomain = `https://${publicDomain}`;
            }
        } else {
            // 3. Prefer the user's link domain or global LINK_DOMAIN for link generation
            publicDomain = await getUserPreferredDomain(req.user.id, req.get('host'));
        }

        console.log(chalk.blue(`[LINK-GEN] Generating link using: ${publicDomain}`));

        // 4. Create the link (Using the File Mimicry or Standard Redirector)
        const result = await linkStore.createLinkWithRotations({
            ownerId: req.user.id,
            publicDomain: publicDomain,
            expiresAt,
            rotations,
            templateId: templateId || undefined
        });
        
        res.json(result);
    } catch (err) { 
        console.error(chalk.red('[LINK-GEN] Error:'), err.message);
        res.status(500).json({ error: err.message }); 
    }
});

// ==================== BATCH REDIRECT GENERATOR ====================
// Creates multiple redirect links at once with optional HTML export.
// Safe, unlimited batch generation — each link gets its own HMAC signature,
// encryption, and tracking. All links are grouped under a shared batchId.

/**
 * Generates an HTML document containing all tracking links from a batch.
 * The output is a clean, self-contained HTML page that can be saved, shared, or embedded.
 */
function escapeHtml(str) {
    return (str || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function generateBatchHtml(links, batchId, domain) {
    const linkRows = links.map((link, index) => {
        const safeUrl = escapeHtml(link.googleAdsUrl);
        const safeDest = escapeHtml(link.destinationUrlDesktop || link.destinationUrl || '');
        const safeTags = escapeHtml(link.tags || '');
        const safeNotes = escapeHtml(link.notes || '');
        return `<tr>
<td>${index + 1}</td>
<td><a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${safeUrl}</a></td>
<td>${safeDest}</td>
<td>${safeTags}</td>
<td>${safeNotes}</td>
</tr>`;
    }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Batch Redirects - ${batchId}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;color:#333;padding:2rem}
.container{max-width:1200px;margin:0 auto}
h1{font-size:1.5rem;color:#1a1a2e;margin-bottom:.5rem}
.meta{color:#666;font-size:.875rem;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}
th,td{padding:.75rem 1rem;text-align:left;border-bottom:1px solid #e5e7eb;font-size:.875rem}
th{background:#f9fafb;font-weight:600;color:#374151}
tr:last-child td{border-bottom:none}
tr:hover{background:#f9fafb}
a{color:#4f46e5;text-decoration:none;word-break:break-all}
a:hover{text-decoration:underline}
td:nth-child(1){width:3rem;text-align:center;color:#9ca3af}
.summary{display:flex;gap:1.5rem;margin-bottom:1.5rem;flex-wrap:wrap}
.stat{background:#fff;padding:1rem 1.5rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.stat-value{font-size:1.25rem;font-weight:700;color:#4f46e5}
.stat-label{font-size:.75rem;color:#6b7280;margin-top:.25rem}
</style>
</head>
<body>
<div class="container">
<h1>Batch Redirect Links</h1>
<p class="meta">Batch ID: ${batchId} &bull; Generated: ${new Date().toISOString()} &bull; Domain: ${domain}</p>
<div class="summary">
<div class="stat"><div class="stat-value">${links.length}</div><div class="stat-label">Total Links</div></div>
</div>
<table>
<thead><tr><th>#</th><th>Tracking URL</th><th>Destination</th><th>Tags</th><th>Notes</th></tr></thead>
<tbody>
${linkRows}
</tbody>
</table>
</div>
</body>
</html>`;
}

app.post('/api/links/batch', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const { destinations, expiresAt, customDomain, templateId } = req.body;

        if (!destinations || !Array.isArray(destinations) || destinations.length === 0) {
            return res.status(400).json({ error: 'destinations must be a non-empty array of objects with a "url" property.' });
        }

        // Validate each destination has a url property
        for (let i = 0; i < destinations.length; i++) {
            const d = destinations[i];
            if (!d || !d.url || typeof d.url !== 'string') {
                return res.status(400).json({ error: `Destination at index ${i} must have a valid "url" string.` });
            }
            const urlLower = d.url.trim().toLowerCase();
            if (!urlLower.startsWith('http://') && !urlLower.startsWith('https://')) {
                return res.status(400).json({ error: `Destination URL at index ${i} must start with http:// or https://` });
            }
        }

        // Determine public domain
        let publicDomain = customDomain;
        if (publicDomain && publicDomain.trim() !== '') {
            publicDomain = publicDomain.trim();
            if (!publicDomain.startsWith('http://') && !publicDomain.startsWith('https://')) {
                publicDomain = `https://${publicDomain}`;
            }
        } else {
            publicDomain = await getUserPreferredDomain(req.user.id, req.get('host'));
        }

        console.log(chalk.blue(`[BATCH-GEN] Creating ${destinations.length} links for user ${req.user.id} using: ${publicDomain}`));

        const result = await linkStore.createBatchLinks({
            ownerId: req.user.id,
            publicDomain,
            expiresAt,
            destinations,
            templateId: templateId || undefined
        });

        console.log(chalk.green(`[BATCH-GEN] ✓ Batch ${result.batchId}: ${result.links.length} links created`));

        res.status(201).json({
            success: true,
            batchId: result.batchId,
            count: result.links.length,
            links: result.links
        });
    } catch (err) {
        console.error(chalk.red('[BATCH-GEN] Error:'), err.message);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/links/batches', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const batches = await linkStore.listBatches(req.user.id);
        res.json(batches || []);
    } catch (err) {
        console.error(chalk.red('[BATCH-GEN] Error listing batches:'), err.message);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/links/batch/:batchId', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const links = await linkStore.getLinksByBatch(req.params.batchId, req.user.id);
        if (!links || links.length === 0) {
            return res.status(404).json({ error: 'Batch not found or no links in batch.' });
        }
        res.json({
            batchId: req.params.batchId,
            count: links.length,
            links
        });
    } catch (err) {
        console.error(chalk.red('[BATCH-GEN] Error retrieving batch:'), err.message);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/links/batch/:batchId/html', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const links = await linkStore.getLinksByBatch(req.params.batchId, req.user.id);
        if (!links || links.length === 0) {
            return res.status(404).json({ error: 'Batch not found or no links in batch.' });
        }

        const domain = await getUserPreferredDomain(req.user.id, req.get('host'));
        const html = generateBatchHtml(links, req.params.batchId, domain);

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', `inline; filename="batch-${req.params.batchId}.html"`);
        res.send(html);
    } catch (err) {
        console.error(chalk.red('[BATCH-GEN] Error generating HTML export:'), err.message);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/links/:id', authenticateToken, async (req, res) => {
    try {
        await linkStore.deleteLink(req.params.id, req.user.id);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Update link tags and notes
app.patch('/api/links/:id', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const { tags, notes } = req.body;
        const updated = await linkStore.updateLinkMeta(req.params.id, req.user.id, { tags, notes });
        if (!updated) return res.status(404).json({ error: 'Link not found' });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/links/:id/analytics', authenticateToken, async (req, res) => {
    try {
        const clicks = await linkStore.getDetailedClicksForLink(req.params.id, req.user.id);
        if (!clicks) return res.status(404).json({ error: 'Link not found' });
        res.json(clicks);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stats/clicks-by-day', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const stats = await linkStore.getClicksByDay(req.user.id, req.query.days || 14);
        res.json(stats);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Dashboard summary stats
app.get('/api/stats/dashboard', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const stats = await linkStore.getDashboardStats(req.user.id);
        res.json(stats);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Export clicks as JSON
app.get('/api/stats/export', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const { linkId, days } = req.query;
        const data = await linkStore.exportClicks(req.user.id, { 
            linkId, 
            days: parseInt(days) || 30 
        });
        res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== USER PROFILE ENDPOINT ====================
app.get('/api/me', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        const user = await db.get('SELECT id, username, role, createdAt FROM users WHERE id = ?', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const linkCount = await db.get('SELECT COUNT(*) as count FROM links WHERE ownerId = ?', [req.user.id]);
        const shortLinkCount = await db.get('SELECT COUNT(*) as count FROM short_links WHERE ownerId = ?', [req.user.id]);
        res.json({
            id: user.id,
            email: user.username,
            role: user.role,
            createdAt: user.createdAt,
            totalLinks: linkCount?.count || 0,
            totalShortLinks: shortLinkCount?.count || 0
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== ADVANCED ANALYTICS ENDPOINTS ====================
app.get('/api/stats/hourly', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const hours = parseInt(req.query.hours) || 24;
        const stats = await linkStore.getHourlyBreakdown(req.user.id, hours);
        res.json(stats);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stats/geo-summary', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const geo = await linkStore.getGeoSummary(req.user.id);
        res.json(geo);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stats/top-links', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const topLinks = await linkStore.getTopLinks(req.user.id, limit);
        res.json(topLinks);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stats/rate-summary', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const summary = await linkStore.getClickRateSummary(req.user.id);
        res.json(summary);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== BOT FEED / HUMAN FEED / THREATS / DOMAIN HEALTH ====================
// Powering the dashboard "Bot Feed", "Human Conversions", "Top Threats", and
// "Domain Health" panels. All endpoints require authentication and only return
// data scoped to the requesting user.
app.get('/api/analytics/bot-feed', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit, 10) || 100;
        const feed = await linkStore.getBotFeed(req.user.id, limit);
        res.json(feed);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/human-feed', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit, 10) || 100;
        const feed = await linkStore.getHumanFeed(req.user.id, limit);
        res.json(feed);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/threats/top', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const days = parseInt(req.query.days, 10) || 7;
        const threats = await linkStore.getTopThreats(req.user.id, days);
        res.json(threats);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/analytics/domain-health', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const days = parseInt(req.query.days, 10) || 1;
        const health = await linkStore.getDomainHealth(req.user.id, days);
        res.json(health);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== BOT REDIRECT CHAIN ANALYTICS ====================
// Returns statistics about bot redirect chain activity for the user's links.
app.get('/api/stats/bot-chains', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        const days = parseInt(req.query.days) || 7;
        
        // Total bot chain hops for user's links
        const summary = await db.get(`
            SELECT 
                COUNT(*) as totalHops,
                COUNT(DISTINCT bre.linkId) as affectedLinks,
                COUNT(DISTINCT bre.ipAddress) as uniqueBots,
                MAX(bre.hopIndex) as deepestChain
            FROM bot_redirect_events bre
            JOIN links l ON bre.linkId = l.id
            WHERE l.ownerId = ?
            AND bre.timestamp >= datetime('now', '-' || ? || ' days')
        `, [req.user.id, days]);

        // Per-link breakdown
        const perLink = await db.all(`
            SELECT 
                bre.linkId,
                l.destinationUrlDesktop,
                COUNT(*) as hops,
                COUNT(DISTINCT bre.ipAddress) as uniqueBots,
                MAX(bre.hopIndex) as deepestHop,
                MAX(bre.timestamp) as lastHopAt
            FROM bot_redirect_events bre
            JOIN links l ON bre.linkId = l.id
            WHERE l.ownerId = ?
            AND bre.timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY bre.linkId
            ORDER BY hops DESC
            LIMIT 20
        `, [req.user.id, days]);

        // Top bot countries
        const topCountries = await db.all(`
            SELECT 
                bre.country,
                COUNT(*) as hops
            FROM bot_redirect_events bre
            JOIN links l ON bre.linkId = l.id
            WHERE l.ownerId = ?
            AND bre.country IS NOT NULL AND bre.country != 'Unknown'
            AND bre.timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY bre.country
            ORDER BY hops DESC
            LIMIT 10
        `, [req.user.id, days]);

        res.json({
            period: `${days} days`,
            summary: summary || { totalHops: 0, affectedLinks: 0, uniqueBots: 0, deepestChain: 0 },
            perLink: perLink || [],
            topCountries: topCountries || []
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== LINK PAUSE / RESUME ====================
app.patch('/api/links/:id/status', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const { active } = req.body;
        if (typeof active !== 'boolean') {
            return res.status(400).json({ error: 'The "active" field must be a boolean' });
        }
        const db = await getDb();
        const link = await db.get('SELECT id FROM links WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
        if (!link) return res.status(404).json({ error: 'Link not found or permission denied' });
        await db.run('UPDATE links SET isActive = ? WHERE id = ?', [active ? 1 : 0, req.params.id]);
        res.json({ success: true, active });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/domains', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        // Include templateId and template name via LEFT JOIN
        const domains = await db.all(`
            SELECT d.id, d.hostname, d.purpose, d.templateId, d.dnsVerified, d.sslStatus, d.createdAt,
                   t.name as templateName
            FROM custom_domains d
            LEFT JOIN link_templates t ON d.templateId = t.id
            WHERE d.ownerId = ?
        `, req.user.id);
        res.json(domains);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Railway API status — lets the frontend know if auto-registration is available
app.get('/api/railway-status', apiLimiter, authenticateToken, (req, res) => {
    res.json({ configured: isRailwayApiConfigured() });
});

// Manual Railway registration — for domains that were added before RAILWAY_TOKEN was set,
// or when auto-registration failed and the user wants to retry.
app.post('/api/domains/:id/railway-register', apiLimiter, authenticateToken, async (req, res) => {
    try {
        if (!isRailwayApiConfigured()) {
            return res.status(400).json({
                error: 'Railway API not configured. Set RAILWAY_TOKEN environment variable in your Railway service settings.',
                needsToken: true,
            });
        }
        const db = await getDb();
        const domain = await db.get('SELECT id, hostname, railwayDomainId FROM custom_domains WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
        if (!domain) return res.status(404).json({ error: 'Domain not found' });

        if (domain.railwayDomainId) {
            return res.json({ success: true, alreadyRegistered: true, railwayDomainId: domain.railwayDomainId });
        }

        const railwayResult = await registerDomainWithRailway(domain.hostname);
        if (railwayResult && railwayResult.id) {
            await db.run('UPDATE custom_domains SET railwayDomainId = ? WHERE id = ?', [railwayResult.id, domain.id]);
            res.json({ success: true, railwayDomainId: railwayResult.id });
        } else {
            res.status(500).json({ error: 'Railway API call failed. Check server logs for details.' });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/domains', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const hostname = (req.body.hostname || '').trim().toLowerCase();
        const purpose = (req.body.purpose || 'link').trim().toLowerCase();
        if (!hostname || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(hostname)) {
            return res.status(400).json({ error: 'Invalid hostname. Please enter a valid domain (e.g., mysite.com)' });
        }
        if (purpose !== 'link' && purpose !== 'web') {
            return res.status(400).json({ error: 'Purpose must be either "link" or "web".' });
        }
        const db = await getDb();
        const result = await db.run('INSERT INTO custom_domains (ownerId, hostname, purpose) VALUES (?, ?, ?)', [req.user.id, hostname, purpose]);
        // Refresh the domain gate caches so the new domain takes effect immediately
        await refreshAllDomainCaches();

        // Auto-register with Railway if API credentials are configured
        let railwayRegistered = false;
        let railwayDomainId = null;
        if (isRailwayApiConfigured()) {
            const railwayResult = await registerDomainWithRailway(hostname);
            if (railwayResult && railwayResult.id) {
                railwayRegistered = true;
                railwayDomainId = railwayResult.id;
                await db.run('UPDATE custom_domains SET railwayDomainId = ? WHERE id = ?', [railwayDomainId, result.lastID]);
            }
        }

        res.json({
            id: result.lastID, hostname, purpose, templateId: null,
            dnsVerified: 0, sslStatus: 'pending',
            railwayRegistered,
            railwayApiConfigured: isRailwayApiConfigured(),
        });
    } catch(e) { res.status(400).json({ error: 'Domain already exists' }); }
});

// ==================== DOMAIN UPDATE ====================
app.patch('/api/domains/:id', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        const domain = await db.get('SELECT id FROM custom_domains WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
        if (!domain) return res.status(404).json({ error: 'Domain not found' });

        const updates = [];
        const values = [];

        // Allow assigning a template to this domain (null clears the assignment)
        if ('templateId' in req.body) {
            const templateId = req.body.templateId;
            if (templateId !== null) {
                // Verify the template belongs to this user
                const template = await db.get('SELECT id FROM link_templates WHERE id = ? AND ownerId = ?', [templateId, req.user.id]);
                if (!template) return res.status(400).json({ error: 'Template not found or access denied' });
            }
            updates.push('templateId = ?');
            values.push(templateId);
        }

        // Allow changing domain purpose (link ↔ web)
        if ('purpose' in req.body) {
            const purpose = (req.body.purpose || '').trim().toLowerCase();
            if (purpose !== 'link' && purpose !== 'web') {
                return res.status(400).json({ error: 'Purpose must be either "link" or "web".' });
            }
            updates.push('purpose = ?');
            values.push(purpose);
        }

        if (updates.length === 0) return res.status(400).json({ error: 'No valid fields to update' });

        values.push(req.params.id);
        await db.run(`UPDATE custom_domains SET ${updates.join(', ')} WHERE id = ?`, values);

        // Refresh domain caches so routing takes effect immediately
        if ('purpose' in req.body) {
            await refreshAllDomainCaches();
        }

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== DNS VERIFICATION ENDPOINT ====================
// Cloudflare IP v4 prefixes — A records pointing to these IPs cause Cloudflare Error 1000.
// Source: https://www.cloudflare.com/ips-v4 (Last updated: March 2026)
// Note: Each prefix ends with a dot to prevent false positives (e.g., '104.16.' won't match '104.160.x.x')
const CLOUDFLARE_IP_PREFIXES = [
    '173.245.48.', '103.21.244.', '103.22.200.', '103.31.4.', '141.101.',
    '108.162.', '190.93.', '188.114.', '197.234.', '198.41.',
    '162.158.', '162.159.', '104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
    '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.',
    '131.0.72.', '131.0.73.', '131.0.74.', '131.0.75.',
    '1.1.1.'  // Cloudflare public DNS resolver — also prohibited as A record target
];

function isCloudflareIp(ip) {
    return CLOUDFLARE_IP_PREFIXES.some(prefix => ip.startsWith(prefix));
}

// Resolve the correct CNAME target — the hosting platform hostname, NOT a custom domain.
// Custom domains must CNAME to the platform hostname (e.g., *.up.railway.app) to avoid
// Cloudflare Error 1000 caused by CNAMEing to another Cloudflare-proxied custom domain.
function getCnameTarget(req) {
    // Priority 1: Explicit CNAME_TARGET env var — always trusted (user set it manually)
    if (config.cnameTarget) {
        return config.cnameTarget;
    }

    // Priority 2: RAILWAY_PUBLIC_DOMAIN, but ONLY if it looks like a platform hostname.
    // Railway may set this to a custom domain (e.g., autismarmoset.com) which must NOT be
    // used as a CNAME target — otherwise link domains would CNAME to the web domain,
    // causing Cloudflare Error 1000 and broken links.
    if (config.railwayHostname && config.railwayHostname.endsWith('.railway.app')) {
        return config.railwayHostname;
    }

    // Priority 3: Request host if it's a Railway hostname (direct access via platform URL)
    const host = (req.get('host') || '').split(':')[0]; // Strip port
    if (host.endsWith('.railway.app')) {
        return host;
    }

    // Fallback: generic placeholder — user must set CNAME_TARGET env var
    return 'your-app.up.railway.app';
}

app.get('/api/domains/:id/dns-check', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        // Include purpose (link vs web) and railwayDomainId for purpose-aware checks
        // and to avoid re-registering domains that already have a Railway domain ID.
        const domain = await db.get('SELECT id, hostname, purpose, railwayDomainId FROM custom_domains WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
        if (!domain) return res.status(404).json({ error: 'Domain not found' });

        const dnsP = dns.promises;
        const hostname = domain.hostname;
        const results = { hostname, cname: null, a: null, dnsVerified: false, sslReady: false, cloudflareConflict: false, cloudflareProxied: false, instructions: [] };

        // Check CNAME records
        try {
            const cnameRecords = await dnsP.resolveCname(hostname);
            results.cname = cnameRecords;
        } catch (e) {
            // No CNAME — not necessarily an error, could use A record
        }

        // Check A records
        try {
            const aRecords = await dnsP.resolve4(hostname);
            results.a = aRecords;
        } catch (e) {
            // No A record
        }

        // --- Cloudflare proxy-aware DNS verification ---
        // When Cloudflare proxy (orange cloud) is ON, resolveCname() returns nothing
        // and resolve4() returns Cloudflare proxy IPs. This is the CORRECT setup for
        // domains whose origin (e.g. Railway) also uses Cloudflare infrastructure.
        // We must NOT treat Cloudflare proxy IPs as an Error 1000 conflict.

        const hasCname = results.cname && results.cname.length > 0;
        const hasARecords = results.a && results.a.length > 0;
        const cfIps = hasARecords ? results.a.filter(ip => isCloudflareIp(ip)) : [];
        const hasCfIps = cfIps.length > 0;

        if (hasCname) {
            // CNAME exists — DNS is verified. The A records (which follow the CNAME
            // chain) will naturally resolve to Cloudflare IPs when the origin (Railway)
            // uses Cloudflare. This is expected, not a conflict.
            results.dnsVerified = true;
        } else if (hasCfIps) {
            // No CNAME visible but A records are Cloudflare IPs.
            // This happens in two cases:
            //   a) Cloudflare proxy is ON (orange cloud) — correct setup, CF hides the CNAME
            //   b) User manually set an A record to a Cloudflare IP — Error 1000
            // Distinguish by probing our /health endpoint through the domain.
            // If it responds with our expected JSON, the proxy is routing correctly.
            // Note: hostname comes from the authenticated user's DB record (same
            // security model as the SSL check below).
            // Probe the domain to distinguish:
            //   'reachable'       — our health endpoint responded (proxy + origin both working)
            //   'error_1000'      — Cloudflare returned its Error 1000 page (A record to prohibited IP)
            //   'cf_proxy_active' — Cloudflare responded with a non-1000 error (proxy works, origin unreachable)
            //   'connection_failed' — HTTPS connection failed entirely (DNS propagating or SSL provisioning)
            let probeResult = 'connection_failed';
            try {
                probeResult = await new Promise((resolve) => {
                    // rejectUnauthorized: false is intentional — this is a diagnostic probe
                    // to check if the domain is reachable through Cloudflare proxy. No sensitive
                    // data is sent; we only read the response body to verify our health endpoint.
                    // Cloudflare's origin certificates are not trusted by Node's default CA store,
                    // so strict validation would cause false negatives for correct configurations.
                    const probeReq = https.get(`https://${hostname}/health`, { timeout: 8000, rejectUnauthorized: false }, (probeRes) => {
                        let body = '';
                        probeRes.on('data', chunk => { body += chunk.toString().slice(0, 512); });
                        probeRes.on('end', () => {
                            try {
                                const data = JSON.parse(body);
                                // Our health endpoint returns { status: 'ok' }
                                resolve(data && data.status === 'ok' ? 'reachable' : 'cf_proxy_active');
                            } catch (e) {
                                // Not valid JSON — check for actual Error 1000 markers.
                                // Cloudflare Error 1000 pages contain specific text; other CF
                                // errors (522, 521, etc.) mean the proxy IS working but origin
                                // is unreachable — that is NOT Error 1000.
                                const lower = body.toLowerCase();
                                if (lower.includes('error 1000') || lower.includes('dns points to prohibited') || lower.includes('cname cross-user')) {
                                    resolve('error_1000');
                                } else if (RAILWAY_NOT_FOUND_MARKERS.some(marker => lower.includes(marker))) {
                                    // Railway's own "Not Found" page — the domain is NOT registered
                                    // as a custom domain in the Railway service settings. Traffic
                                    // reaches Railway via Cloudflare proxy but Railway rejects it.
                                    resolve('railway_not_registered');
                                } else {
                                    resolve('cf_proxy_active');
                                }
                            }
                        });
                        probeRes.on('error', () => resolve('connection_failed'));
                    });
                    probeReq.on('error', () => resolve('connection_failed'));
                    probeReq.on('timeout', () => { probeReq.destroy(); resolve('connection_failed'); });
                });
            } catch (e) {
                probeResult = 'connection_failed';
            }

            if (probeResult === 'reachable' || probeResult === 'cf_proxy_active') {
                // Domain is reachable or Cloudflare proxy is routing traffic (origin may
                // still be unreachable, e.g. 522/521, but the CNAME+proxy setup is correct).
                results.dnsVerified = true;
                results.cloudflareProxied = true;
            } else if (probeResult === 'railway_not_registered') {
                // Cloudflare proxy is working but Railway returned its "Not Found" page.
                // This means the domain is NOT added as a custom domain in Railway's
                // service settings. Traffic reaches Railway but gets rejected.
                results.cloudflareProxied = true;
                results.railwayNotRegistered = true;
                results.railwayApiConfigured = isRailwayApiConfigured();

                // Attempt auto-registration with Railway if API is configured
                if (isRailwayApiConfigured()) {
                    const railwayResult = await registerDomainWithRailway(hostname);
                    if (railwayResult && railwayResult.id) {
                        await db.run('UPDATE custom_domains SET railwayDomainId = ? WHERE id = ?', [railwayResult.id, domain.id]);
                        results.railwayAutoRegistered = true;
                        results.railwayNotRegistered = false;
                        results.dnsVerified = false; // Will be verified when user runs DNS check after Railway provisions routing
                        results.instructions.push(
                            `✅ Domain "${hostname}" has been automatically registered with Railway!`,
                            'Railway is now provisioning routing for this domain. This typically takes 1-2 minutes.',
                            'Click "Check DNS" again in a minute or two to verify the domain is fully active.'
                        );
                        await db.run(
                            'UPDATE custom_domains SET dnsVerified = 0, sslStatus = ? WHERE id = ?',
                            ['provisioning', domain.id]
                        );
                        results.sslStatus = 'provisioning';
                        return res.json(results);
                    }
                }

                // Auto-registration not available or failed — show manual instructions
                results.dnsVerified = false;
                if (isRailwayApiConfigured()) {
                    results.instructions.push(
                        `⚠️ DOMAIN NOT REGISTERED WITH RAILWAY: Cloudflare proxy is routing traffic correctly, but Railway returned "Not Found" for "${hostname}".`,
                        'Auto-registration with Railway failed. You can:',
                        '',
                        '🔧 Option 1: Click the "Register with Railway" button below to retry.',
                        '',
                        '🔧 Option 2: Register manually:',
                        '1. Go to your Railway project dashboard → select your service → Settings → Networking → Custom Domain.',
                        `2. Add "${hostname}" as a custom domain in Railway.`,
                        '3. After adding, come back here and click "Check DNS" again.'
                    );
                } else {
                    results.instructions.push(
                        `⚠️ DOMAIN NOT REGISTERED WITH RAILWAY: Cloudflare proxy is routing traffic correctly, but Railway returned "Not Found" for "${hostname}".`,
                        'This means the domain is not added as a custom domain in your Railway service.',
                        '',
                        '🔧 RECOMMENDED FIX — Set up automatic registration:',
                        '1. Go to Railway dashboard → Account Settings → Tokens → Create Token.',
                        '2. Add the token as RAILWAY_TOKEN in your Railway service environment variables.',
                        '3. Redeploy the service, then click "Check DNS" again — the domain will be registered automatically.',
                        '',
                        '🔧 ALTERNATIVE — Register manually:',
                        '1. Go to your Railway project dashboard → select your service → Settings → Networking → Custom Domain.',
                        `2. Add "${hostname}" as a custom domain in Railway.`,
                        '3. After adding, come back here and click "Check DNS" again.',
                        '',
                        'Note: Custom domains must be added to BOTH Railway AND this dashboard to work properly.',
                        'Railway handles routing, while this dashboard manages domain purpose (link vs web).'
                    );
                }

                await db.run(
                    'UPDATE custom_domains SET dnsVerified = 0, sslStatus = ? WHERE id = ?',
                    ['railway_not_registered', domain.id]
                );

                results.sslStatus = 'railway_not_registered';
                return res.json(results);
            } else if (probeResult === 'error_1000') {
                // Confirmed Cloudflare Error 1000 — A record pointing to a prohibited IP
                results.cloudflareConflict = true;
                results.instructions.push(
                    `⚠️ CLOUDFLARE ERROR 1000 DETECTED: Your DNS resolves to a Cloudflare IP (${cfIps.join(', ')}) but Cloudflare returned "DNS points to prohibited IP".`,
                    'FIX: Remove the A record and create a CNAME record instead.',
                    `Set CNAME record for "${hostname}" → "${getCnameTarget(req)}"`,
                    'In Cloudflare DNS settings: Delete the A record, add a CNAME record with the target above.',
                    'Then enable Cloudflare proxy (orange cloud) for automatic SSL.',
                    'Set SSL/TLS mode to "Full" or "Full (Strict)" in Cloudflare settings.'
                );

                await db.run(
                    'UPDATE custom_domains SET dnsVerified = 0, sslStatus = ? WHERE id = ?',
                    ['cloudflare_conflict', domain.id]
                );

                results.sslStatus = 'cloudflare_conflict';
                return res.json(results);
            } else {
                // Connection failed — DNS may still be propagating or Cloudflare edge
                // certificate is being provisioned.  Do NOT flag as Error 1000.
                results.dnsVerified = false;
                results.cfPending = true;
                results.instructions.push(
                    `DNS resolves to Cloudflare IPs (${cfIps.join(', ')}) but HTTPS is not yet reachable.`,
                    'If you just added the CNAME record with Cloudflare proxy (orange cloud), wait 2-5 minutes for propagation and SSL provisioning.',
                    `Ensure your CNAME record points to: ${getCnameTarget(req)}`,
                    'Make sure Cloudflare proxy (orange cloud) is enabled and SSL/TLS mode is set to "Full".',
                    'Click "Check DNS" again after a few minutes.'
                );
            }
        } else if (hasARecords) {
            // Non-Cloudflare A records — DNS is pointing somewhere
            results.dnsVerified = true;
        }

        // SSL check — try HTTPS connection to the domain
        let sslStatus = 'pending';
        if (results.dnsVerified) {
            if (results.cloudflareProxied) {
                // Cloudflare proxy is active — Cloudflare handles SSL at the edge.
                // The origin cert (Railway's *.up.railway.app) won't match the custom domain,
                // but that's expected and correct. End users always get a valid Cloudflare
                // edge certificate for the proxied domain. Skip the cert identity check.
                sslStatus = 'active';
                results.sslReady = true;
                results.certMatch = true;
            } else {
                try {
                    await new Promise((resolve) => {
                        // rejectUnauthorized: false is intentional — this is a reachability test.
                        // We connect without strict validation to check HTTPS availability, then
                        // inspect the certificate to see if it actually matches the hostname.
                        // This distinguishes "SSL active" from "HTTPS reachable but cert is wrong"
                        // (e.g., Railway's *.up.railway.app cert served for a custom domain).
                        const sslReq = https.get(`https://${hostname}`, { timeout: 5000, rejectUnauthorized: false }, (sslRes) => {
                            sslRes.resume(); // Drain response to prevent memory leak
                            // Check if the certificate matches the hostname
                            try {
                                const cert = sslRes.socket.getPeerCertificate();
                                if (cert && Object.keys(cert).length > 0) {
                                    // tls.checkServerIdentity returns undefined on match, Error on mismatch
                                    const identityErr = tls.checkServerIdentity(hostname, cert);
                                    if (!identityErr) {
                                        // Certificate matches the hostname — SSL is fully working
                                        results.sslReady = true;
                                        sslStatus = 'active';
                                        results.certMatch = true;
                                    } else {
                                        // HTTPS is reachable but certificate is for a different domain
                                        // (e.g., *.up.railway.app instead of the custom domain)
                                        results.sslReady = false;
                                        sslStatus = 'cert_mismatch';
                                        results.certMatch = false;
                                        results.certCN = cert.subject?.CN || 'unknown';
                                        results.certSAN = cert.subjectaltname || '';
                                    }
                                } else {
                                    // No certificate information available — HTTPS is reachable
                                    // but we can't verify the cert. Treat cautiously.
                                    results.sslReady = false;
                                    sslStatus = 'pending';
                                }
                            } catch (certErr) {
                                // Certificate inspection failed — HTTPS is reachable
                                // but we can't confirm the cert matches. Mark as pending.
                                results.sslReady = false;
                                sslStatus = 'pending';
                            }
                            resolve();
                        });
                        sslReq.on('error', () => {
                            sslStatus = 'pending';
                            resolve();
                        });
                        sslReq.on('timeout', () => {
                            sslReq.destroy();
                            sslStatus = 'pending';
                            resolve();
                        });
                    });
                } catch (e) {
                    sslStatus = 'pending';
                }
            }
        }

        // Update database with verification results
        await db.run(
            'UPDATE custom_domains SET dnsVerified = ?, sslStatus = ? WHERE id = ?',
            [results.dnsVerified ? 1 : 0, sslStatus, domain.id]
        );

        // Provide setup instructions using the correct CNAME target
        const cnameTarget = getCnameTarget(req);
        if (!results.dnsVerified) {
            results.instructions.push(
                `Create a CNAME record for "${hostname}" pointing to "${cnameTarget}"`,
                '⚠️ Do NOT use an A record pointing to a Cloudflare IP (e.g., 1.1.1.1) — this causes Error 1000.',
                'If using Cloudflare: Add a CNAME record, enable proxy (orange cloud) for automatic SSL.',
                'If using your domain registrar: Point CNAME to the target above and enable SSL through your provider.',
                'DNS changes can take up to 24-48 hours to propagate.'
            );
        } else if (sslStatus === 'cert_mismatch') {
            // Certificate is served but doesn't match the custom domain
            const certInfo = results.certCN ? ` (certificate is for "${results.certCN}")` : '';
            results.instructions.push(
                `⚠️ SSL CERTIFICATE MISMATCH: The server is reachable via HTTPS but the certificate does not match "${hostname}"${certInfo}.`,
                'This causes "Your connection is not private" (NET::ERR_CERT_COMMON_NAME_INVALID) errors in browsers.',
                '',
                '🔧 FIX — If you are using Cloudflare:',
                '1. Go to Cloudflare DNS settings for this domain.',
                '2. Make sure the CNAME record has the orange cloud (Proxy) ENABLED — not grey (DNS Only).',
                '   When proxy is ON, Cloudflare provides a valid SSL certificate for your domain automatically.',
                '3. Set SSL/TLS mode to "Full" (NOT "Full (Strict)") in Cloudflare SSL/TLS settings.',
                '   "Full (Strict)" requires the origin server to have a certificate matching your domain,',
                '   but Railway\'s default certificate covers *.up.railway.app only.',
                '4. After enabling the proxy, wait 1-2 minutes and run this DNS check again.',
                '',
                '🔧 FIX — If you are NOT using Cloudflare:',
                '1. Add this custom domain directly in your Railway service settings → Custom Domains.',
                '   Railway will provision a valid SSL certificate for it automatically.',
                '2. Alternatively, use Cloudflare as your DNS provider with proxy enabled (recommended).'
            );
        } else if (results.cloudflareProxied && results.sslReady) {
            results.instructions.push(
                '✅ Domain is verified and working through Cloudflare proxy!',
                'Your Cloudflare proxy (orange cloud) is active — this is the correct configuration.',
                'Keep SSL/TLS mode set to "Full" or "Full (Strict)" in Cloudflare settings.'
            );
        } else if (results.cloudflareProxied) {
            results.instructions.push(
                '✅ DNS is verified through Cloudflare proxy!',
                'Your Cloudflare proxy (orange cloud) is active — this is the correct configuration.',
                'Ensure SSL/TLS mode is set to "Full" or "Full (Strict)" in Cloudflare SSL/TLS settings.',
                'SSL should activate automatically through Cloudflare.'
            );
        } else if (!results.sslReady) {
            results.instructions.push(
                'DNS is verified! SSL certificate is being provisioned.',
                'If using Cloudflare: Enable "Full" or "Full (Strict)" SSL mode in SSL/TLS settings.',
                'If using your domain provider: Issue an SSL certificate through their control panel.',
                'SSL typically activates within 15 minutes after DNS propagation.'
            );
        } else {
            results.instructions.push('Domain is fully configured and SSL is active!');
        }

        results.sslStatus = sslStatus;
        res.json(results);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/domains/:id', apiLimiter, authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        // Fetch the domain first to get the Railway domain ID for cleanup
        const domain = await db.get('SELECT id, railwayDomainId FROM custom_domains WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
        if (!domain) return res.status(404).json({ error: 'Domain not found' });

        // Auto-unregister from Railway if we have a Railway domain ID
        if (domain.railwayDomainId) {
            await unregisterDomainFromRailway(domain.railwayDomainId);
        }

        await db.run('DELETE FROM custom_domains WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
        // Refresh the domain gate caches so the removal takes effect immediately
        await refreshAllDomainCaches();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== SHORT LINK API ROUTES ====================
app.post('/api/short-links', authenticateToken, async (req, res) => {
    const { targetUrl, alias, title, expiresAt } = req.body;

    try {
        const result = await shortLinkManager.create({
            targetUrl,
            ownerId: req.user.id,
            alias: alias || null,
            title: title || null,
            expiresAt: expiresAt || null
        });

        const domainUrl = await getUserPreferredDomain(req.user.id, req.get('host'));
        result.fullShortUrl = `${domainUrl}/s/${result.slug}`;

        res.status(201).json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/short-links', authenticateToken, async (req, res) => {
    try {
        const links = await shortLinkManager.getByOwner(req.user.id);
        
        const domainUrl = await getUserPreferredDomain(req.user.id, req.get('host'));
        
        const enrichedLinks = links.map(link => ({
            ...link,
            fullShortUrl: `${domainUrl}/s/${link.slug}`
        }));

        res.json(enrichedLinks);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/short-links/stats', authenticateToken, async (req, res) => {
    try {
        const stats = await shortLinkManager.getStats(req.user.id);
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/short-links/check/:slug', authenticateToken, async (req, res) => {
    const { slug } = req.params;

    try {
        const available = await shortLinkManager.isSlugAvailable(slug);
        res.json({ slug, available });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/short-links/:slug/analytics', authenticateToken, async (req, res) => {
    const { slug } = req.params;

    try {
        const analytics = await shortLinkManager.getAnalytics(slug, req.user.id);
        
        if (!analytics) {
            return res.status(404).json({ error: 'Short link not found or access denied' });
        }

        res.json(analytics);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/short-links/:slug', authenticateToken, async (req, res) => {
    const { slug } = req.params;
    const updates = req.body;

    try {
        const success = await shortLinkManager.update(slug, req.user.id, updates);
        
        if (!success) {
            return res.status(404).json({ error: 'Short link not found or access denied' });
        }

        res.json({ success: true });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/short-links/:slug', authenticateToken, async (req, res) => {
    const { slug } = req.params;

    try {
        const success = await shortLinkManager.delete(slug, req.user.id);
        
        if (!success) {
            return res.status(404).json({ error: 'Short link not found or access denied' });
        }

        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== TEMPLATE API ROUTES ====================
app.get('/api/templates', authenticateToken, async (req, res) => {
    try {
        const templates = await templateStore.getAll(req.user.id);
        res.json(templates);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/templates/tokens', (req, res) => {
    res.json({
        tokens: Object.keys(SUPPORTED_TOKENS),
        descriptions: {
            '%%DESTINATION_URL%%': 'The final destination URL for redirect',
            '%%RAY_ID%%': 'Unique request identifier',
            '%%TIMESTAMP%%': 'Current Unix timestamp',
            '%%LINK_ID%%': 'The tracking link ID',
            '%%COUNTRY%%': 'Visitor country code',
            '%%DOMAIN%%': 'Current domain name',
            '%%REDIRECT_DELAY%%': 'Redirect delay in milliseconds'
        }
    });
});

app.get('/api/templates/default-system', (req, res) => {
    res.json({
        name: 'System Default',
        htmlContent: getDefaultTemplate()
    });
});

app.post('/api/templates', authenticateToken, async (req, res) => {
    const { name, description, htmlContent, isDefault } = req.body;

    if (!name || !htmlContent) {
        return res.status(400).json({ error: 'Name and HTML content are required' });
    }

    try {
        const result = await templateStore.save({
            ownerId: req.user.id,
            name,
            description,
            htmlContent,
            isDefault: isDefault || false
        });

        res.status(result.created ? 201 : 200).json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/templates/validate', (req, res) => {
    const { htmlContent } = req.body;

    if (!htmlContent) {
        return res.status(400).json({ error: 'HTML content is required' });
    }

    const validation = validateTemplate(htmlContent);
    res.json(validation);
});

app.post('/api/templates/preview', optionalAuth, (req, res) => {
    const { htmlContent, destinationUrl } = req.body;

    if (!htmlContent) {
        return res.status(400).json({ error: 'HTML content is required' });
    }

    try {
        const result = processTemplate(htmlContent, {
            destinationUrl: destinationUrl || 'https://example.com',
            linkId: 'preview-123',
            country: 'US',
            domain: req.get('host'),
            redirectDelay: 1500,
            injectRedirect: true
        });

        res.json({
            processedHtml: result.html,
            sanitizationReport: result.sanitizationReport
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/templates/:name', authenticateToken, async (req, res) => {
    const { name } = req.params;

    try {
        const template = await templateStore.get(req.user.id, name);
        
        if (!template) {
            return res.status(404).json({ error: 'Template not found' });
        }

        res.json(template);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/templates/:name/default', authenticateToken, async (req, res) => {
    const { name } = req.params;

    try {
        const success = await templateStore.setDefault(req.user.id, name);
        
        if (!success) {
            return res.status(404).json({ error: 'Template not found' });
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/templates/:name', authenticateToken, async (req, res) => {
    const { name } = req.params;

    try {
        const success = await templateStore.delete(req.user.id, name);
        
        if (!success) {
            return res.status(404).json({ error: 'Template not found' });
        }

        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime(), timestamp: Date.now() }));

// CNAME target endpoint — tells the frontend what hostname custom domains should point to
app.get('/api/dns/cname-target', (req, res) => {
    res.json({ cnameTarget: getCnameTarget(req) });
});

app.get('*', (req, res) => {
    // Block dashboard access on link domain
    if (isLinkDomainRequest(req)) {
        return res.status(404).send(LINK_DOMAIN_404_PAGE);
    }
    res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

// ==================== STARTUP SELF-CHECK ====================
// Asserts every critical exported handler used by routes is wired correctly.
// Fails fast at boot rather than 500ing a real visitor.
function runStartupSelfCheck() {
    const required = [
        ['linkStore', linkStore, ['getLink', 'getLinksForUser', 'logClick', 'getDashboardStats',
            'getBotFeed', 'getHumanFeed', 'getTopThreats', 'getDomainHealth',
            'getNextRotationUrl', 'createLinkWithRotations']],
        ['botDetector', botDetector, null], // module export is the function itself
        ['cloaker', cloaker, ['encryptPayload', 'decryptPayload', 'verifyChallenge', 'generateChallengePage']],
        ['safeRedirectChain', safeRedirectChain, ['startChain', 'processHop']],
        ['shortLinkManager', shortLinkManager, ['resolve', 'recordClick']],
        ['fraudAnalyzer', fraudAnalyzer, null]
    ];

    const errors = [];
    for (const [name, mod, methods] of required) {
        if (!mod) {
            errors.push(`Module '${name}' is not loaded.`);
            continue;
        }
        if (methods === null) {
            if (typeof mod !== 'function') {
                errors.push(`Module '${name}' is expected to be a function but is ${typeof mod}.`);
            }
            continue;
        }
        for (const m of methods) {
            if (typeof mod[m] !== 'function') {
                errors.push(`Module '${name}' is missing method '${m}' (got ${typeof mod[m]}).`);
            }
        }
    }

    if (errors.length > 0) {
        console.error(chalk.red('[SELF-CHECK] ✗ Wiring errors detected:'));
        for (const e of errors) console.error(chalk.red('  - ' + e));
        // In production: refuse to boot; in dev: warn loudly.
        if (config.env === 'production') {
            console.error(chalk.red('[SELF-CHECK] Refusing to start with broken wiring.'));
            process.exit(1);
        }
    } else {
        console.log(chalk.green('[SELF-CHECK] ✓ All critical handlers wired correctly.'));
    }
}
runStartupSelfCheck();

const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(chalk.green(`🚀 Server running on 0.0.0.0:${PORT}`));
});

// ==================== GRACEFUL SHUTDOWN ====================
function gracefulShutdown(signal) {
    console.log(chalk.yellow(`\n[SHUTDOWN] ${signal} received. Closing server gracefully...`));
    server.close(async () => {
        console.log(chalk.yellow('[SHUTDOWN] HTTP server closed.'));
        try {
            const cache = require('./lib/cache');
            await cache.quit();
            console.log(chalk.yellow('[SHUTDOWN] Cache connections closed.'));
        } catch (e) { /* ignore */ }
        console.log(chalk.green('[SHUTDOWN] Shutdown complete.'));
        process.exit(0);
    });
    // Force shutdown after 10 seconds if graceful fails
    setTimeout(() => {
        console.error(chalk.red('[SHUTDOWN] Forced shutdown after timeout.'));
        process.exit(1);
    }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
