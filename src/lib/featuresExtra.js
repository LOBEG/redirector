/**
 * featuresExtra.js — additive feature helpers
 *
 * Centralizes logic for features 1, 2, 3, 6, 7, 13, 16, 19. Each function is
 * carefully designed so that:
 *   1. It NEVER triggers on a real human path unless explicitly configured.
 *   2. It is fully backward compatible — null/missing config → no-op.
 *   3. It does not mutate external state besides the DB rows it owns.
 *
 * Convention: every function takes the link record and current request
 * context, returns a structured decision the caller can act on.
 */
'use strict';

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const bcrypt = require('bcrypt');
const geoip = require('geoip-lite');
const useragent = require('useragent');
const chalk = require('chalk');
const getDb = require('./database');

// ============================================================================
// Feature 1: Click cap
// ============================================================================
/**
 * Returns true if link.maxClicks is set and link.clicks already reached it.
 * Bot clicks (link.botClicks) are excluded — they don't burn the cap.
 */
function isClickCapReached(link) {
    if (!link || !link.maxClicks) return false;
    const cap = Number(link.maxClicks);
    if (!Number.isFinite(cap) || cap <= 0) return false;
    const human = Math.max(0, Number(link.clicks || 0) - Number(link.botClicks || 0));
    return human >= cap;
}

// ============================================================================
// Feature 2: Per-link PIN gate
// ============================================================================
/** Hash a user-supplied PIN for storage. */
async function hashAccessPin(pin) {
    if (!pin || typeof pin !== 'string') throw new Error('PIN must be a non-empty string');
    const trimmed = pin.trim();
    if (trimmed.length < 4 || trimmed.length > 64) {
        throw new Error('PIN must be 4-64 characters long');
    }
    return bcrypt.hash(trimmed, 10);
}

/** Compare submitted PIN to stored hash. */
async function verifyAccessPin(pin, hash) {
    if (!pin || !hash) return false;
    try {
        return await bcrypt.compare(String(pin), String(hash));
    } catch (e) {
        return false;
    }
}

/**
 * Renders the lightweight PIN prompt page. NO redirect logic — submission goes
 * through /tr/v2/pin which validates and sets a short-lived JWT cookie.
 */
function renderPinGatePage(linkId) {
    const safeId = String(linkId).replace(/[^a-zA-Z0-9_-]/g, '');
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Verification Required</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{color-scheme:light;--bg:#fff;--card:#fff;--line:rgba(15,23,42,.14);--text:#0f172a;--muted:#6d28d9;--soft:#475569;--accent:#8b5cf6;--accent2:#06b6d4;--danger:#dc2626}
body{font-family:-apple-system,system-ui,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;color:var(--text);padding:1.25rem;overflow:hidden}
body:before{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(15,23,42,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(15,23,42,.045) 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.72),transparent);pointer-events:none}
.shell{position:relative;width:100%;max-width:480px}
.glow{display:none}
.card{position:relative;background:var(--card);border:0;border-radius:28px;box-shadow:none;padding:2rem;overflow:hidden;backdrop-filter:none;text-align:left}
.card:before{content:"";position:absolute;inset:0;background:linear-gradient(145deg,rgba(255,255,255,.13),transparent 42%);pointer-events:none}
.top{position:relative;display:flex;align-items:center;gap:1rem;margin-bottom:1.6rem}
.badge{width:58px;height:58px;border-radius:18px;display:grid;place-items:center;background:linear-gradient(135deg,rgba(139,92,246,.95),rgba(6,182,212,.9));box-shadow:none;font-size:1.55rem}
.eyebrow{color:var(--muted);font-size:.76rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;margin-bottom:.35rem}
h1{font-size:1.72rem;line-height:1.1;letter-spacing:-.04em}
p{position:relative;color:var(--soft);line-height:1.7;margin-bottom:1.35rem;font-size:.95rem}
.panel{position:relative;border:1px solid var(--line);border-radius:22px;background:rgba(248,250,252,.92);padding:1rem}
label{display:block;color:#334155;font-size:.78rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-bottom:.65rem}
.input-wrap{position:relative}
.input-wrap:before{content:"•••";position:absolute;left:1rem;top:50%;transform:translateY(-50%);color:rgba(71,85,105,.52);font-size:.75rem;letter-spacing:.2em;pointer-events:none}
input{width:100%;padding:1rem 1rem 1rem 3.6rem;border:1px solid rgba(148,163,184,.42);border-radius:16px;background:#fff;color:#0f172a;font-size:1.05rem;text-align:center;letter-spacing:.24em;box-shadow:none;transition:border-color .18s,background .18s}
input::placeholder{color:rgba(71,85,105,.58);letter-spacing:.05em}
input:focus{outline:none;border-color:rgba(34,211,238,.88);box-shadow:none;background:#fff}
button{width:100%;margin-top:1rem;padding:1rem 1.1rem;border:0;border-radius:16px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;font-weight:800;cursor:pointer;font-size:.98rem;letter-spacing:.02em;box-shadow:none;transition:transform .18s,filter .18s}
button:hover{transform:translateY(-1px);box-shadow:none;filter:saturate(1.08)}
button:active{transform:translateY(0)}
.err{color:var(--danger);font-size:.86rem;margin-top:.85rem;min-height:1.25em;text-align:center}
.foot{position:relative;display:flex;align-items:center;justify-content:center;gap:.45rem;color:rgba(71,85,105,.8);font-size:.78rem;margin-top:1.1rem}
.dot{width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:none}
@media (max-width:520px){.card{padding:1.45rem;border-radius:24px}.top{align-items:flex-start}.badge{width:50px;height:50px;border-radius:16px}h1{font-size:1.45rem}}
</style>
</head>
<body>
<main class="shell" aria-labelledby="pin-title">
<div class="glow" aria-hidden="true"></div>
<section class="card">
<div class="top">
<div class="badge" aria-hidden="true">🔐</div>
<div>
<div class="eyebrow">Secure access</div>
<h1 id="pin-title">Access Code Required</h1>
</div>
</div>
<p>This destination is protected. Enter the access code you were given to continue through the secure verification step.</p>
<form id="f" method="post" action="/tr/v2/pin" autocomplete="off">
<input type="hidden" name="lid" value="${safeId}">
<div class="panel">
<label for="pin">Private access code</label>
<div class="input-wrap">
<input id="pin" type="password" name="pin" placeholder="Enter code" maxlength="64" required autofocus inputmode="text" aria-describedby="err">
</div>
<button type="submit">Verify and continue</button>
<div class="err" id="err"></div>
</div>
</form>
<div class="foot"><span class="dot" aria-hidden="true"></span><span>Encrypted session verification</span></div>
</section>
</main>
<script>
(function(){
    var f=document.getElementById('f'),err=document.getElementById('err');
    f.addEventListener('submit',function(e){
        e.preventDefault();
        err.textContent='';
        var pin=document.getElementById('pin').value;
        fetch('/tr/v2/pin',{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},credentials:'same-origin',body:JSON.stringify({lid:'${safeId}',pin:pin})})
            .then(function(r){return r.json().then(function(d){return{s:r.status,d:d}})})
            .then(function(o){
                if(o.d&&o.d.success&&o.d.next){window.location.replace(o.d.next);}
                else{err.textContent=(o.d&&o.d.error)||'Incorrect code. Please try again.';}
            }).catch(function(){err.textContent='Network error. Please try again.';});
    });
})();
</script>
</body>
</html>`;
}

// ============================================================================
// Feature 3: Geo / ASN / device targeting rules on link_destinations
// ============================================================================
/**
 * Test whether a destination's `rules` JSON matches the visitor.
 * Empty/null rules → always matches.
 *
 * Rule shape (all keys optional):
 *   { countries: ["US","CA"], deny_countries: ["RU"],
 *     devices: ["mobile","desktop","tablet"],
 *     asnDeny: ["AS15169"],            // string match against geoip 'org' field
 *     hours: [9, 17] }                 // [from, to) UTC hours
 */
function destinationRulesMatch(rules, ctx) {
    if (!rules) return true;
    let r = rules;
    if (typeof r === 'string') {
        try { r = JSON.parse(r); } catch (e) { return true; } // malformed → don't filter
    }
    if (!r || typeof r !== 'object') return true;

    // Country allow-list
    if (Array.isArray(r.countries) && r.countries.length > 0) {
        const c = (ctx.country || '').toUpperCase();
        const allowed = r.countries.map(x => String(x).toUpperCase());
        if (!allowed.includes(c)) return false;
    }
    // Country deny-list
    if (Array.isArray(r.deny_countries) && r.deny_countries.length > 0) {
        const c = (ctx.country || '').toUpperCase();
        const denied = r.deny_countries.map(x => String(x).toUpperCase());
        if (denied.includes(c)) return false;
    }
    // Device class
    if (Array.isArray(r.devices) && r.devices.length > 0) {
        const allowed = r.devices.map(x => String(x).toLowerCase());
        if (!allowed.includes(String(ctx.device || '').toLowerCase())) return false;
    }
    // ASN / org deny
    if (Array.isArray(r.asnDeny) && r.asnDeny.length > 0) {
        const org = String(ctx.asn || '').toLowerCase();
        if (r.asnDeny.some(x => org.includes(String(x).toLowerCase()))) return false;
    }
    // Hours window (UTC). Inclusive from, exclusive to.
    if (Array.isArray(r.hours) && r.hours.length === 2) {
        const h = new Date().getUTCHours();
        const [from, to] = r.hours.map(x => Number(x));
        if (Number.isFinite(from) && Number.isFinite(to)) {
            if (from <= to) {
                if (h < from || h >= to) return false;
            } else { // wraps midnight
                if (h < from && h >= to) return false;
            }
        }
    }
    return true;
}

/**
 * Classify the device from a User-Agent string. Used by destinationRulesMatch.
 */
function classifyDevice(uaString) {
    try {
        const ua = useragent.parse(uaString || '');
        const family = (ua.device && ua.device.family) || '';
        const lc = (uaString || '').toLowerCase();
        if (/mobile|iphone|android(?!.*tablet)/i.test(uaString || '')) return 'mobile';
        if (/tablet|ipad/i.test(uaString || '') || /tablet/i.test(family)) return 'tablet';
        if (lc.includes('mobile')) return 'mobile';
        return 'desktop';
    } catch (e) {
        return 'desktop';
    }
}

/**
 * Pick the best matching rotation for a request, weighted by `weight`.
 * Falls back to the unfiltered weighted selection if NO destination matches.
 */
function pickRotationWithRules(rotations, ctx) {
    if (!Array.isArray(rotations) || rotations.length === 0) return null;
    const matching = rotations.filter(r => destinationRulesMatch(r.rules, ctx));
    const pool = matching.length > 0 ? matching : rotations;
    if (pool.length === 1) return pool[0];
    const totalWeight = pool.reduce((sum, r) => sum + (r.weight || 100), 0);
    let rnd = Math.random() * totalWeight;
    for (const r of pool) {
        rnd -= (r.weight || 100);
        if (rnd <= 0) return r;
    }
    return pool[pool.length - 1];
}

// ============================================================================
// Feature 6: Webhook on click (HMAC-signed, fire-and-forget)
// ============================================================================
/**
 * Fire a webhook for a click event. Never blocks the response — failures are
 * logged to click_webhook_log but don't propagate.
 *
 * @param {object} opts
 * @param {string} opts.url                Webhook URL
 * @param {string} opts.secret             HMAC secret (typically config.jwt.secret)
 * @param {object} opts.payload            JSON-serializable payload
 * @param {number} opts.linkId             For logging
 * @param {number} opts.ownerId            For logging
 * @param {number} [opts.timeoutMs=5000]
 */
function fireClickWebhook(opts) {
    const { url, secret, payload, linkId, ownerId, timeoutMs = 5000 } = opts;
    if (!url || typeof url !== 'string') return;
    let parsed;
    try {
        parsed = new URL(url);
    } catch (e) {
        return _logWebhook({ linkId, ownerId, url, status: 0, error: 'invalid url' });
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return;

    const body = JSON.stringify(payload || {});
    const signature = crypto.createHmac('sha256', secret || '').update(body).digest('hex');
    const transport = parsed.protocol === 'https:' ? https : http;
    const reqOpts = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + (parsed.search || ''),
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            'User-Agent': 'redirector-webhook/1.0',
            'X-Webhook-Signature': `sha256=${signature}`
        },
        timeout: timeoutMs
    };
    try {
        const r = transport.request(reqOpts, (resp) => {
            // Drain to free socket
            resp.on('data', () => {});
            resp.on('end', () => {
                _logWebhook({ linkId, ownerId, url, status: resp.statusCode, error: null });
            });
        });
        r.on('error', (err) => {
            _logWebhook({ linkId, ownerId, url, status: 0, error: err.message });
        });
        r.on('timeout', () => {
            r.destroy();
            _logWebhook({ linkId, ownerId, url, status: 0, error: 'timeout' });
        });
        r.write(body);
        r.end();
    } catch (e) {
        _logWebhook({ linkId, ownerId, url, status: 0, error: e.message });
    }
}

async function _logWebhook({ linkId, ownerId, url, status, error }) {
    try {
        const db = await getDb();
        await db.run(
            'INSERT INTO click_webhook_log (linkId, ownerId, url, status, error) VALUES (?, ?, ?, ?, ?)',
            [linkId || null, ownerId || null, url, status || 0, error]
        );
    } catch (e) { /* logging failure is non-fatal */ }
}

// ============================================================================
// Feature 7: Active hours window
// ============================================================================
/**
 * Returns true if the link is INSIDE its configured active-hours window
 * (or no window is configured). Hours are 0-23.
 */
function isWithinActiveHours(link) {
    if (!link) return true;
    const from = link.activeFromHour;
    const to = link.activeToHour;
    if (from == null || to == null) return true;
    const tz = link.activeTimezone || 'UTC';
    let hour;
    try {
        const fmt = new Intl.DateTimeFormat('en-US', { hour: 'numeric', hour12: false, timeZone: tz });
        const parts = fmt.formatToParts(new Date());
        const hPart = parts.find(p => p.type === 'hour');
        hour = parseInt(hPart ? hPart.value : '0', 10);
        if (hour === 24) hour = 0; // hour12:false sometimes returns 24 for midnight
    } catch (e) {
        hour = new Date().getUTCHours();
    }
    const f = Number(from), t = Number(to);
    if (!Number.isFinite(f) || !Number.isFinite(t)) return true;
    if (f === t) return true; // degenerate, treat as always-on
    if (f < t) return hour >= f && hour < t;
    // Wraps midnight: e.g. 22 → 6
    return hour >= f || hour < t;
}

// ============================================================================
// Feature 16: Click anomaly detection (3σ baseline)
// ============================================================================
/**
 * Cheap online update of mean/stddev for a link's hourly clicks.
 * Uses Welford's algorithm semantics in aggregate form.
 */
async function updateAnomalyBaseline(linkId, hourlyCount) {
    if (!linkId) return;
    const c = Number(hourlyCount);
    if (!Number.isFinite(c) || c < 0) return;
    try {
        const db = await getDb();
        const row = await db.get('SELECT * FROM link_anomaly_baselines WHERE linkId = ?', [linkId]);
        if (!row) {
            await db.run(
                'INSERT INTO link_anomaly_baselines (linkId, meanHourlyClicks, stddevHourlyClicks, sampleCount) VALUES (?, ?, 0, 1)',
                [linkId, c]
            );
            return;
        }
        const n = (row.sampleCount || 0) + 1;
        const delta = c - row.meanHourlyClicks;
        const newMean = row.meanHourlyClicks + delta / n;
        const m2 = row.stddevHourlyClicks * row.stddevHourlyClicks * Math.max(1, row.sampleCount - 1) + delta * (c - newMean);
        const newVariance = n > 1 ? m2 / (n - 1) : 0;
        const newStddev = Math.sqrt(Math.max(0, newVariance));
        await db.run(
            'UPDATE link_anomaly_baselines SET meanHourlyClicks = ?, stddevHourlyClicks = ?, sampleCount = ?, updatedAt = CURRENT_TIMESTAMP WHERE linkId = ?',
            [newMean, newStddev, n, linkId]
        );
    } catch (e) { /* non-fatal */ }
}

/**
 * Check whether the current hour's click count is anomalous (>3σ above mean).
 * Returns null when no baseline yet (need ≥5 samples) or no anomaly.
 */
async function detectAnomaly(linkId, currentHourCount) {
    try {
        const db = await getDb();
        const row = await db.get('SELECT * FROM link_anomaly_baselines WHERE linkId = ?', [linkId]);
        if (!row || row.sampleCount < 5 || row.stddevHourlyClicks <= 0) return null;
        const z = (currentHourCount - row.meanHourlyClicks) / row.stddevHourlyClicks;
        if (z >= 3) {
            return { isAnomaly: true, z, mean: row.meanHourlyClicks, stddev: row.stddevHourlyClicks, currentHourCount };
        }
        return null;
    } catch (e) { return null; }
}

// ============================================================================
// Feature 19: Cloaker preset profiles
// ============================================================================
const CLOAKER_PRESETS = {
    fast:     { redirectDelayMs: 1500, jitterMin: 200, jitterMax: 500 },
    balanced: { redirectDelayMs: 4000, jitterMin: 600, jitterMax: 1500 },
    stealth:  { redirectDelayMs: 7000, jitterMin: 1000, jitterMax: 2500 }
};

function getCloakerProfile(profileName) {
    const key = String(profileName || '').toLowerCase();
    return CLOAKER_PRESETS[key] || CLOAKER_PRESETS.balanced;
}

// ============================================================================
// Feature 17: Privacy-safe IP hash (used by template token)
// ============================================================================
/**
 * Returns first 16 chars of SHA-256(ip || secret). One-way and stable per-secret.
 */
function hashIp(ip, secret) {
    if (!ip) return '';
    return crypto.createHmac('sha256', secret || '').update(String(ip)).digest('hex').slice(0, 16);
}

// ============================================================================
module.exports = {
    // Feature 1
    isClickCapReached,
    // Feature 2
    hashAccessPin,
    verifyAccessPin,
    renderPinGatePage,
    // Feature 3
    destinationRulesMatch,
    classifyDevice,
    pickRotationWithRules,
    // Feature 6
    fireClickWebhook,
    // Feature 7
    isWithinActiveHours,
    // Feature 16
    updateAnomalyBaseline,
    detectAnomaly,
    // Feature 17
    hashIp,
    // Feature 19
    CLOAKER_PRESETS,
    getCloakerProfile
};
