#!/usr/bin/env node
/**
 * Extra-features smoke test — exercises the additive routes added in this PR.
 * Boots the server, authenticates as the auto-created admin, and asserts that
 * every new endpoint returns a sensible response.
 */
'use strict';

process.env.NODE_ENV = 'test';
process.env.PORT = process.env.PORT || '40124';
process.env.JWT_SECRET = 'extra-smoke-secret';
process.env.REDIRECTOR_SECRET = 'extra-smoke-redir-secret';
process.env.ADMIN_EMAIL = 'extra-smoke@example.com';

const http = require('http');

function req(path, opts = {}) {
    return new Promise((resolve, reject) => {
        const r = http.request({
            host: '127.0.0.1', port: process.env.PORT, method: opts.method || 'GET', path,
            headers: Object.assign({
                'User-Agent': 'Mozilla/5.0 (Macintosh) Chrome/120.0 Safari/537.36',
                'Accept': 'application/json'
            }, opts.headers || {}),
            timeout: 8000
        }, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });
        r.on('error', reject);
        r.on('timeout', () => { r.destroy(); reject(new Error('timeout: ' + path)); });
        if (opts.body) r.write(typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body));
        r.end();
    });
}

async function getAdminJwt() {
    const fs = require('fs');
    const path = require('path');
    // Read admin access key from logs is tricky — instead, use the auth library
    // to mint a JWT directly. The admin user is auto-created at startup.
    const cfg = require('../src/config');
    const jwt = require('jsonwebtoken');
    const getDb = require('../src/lib/database');
    const db = await getDb();
    const adminEmail = process.env.ADMIN_EMAIL;
    const u = await db.get('SELECT id, username, role FROM users WHERE username = ?', adminEmail);
    if (!u) throw new Error('Admin user not yet provisioned');
    return jwt.sign({ id: u.id, user: u.username, role: u.role }, cfg.jwt.secret, { expiresIn: '1h' });
}

async function main() {
    // Boot server
    require('../src/server.js');
    await new Promise(r => setTimeout(r, 1500));

    let failures = 0;
    async function check(name, fn) {
        try { await fn(); console.log(`[X-SMOKE] ✓ ${name}`); }
        catch (e) { failures++; console.error(`[X-SMOKE] ✗ ${name}: ${e.message}`); }
    }

    const token = await getAdminJwt();
    const auth = { 'Authorization': `Bearer ${token}` };
    const json = (b) => ({ ...auth, 'Content-Type': 'application/json' });

    // ===== Feature 11: API keys =====
    let createdApiKey;
    await check('POST /api/api-keys creates a key', async () => {
        const r = await req('/api/api-keys', { method: 'POST', headers: json(), body: { name: 'smoke-key' } });
        if (r.status !== 201) throw new Error(`status ${r.status}`);
        const obj = JSON.parse(r.body);
        if (!obj.key || !obj.key.startsWith('rdr_')) throw new Error('bad key format');
        // Hold the API key in-memory ONLY — do NOT log it (clear-text-logging risk).
        createdApiKey = obj;
    });

    await check('GET /api/api-keys lists keys', async () => {
        const r = await req('/api/api-keys', { headers: auth });
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        const list = JSON.parse(r.body);
        if (!Array.isArray(list) || list.length === 0) throw new Error('empty list');
    });

    await check('API key auth works as Bearer token', async () => {
        const r = await req('/api/me', { headers: { 'Authorization': `Bearer ${createdApiKey.key}` }});
        if (r.status !== 200) throw new Error(`status ${r.status}`);
    });

    await check('DELETE /api/api-keys/:id revokes', async () => {
        const r = await req(`/api/api-keys/${createdApiKey.id}`, { method: 'DELETE', headers: auth });
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        // After revocation, key should no longer authenticate
        const r2 = await req('/api/me', { headers: { 'Authorization': `Bearer ${createdApiKey.key}` }});
        if (r2.status !== 401) throw new Error(`expected 401 after revoke, got ${r2.status}`);
        // Drop the plaintext key from memory once we're done with it so it
        // can't be accidentally serialized by any later error path.
        createdApiKey.key = null;
    });

    // ===== Feature 12: heatmap + funnel =====
    await check('GET /api/stats/click-heatmap returns 7x24 matrix', async () => {
        const r = await req('/api/stats/click-heatmap', { headers: auth });
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        const obj = JSON.parse(r.body);
        if (!Array.isArray(obj.matrix) || obj.matrix.length !== 7) throw new Error('bad matrix');
        if (obj.matrix[0].length !== 24) throw new Error('bad row width');
    });
    await check('GET /api/stats/conversion-funnel works', async () => {
        const r = await req('/api/stats/conversion-funnel', { headers: auth });
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        const obj = JSON.parse(r.body);
        if (typeof obj.impressions !== 'number') throw new Error('no impressions field');
    });

    // ===== Feature 17: extended tokens =====
    await check('GET /api/templates/tokens-extended lists new tokens', async () => {
        const r = await req('/api/templates/tokens-extended');
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        const obj = JSON.parse(r.body);
        if (!obj.tokens.includes('%%USER_AGENT%%')) throw new Error('missing %%USER_AGENT%%');
        if (!obj.tokens.includes('%%IP_HASH%%')) throw new Error('missing %%IP_HASH%%');
        if (!obj.tokens.includes('%%REFERRER%%')) throw new Error('missing %%REFERRER%%');
    });

    // ===== Feature 18: trash =====
    await check('GET /api/links/trash returns array', async () => {
        const r = await req('/api/links/trash', { headers: auth });
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        if (!Array.isArray(JSON.parse(r.body))) throw new Error('not array');
    });

    // ===== Feature 19: cloaker presets =====
    await check('GET /api/cloaker-presets returns 3 presets', async () => {
        const r = await req('/api/cloaker-presets', { headers: auth });
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        const obj = JSON.parse(r.body);
        if (!obj.fast || !obj.balanced || !obj.stealth) throw new Error('missing preset');
    });

    // ===== Feature 20: account export =====
    await check('GET /api/account/export returns json', async () => {
        const r = await req('/api/account/export', { headers: auth });
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        const obj = JSON.parse(r.body);
        if (obj.version !== 1) throw new Error('bad export version');
        if (!Array.isArray(obj.links)) throw new Error('no links array');
        if (!Array.isArray(obj.templates)) throw new Error('no templates array');
    });

    // ===== Feature 15: public templates =====
    await check('GET /api/templates/public returns array', async () => {
        const r = await req('/api/templates/public');
        if (r.status !== 200) throw new Error(`status ${r.status}`);
        if (!Array.isArray(JSON.parse(r.body))) throw new Error('not array');
    });

    // ===== Feature 14: public stats — invalid token returns 404 =====
    await check('GET /pub/stats/<bad> returns 404', async () => {
        const r = await req('/pub/stats/nonexistent_token_xyz');
        if (r.status !== 404) throw new Error(`status ${r.status}`);
    });

    // ===== Feature 4: QR endpoint for nonexistent slug returns 404 =====
    await check('GET /api/short-links/nonexistent/qr.svg returns 404', async () => {
        const r = await req('/api/short-links/nonexistent/qr.svg');
        if (r.status !== 404) throw new Error(`status ${r.status}`);
    });

    // ===== Feature 2: PIN endpoint with no payload returns 400 =====
    await check('POST /tr/v2/pin without body returns 400', async () => {
        const r = await req('/tr/v2/pin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: {} });
        if (r.status !== 400) throw new Error(`status ${r.status}`);
    });

    // ===== Feature 16/13: anomaly + auto-pause helpers don't blow up =====
    await check('featuresExtra helpers callable', async () => {
        const fe = require('../src/lib/featuresExtra');
        if (fe.isClickCapReached({ maxClicks: 10, clicks: 5, botClicks: 0 })) throw new Error('cap false-positive');
        if (!fe.isClickCapReached({ maxClicks: 10, clicks: 12, botClicks: 0 })) throw new Error('cap miss');
        if (!fe.isWithinActiveHours({})) throw new Error('default should be active');
        const profile = fe.getCloakerProfile('stealth');
        if (profile.redirectDelayMs < 1000) throw new Error('bad stealth profile');
        if (!fe.destinationRulesMatch(null, {})) throw new Error('null rules should match');
        if (fe.destinationRulesMatch({ countries: ['US'] }, { country: 'RU' })) throw new Error('country filter broken');
        if (!fe.destinationRulesMatch({ countries: ['US'] }, { country: 'us' })) throw new Error('country case-insensitive broken');
    });

    if (failures > 0) {
        console.error(`[X-SMOKE] ${failures} failure(s)`);
        process.exit(1);
    }
    console.log('\n[X-SMOKE] All extra-feature checks passed.');
    process.exit(0);
}

main().catch(e => { console.error('[X-SMOKE] Fatal:', e); process.exit(1); });
