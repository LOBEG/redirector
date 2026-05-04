/**
 * extraRoutes.js — mounts all additive feature routes.
 *
 * Designed as a single Express middleware factory so server.js needs only
 * one new line:  `app.use(extraRoutes(deps))`.
 *
 * Every route defined here is additive — none rewrites or shadows an existing
 * server.js handler. The helpers expect to be passed shared dependencies
 * (auth middleware, broadcastToUser, getUserPreferredDomain, etc.) so this
 * module stays decoupled from the boot wiring.
 *
 * Features delivered:
 *   - 4   QR code SVG endpoint
 *   - 9   Template revision history + restore
 *   - 11  API key management
 *   - 12  Click heatmap + conversion funnel
 *   - 14  Public read-only analytics share
 *   - 15  Public template marketplace + clone
 *   - 17  USER_AGENT / IP_HASH / REFERRER token preview helper
 *   - 18  Soft delete recycle bin (GET trash + restore)
 *   - 19  Cloaker preset profiles (list)
 *   - 20  Account export + import
 */
'use strict';

const express = require('express');
const QRCode = require('qrcode');
const chalk = require('chalk');
const crypto = require('crypto');

const getDb = require('./database');
const featuresExtra = require('./featuresExtra');
const apiKeyManager = require('./apiKeyManager');

function buildExtraRouter(deps) {
    const {
        authenticateToken,
        apiLimiter,
        getUserPreferredDomain,
        getJwtSecret
    } = deps;

    const router = express.Router();

    // ============================================================
    // Feature 4: QR code SVG for short links
    //   GET /api/short-links/:slug/qr.svg  (cache-friendly, public)
    //   GET /api/links/:id/qr.svg          (auth required)
    // ============================================================
    router.get('/api/short-links/:slug/qr.svg', async (req, res) => {
        try {
            const db = await getDb();
            const link = await db.get(
                'SELECT id, slug, ownerId FROM short_links WHERE slug = ? AND (isActive IS NULL OR isActive = 1)',
                [req.params.slug]
            );
            if (!link) return res.status(404).send('Not Found');
            const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
            const fullUrl = `${protocol}://${req.get('host')}/s/${link.slug}`;
            const svg = await QRCode.toString(fullUrl, { type: 'svg', margin: 1, width: 256, errorCorrectionLevel: 'M' });
            res.setHeader('Content-Type', 'image/svg+xml');
            res.setHeader('Cache-Control', 'public, max-age=3600');
            return res.send(svg);
        } catch (e) {
            console.error(chalk.red('[QR]'), e.message);
            res.status(500).send('Error generating QR');
        }
    });

    router.get('/api/links/:id/qr.svg', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const link = await db.get('SELECT id, googleAdsUrl FROM links WHERE id = ? AND ownerId = ? AND deletedAt IS NULL', [req.params.id, req.user.id]);
            if (!link) return res.status(404).send('Not Found');
            const target = link.googleAdsUrl;
            const svg = await QRCode.toString(target, { type: 'svg', margin: 1, width: 256, errorCorrectionLevel: 'M' });
            res.setHeader('Content-Type', 'image/svg+xml');
            res.setHeader('Cache-Control', 'private, max-age=600');
            return res.send(svg);
        } catch (e) {
            res.status(500).send('Error');
        }
    });

    // ============================================================
    // Feature 9: Template revision history + restore
    // ============================================================
    router.get('/api/templates/:id/revisions', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            // Verify ownership
            const tpl = await db.get('SELECT id FROM link_templates WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
            if (!tpl) return res.status(404).json({ error: 'Template not found' });
            const revisions = await db.all(
                'SELECT id, savedAt, description, LENGTH(htmlContent) as size FROM link_template_revisions WHERE templateId = ? ORDER BY savedAt DESC LIMIT 50',
                [req.params.id]
            );
            res.json(revisions);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.post('/api/templates/:id/revisions/:revisionId/restore', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const tpl = await db.get('SELECT id FROM link_templates WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
            if (!tpl) return res.status(404).json({ error: 'Template not found' });
            const rev = await db.get(
                'SELECT htmlContent FROM link_template_revisions WHERE id = ? AND templateId = ? AND ownerId = ?',
                [req.params.revisionId, req.params.id, req.user.id]
            );
            if (!rev) return res.status(404).json({ error: 'Revision not found' });
            // Snapshot current state before restoring (so restore is itself reversible)
            const current = await db.get('SELECT htmlContent, description FROM link_templates WHERE id = ?', [req.params.id]);
            if (current) {
                await db.run(
                    'INSERT INTO link_template_revisions (templateId, ownerId, htmlContent, description) VALUES (?, ?, ?, ?)',
                    [req.params.id, req.user.id, current.htmlContent, current.description || 'Auto-snapshot before restore']
                );
            }
            await db.run('UPDATE link_templates SET htmlContent = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?',
                [rev.htmlContent, req.params.id]);
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // Manual snapshot endpoint (templateStore.save also auto-snapshots — see hook below)
    router.post('/api/templates/:id/snapshot', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const tpl = await db.get('SELECT * FROM link_templates WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
            if (!tpl) return res.status(404).json({ error: 'Template not found' });
            await db.run(
                'INSERT INTO link_template_revisions (templateId, ownerId, htmlContent, description) VALUES (?, ?, ?, ?)',
                [tpl.id, req.user.id, tpl.htmlContent, req.body.description || 'Manual snapshot']
            );
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // ============================================================
    // Feature 11: API key management
    // ============================================================
    router.get('/api/api-keys', apiLimiter, authenticateToken, async (req, res) => {
        try { res.json(await apiKeyManager.listApiKeys(req.user.id)); }
        catch (e) { res.status(500).json({ error: e.message }); }
    });
    router.post('/api/api-keys', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const { name, scopes } = req.body;
            const result = await apiKeyManager.createApiKey({ ownerId: req.user.id, name, scopes });
            res.status(201).json(result);
        } catch (e) { res.status(400).json({ error: e.message }); }
    });
    router.delete('/api/api-keys/:id', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const ok = await apiKeyManager.revokeApiKey(req.user.id, req.params.id);
            if (!ok) return res.status(404).json({ error: 'Key not found' });
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // ============================================================
    // Feature 12: Heatmap + conversion funnel
    // ============================================================
    router.get('/api/stats/click-heatmap', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const days = Math.max(1, Math.min(365, parseInt(req.query.days, 10) || 30));
            // SQLite: %w = day of week (0=Sun), %H = hour 0-23
            const rows = await db.all(`
                SELECT
                    CAST(strftime('%w', timestamp) AS INTEGER) as dow,
                    CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                    COUNT(*) as total,
                    SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END) as bots
                FROM clicks
                JOIN links l ON clicks.linkId = l.id
                WHERE l.ownerId = ?
                  AND clicks.timestamp >= datetime('now', '-' || ? || ' days')
                GROUP BY dow, hour
            `, [req.user.id, days]);
            // Build a 7x24 matrix (humans only — bots subtracted)
            const matrix = Array.from({ length: 7 }, () => Array(24).fill(0));
            for (const r of rows) {
                if (r.dow >= 0 && r.dow < 7 && r.hour >= 0 && r.hour < 24) {
                    matrix[r.dow][r.hour] = (r.total || 0) - (r.bots || 0);
                }
            }
            res.json({ days, matrix });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.get('/api/stats/conversion-funnel', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const days = Math.max(1, Math.min(365, parseInt(req.query.days, 10) || 7));
            const totals = await db.get(`
                SELECT
                    COUNT(*) as impressions,
                    SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END) as botBlocks,
                    SUM(CASE WHEN isBot = 0 THEN 1 ELSE 0 END) as humanClicks
                FROM clicks
                JOIN links l ON clicks.linkId = l.id
                WHERE l.ownerId = ?
                  AND clicks.timestamp >= datetime('now', '-' || ? || ' days')
            `, [req.user.id, days]);
            const botHops = await db.get(`
                SELECT COUNT(*) as totalHops
                FROM bot_redirect_events bre
                JOIN links l ON bre.linkId = l.id
                WHERE l.ownerId = ?
                  AND bre.timestamp >= datetime('now', '-' || ? || ' days')
            `, [req.user.id, days]);
            const t = totals || { impressions: 0, botBlocks: 0, humanClicks: 0 };
            res.json({
                days,
                impressions:    t.impressions || 0,     // every page-serve
                unlockAttempts: t.humanClicks || 0,     // humans that landed on cloaker
                successfulUnlocks: t.humanClicks || 0,  // approximated 1:1 — humans always proceed
                botBlocks:      t.botBlocks || 0,
                botRedirectHops: (botHops && botHops.totalHops) || 0
            });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // ============================================================
    // Feature 14: Public read-only analytics share
    // ============================================================
    router.post('/api/links/:id/share', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const link = await db.get('SELECT id FROM links WHERE id = ? AND ownerId = ? AND deletedAt IS NULL', [req.params.id, req.user.id]);
            if (!link) return res.status(404).json({ error: 'Link not found' });
            const days = Math.max(1, Math.min(365, parseInt(req.body.expiresInDays, 10) || 30));
            const token = crypto.randomBytes(24).toString('base64url');
            const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
            await db.run(
                'INSERT INTO analytics_share_tokens (token, linkId, ownerId, expiresAt) VALUES (?, ?, ?, ?)',
                [token, link.id, req.user.id, expiresAt]
            );
            const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
            const url = `${protocol}://${req.get('host')}/pub/stats/${token}`;
            res.json({ token, url, expiresAt });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.get('/api/links/:id/shares', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const rows = await db.all(
                'SELECT id, token, expiresAt, createdAt FROM analytics_share_tokens WHERE linkId = ? AND ownerId = ? ORDER BY createdAt DESC',
                [req.params.id, req.user.id]
            );
            res.json(rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.delete('/api/share-tokens/:id', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            await db.run('DELETE FROM analytics_share_tokens WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // Public dashboard — NO PII, numbers only.
    router.get('/pub/stats/:token', async (req, res) => {
        try {
            const db = await getDb();
            const row = await db.get('SELECT * FROM analytics_share_tokens WHERE token = ?', [req.params.token]);
            if (!row) return res.status(404).send(_publicNotFound());
            if (row.expiresAt && new Date(row.expiresAt) < new Date()) {
                return res.status(410).send(_publicNotFound('This share link has expired.'));
            }
            const link = await db.get('SELECT id, clicks, botClicks, createdAt FROM links WHERE id = ? AND deletedAt IS NULL', [row.linkId]);
            if (!link) return res.status(404).send(_publicNotFound());
            const byDay = await db.all(`
                SELECT DATE(timestamp) as day,
                       COUNT(*) as total,
                       SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END) as bots
                FROM clicks
                WHERE linkId = ?
                  AND timestamp >= datetime('now', '-30 days')
                GROUP BY day
                ORDER BY day ASC`,
                [link.id]
            );
            const topCountries = await db.all(`
                SELECT country, COUNT(*) as count
                FROM clicks WHERE linkId = ? AND isBot = 0
                  AND country IS NOT NULL AND country != 'Unknown'
                GROUP BY country ORDER BY count DESC LIMIT 10`,
                [link.id]
            );
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('X-Robots-Tag', 'noindex, nofollow');
            res.send(_renderPublicStats({ link, byDay, topCountries }));
        } catch (e) {
            console.error('[PUBSTATS]', e.message);
            res.status(500).send(_publicNotFound('An error occurred.'));
        }
    });

    // ============================================================
    // Feature 15: Public template marketplace
    // ============================================================
    router.get('/api/templates/public', apiLimiter, async (req, res) => {
        try {
            const db = await getDb();
            const rows = await db.all(`
                SELECT t.id, t.name, t.description, t.createdAt, t.updatedAt,
                       LENGTH(t.htmlContent) as contentSize,
                       u.username as authorEmail
                FROM link_templates t
                LEFT JOIN users u ON u.id = t.ownerId
                WHERE t.isPublic = 1
                ORDER BY t.updatedAt DESC LIMIT 200
            `);
            // Hide raw email — just show first part
            res.json(rows.map(r => ({
                id: r.id, name: r.name, description: r.description,
                contentSize: r.contentSize,
                author: r.authorEmail ? r.authorEmail.split('@')[0] : 'anon',
                updatedAt: r.updatedAt
            })));
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.patch('/api/templates/:id/visibility', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const tpl = await db.get('SELECT id FROM link_templates WHERE id = ? AND ownerId = ?', [req.params.id, req.user.id]);
            if (!tpl) return res.status(404).json({ error: 'Template not found' });
            const isPublic = req.body.isPublic ? 1 : 0;
            await db.run('UPDATE link_templates SET isPublic = ? WHERE id = ?', [isPublic, tpl.id]);
            res.json({ success: true, isPublic: !!isPublic });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.post('/api/templates/:id/clone', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const src = await db.get(
                'SELECT * FROM link_templates WHERE id = ? AND (isPublic = 1 OR ownerId = ?)',
                [req.params.id, req.user.id]
            );
            if (!src) return res.status(404).json({ error: 'Template not found or not public' });
            // Generate a unique name
            let name = `${src.name} (cloned)`;
            let suffix = 1;
            while (await db.get('SELECT id FROM link_templates WHERE ownerId = ? AND name = ?', [req.user.id, name])) {
                suffix++;
                name = `${src.name} (cloned ${suffix})`;
                if (suffix > 100) break;
            }
            const result = await db.run(
                'INSERT INTO link_templates (ownerId, name, description, htmlContent, isDefault, isPublic) VALUES (?, ?, ?, ?, 0, 0)',
                [req.user.id, name, src.description, src.htmlContent]
            );
            res.status(201).json({ id: result.lastID, name, description: src.description });
        } catch (e) { res.status(400).json({ error: e.message }); }
    });

    // ============================================================
    // Feature 18: Soft delete recycle bin
    // ============================================================
    router.get('/api/links/trash', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const rows = await db.all(
                'SELECT id, googleAdsUrl, destinationUrlDesktop, deletedAt, expiresAt, clicks, botClicks FROM links WHERE ownerId = ? AND deletedAt IS NOT NULL ORDER BY deletedAt DESC LIMIT 200',
                [req.user.id]
            );
            res.json(rows);
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.post('/api/links/:id/restore', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const result = await db.run(
                'UPDATE links SET deletedAt = NULL WHERE id = ? AND ownerId = ? AND deletedAt IS NOT NULL',
                [req.params.id, req.user.id]
            );
            if (result.changes === 0) return res.status(404).json({ error: 'Link not found in trash' });
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // ============================================================
    // Feature 19: Cloaker presets (read)
    // ============================================================
    router.get('/api/cloaker-presets', apiLimiter, authenticateToken, (req, res) => {
        res.json(featuresExtra.CLOAKER_PRESETS);
    });

    // ============================================================
    // Feature 20: Account export / import
    // ============================================================
    router.get('/api/account/export', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const db = await getDb();
            const links = await db.all('SELECT * FROM links WHERE ownerId = ? AND deletedAt IS NULL', [req.user.id]);
            const ids = links.map(l => l.id);
            const placeholders = ids.length ? ids.map(() => '?').join(',') : 'NULL';
            const destinations = ids.length
                ? await db.all(`SELECT * FROM link_destinations WHERE linkId IN (${placeholders})`, ids)
                : [];
            const shortLinks = await db.all('SELECT * FROM short_links WHERE ownerId = ?', [req.user.id]);
            const templates = await db.all('SELECT * FROM link_templates WHERE ownerId = ?', [req.user.id]);
            const domains = await db.all('SELECT * FROM custom_domains WHERE ownerId = ?', [req.user.id]);
            const payload = {
                version: 1,
                exportedAt: new Date().toISOString(),
                accountEmail: req.user.user,
                links, destinations, shortLinks, templates, domains
            };
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="account-export-${Date.now()}.json"`);
            res.send(JSON.stringify(payload, null, 2));
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    router.post('/api/account/import', apiLimiter, authenticateToken, async (req, res) => {
        try {
            const data = req.body;
            if (!data || data.version !== 1) {
                return res.status(400).json({ error: 'Invalid export file (missing or unsupported version).' });
            }
            const db = await getDb();
            const counts = { templates: 0, shortLinks: 0, domains: 0 };
            // Templates
            if (Array.isArray(data.templates)) {
                for (const t of data.templates) {
                    if (!t.name || !t.htmlContent) continue;
                    let name = t.name;
                    let suffix = 1;
                    // Find an unused name for this user
                    while (await db.get('SELECT id FROM link_templates WHERE ownerId = ? AND name = ?', [req.user.id, name])) {
                        suffix++;
                        name = `${t.name} (imported ${suffix})`;
                        if (suffix > 100) break;
                    }
                    await db.run(
                        'INSERT INTO link_templates (ownerId, name, description, htmlContent, isDefault, isPublic) VALUES (?, ?, ?, ?, 0, 0)',
                        [req.user.id, name, t.description || null, t.htmlContent]
                    );
                    counts.templates++;
                }
            }
            // Short links — generate fresh slugs to avoid collisions
            if (Array.isArray(data.shortLinks)) {
                for (const s of data.shortLinks) {
                    if (!s.targetUrl) continue;
                    const newSlug = s.slug + '-' + crypto.randomBytes(2).toString('hex');
                    try {
                        await db.run(
                            'INSERT INTO short_links (slug, targetUrl, ownerId, title, expiresAt, isActive, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)',
                            [newSlug, s.targetUrl, req.user.id, s.title || null, s.expiresAt || null, 1, s.metadata || null]
                        );
                        counts.shortLinks++;
                    } catch (e) { /* duplicate slug fallback */ }
                }
            }
            // Custom domains — only insert if not already taken
            if (Array.isArray(data.domains)) {
                for (const d of data.domains) {
                    if (!d.hostname) continue;
                    const exists = await db.get('SELECT id FROM custom_domains WHERE hostname = ?', [d.hostname]);
                    if (exists) continue;
                    try {
                        await db.run(
                            'INSERT INTO custom_domains (ownerId, hostname, purpose) VALUES (?, ?, ?)',
                            [req.user.id, d.hostname, d.purpose || 'link']
                        );
                        counts.domains++;
                    } catch (e) { /* dup */ }
                }
            }
            // NOTE: link records are NOT re-imported — IDs and HMAC signatures
            // are server-bound and would require re-generation. This matches
            // the behavior of most "account migrations" — preferences and
            // assets transfer; live tracking artifacts must be regenerated.
            res.json({ success: true, imported: counts });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });

    // ============================================================
    // Feature 17: Token preview helper — exposes new token names
    // ============================================================
    router.get('/api/templates/tokens-extended', (req, res) => {
        res.json({
            tokens: [
                '%%DESTINATION_URL%%', '%%RAY_ID%%', '%%TIMESTAMP%%',
                '%%LINK_ID%%', '%%COUNTRY%%', '%%DOMAIN%%', '%%REDIRECT_DELAY%%',
                '%%USER_AGENT%%', '%%IP_HASH%%', '%%REFERRER%%'
            ],
            descriptions: {
                '%%USER_AGENT%%': "Visitor's User-Agent string (HTML-escaped)",
                '%%IP_HASH%%': 'Privacy-safe one-way hash of visitor IP (16 hex chars)',
                '%%REFERRER%%': "HTTP Referer header (HTML-escaped, may be empty)"
            }
        });
    });

    return router;
}

// ----------------------------------------------------------------
// Public dashboard rendering helpers (Feature 14)
// ----------------------------------------------------------------
function _publicNotFound(msg) {
    const text = msg || 'This share link is invalid.';
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Not Found</title></head><body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f7fa;color:#666"><div style="text-align:center"><h1>404</h1><p>${_esc(text)}</p></div></body></html>`;
}

function _esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function _renderPublicStats({ link, byDay, topCountries }) {
    const human = Math.max(0, (link.clicks || 0) - (link.botClicks || 0));
    const dayRows = byDay.map(d => `<tr><td>${_esc(d.day)}</td><td>${(d.total||0)-(d.bots||0)}</td><td>${d.bots||0}</td></tr>`).join('');
    const countryRows = topCountries.map(c => `<tr><td>${_esc(c.country)}</td><td>${c.count}</td></tr>`).join('') || '<tr><td colspan="2" style="text-align:center;color:#999">No data</td></tr>';
    return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Link Performance</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;color:#1a1a2e;padding:2rem}
.wrap{max-width:900px;margin:0 auto}
h1{font-size:1.4rem;margin-bottom:.25rem}
.meta{color:#666;font-size:.85rem;margin-bottom:1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}
.card{background:#fff;border-radius:8px;padding:1rem 1.25rem;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.val{font-size:1.5rem;font-weight:700;color:#4f46e5}
.lbl{font-size:.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:1.5rem}
th,td{padding:.6rem .9rem;text-align:left;border-bottom:1px solid #e5e7eb;font-size:.875rem}
th{background:#f9fafb;font-weight:600;color:#374151}
tr:last-child td{border-bottom:none}
.foot{text-align:center;color:#bbb;font-size:.75rem;margin-top:1.5rem}
</style></head>
<body>
<div class="wrap">
<h1>Link Performance Report</h1>
<p class="meta">Public read-only summary &bull; No personal data shown</p>
<div class="grid">
  <div class="card"><div class="val">${human}</div><div class="lbl">Human clicks</div></div>
  <div class="card"><div class="val">${link.botClicks||0}</div><div class="lbl">Bots blocked</div></div>
  <div class="card"><div class="val">${link.clicks||0}</div><div class="lbl">Total impressions</div></div>
</div>
<h2 style="font-size:1rem;margin:1rem 0 .5rem;color:#374151">Last 30 days</h2>
<table><thead><tr><th>Date</th><th>Humans</th><th>Bots</th></tr></thead><tbody>${dayRows||'<tr><td colspan="3" style="text-align:center;color:#999">No data</td></tr>'}</tbody></table>
<h2 style="font-size:1rem;margin:1rem 0 .5rem;color:#374151">Top countries</h2>
<table><thead><tr><th>Country</th><th>Clicks</th></tr></thead><tbody>${countryRows}</tbody></table>
<div class="foot">Generated ${new Date().toISOString()}</div>
</div></body></html>`;
}

module.exports = { buildExtraRouter };
