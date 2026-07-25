const getDb = require('./database');
const googleAdsRedirector = require('./googleAdsRedirector');
const chalk = require('chalk');
const cache = require('./cache');
const { v4: uuidv4 } = require('uuid');

// Cache TTLs for different query types (in seconds)
const CACHE_TTL = {
    dashboardStats: 30,   // 30s — frequently polled, short TTL
    geoSummary: 120,      // 2min — changes slowly
    topLinks: 60,         // 1min
    clickRate: 30         // 30s
};

const linkStore = {
    async createLinkWithRotations({ ownerId, publicDomain, expiresAt, rotations, templateId, singleUse }) {
        const db = await getDb();
        
        const firstUrl = rotations[0]?.url;
        if (!firstUrl) throw new Error("Invalid rotation data: At least one destination URL is required.");
        
        const { googleAdsUrl, internalId } = googleAdsRedirector.createRedirect(firstUrl, publicDomain);

        await db.run('BEGIN TRANSACTION');
        try {
            // MODIFIED: Added templateId and singleUse to the INSERT statement
            await db.run(
                `INSERT INTO links (id, ownerId, googleAdsUrl, destinationUrlDesktop, expiresAt, clicks, botClicks, templateId, singleUse) 
                 VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)`,
                [internalId, ownerId, googleAdsUrl, firstUrl, expiresAt, templateId, singleUse ? 1 : 0]
            );

            for (const rotation of rotations) {
                await db.run(
                    `INSERT INTO link_destinations (linkId, url, platform, weight) 
                     VALUES (?, ?, ?, ?)`,
                    [internalId, rotation.url, rotation.platform || 'desktop', rotation.weight || 100]
                );
            }
            
            await db.run('COMMIT');
            console.log(chalk.green(`[LINKSTORE] ✓ Created link ${internalId} for user ${ownerId}`));
            
            return { 
                id: internalId, 
                ownerId, 
                googleAdsUrl, 
                destinationUrlDesktop: firstUrl, 
                expiresAt, 
                clicks: 0, 
                botClicks: 0,
                templateId,
                singleUse: singleUse ? 1 : 0
            };
        } catch (error) {
            await db.run('ROLLBACK');
            console.error(chalk.red(`[LINKSTORE] Failed to create link: ${error.message}`));
            throw error;
        }
    },

    async getLinksForUser(ownerId) {
        const db = await getDb();
        // Feature 18: hide soft-deleted links from default list (recycle bin
        // surfaces them via /api/links/trash). One-line additive WHERE clause.
        return db.all('SELECT * FROM links WHERE ownerId = ? AND deletedAt IS NULL ORDER BY createdAt DESC', ownerId);
    },
    
    async getRotationsForLink(linkId) {
        const db = await getDb();
        return db.all('SELECT * FROM link_destinations WHERE linkId = ?', linkId);
    },

    /**
     * Select the next destination URL from rotations using weighted random selection.
     * If the link has multiple rotations in link_destinations, picks one based on weight.
     * Falls back to the link's destinationUrlDesktop if no rotations exist.
     * 
     * @param {string} linkId - The link ID
     * @param {string} fallbackUrl - Fallback URL (link.destinationUrlDesktop) if no rotations
     * @returns {Promise<string>} The selected destination URL
     */
    async getNextRotationUrl(linkId, fallbackUrl) {
        try {
            const db = await getDb();
            const rotations = await db.all(
                'SELECT url, weight FROM link_destinations WHERE linkId = ?', 
                linkId
            );

            if (!rotations || rotations.length === 0) {
                return fallbackUrl;
            }

            // Single rotation — skip random selection
            if (rotations.length === 1) {
                return rotations[0].url;
            }

            // Weighted random selection across all rotations
            const totalWeight = rotations.reduce((sum, r) => sum + (r.weight || 100), 0);
            let random = Math.random() * totalWeight;

            for (const rotation of rotations) {
                random -= (rotation.weight || 100);
                if (random <= 0) {
                    return rotation.url;
                }
            }

            // Fallback to last rotation (shouldn't normally reach here)
            return rotations[rotations.length - 1].url;
        } catch (e) {
            console.error(chalk.red(`[LINKSTORE] Rotation selection error: ${e.message}`));
            return fallbackUrl;
        }
    },

    async getLink(id) {
        const db = await getDb();
        // MODIFIED: Fetches template content along with the link
        return db.get(`
            SELECT 
                l.*,
                t.htmlContent
            FROM links l
            LEFT JOIN link_templates t ON l.templateId = t.id
            WHERE l.id = ?
        `, id);
    },
    
    async deleteLink(id, ownerId) {
        const db = await getDb();
        const link = await db.get('SELECT id FROM links WHERE id = ? AND ownerId = ?', [id, ownerId]);
        if (!link) throw new Error("Link not found or permission denied.");

        // Feature 18: soft delete — set deletedAt rather than dropping rows.
        // The recycle bin endpoint can restore within the retention window.
        // Hard-delete remains available via DELETE FROM links once trash is purged.
        const result = await db.run(
            'UPDATE links SET deletedAt = CURRENT_TIMESTAMP WHERE id = ? AND ownerId = ? AND deletedAt IS NULL',
            [id, ownerId]
        );
        return result.changes > 0;
    },
    
    async logClick({ linkId, isBot, ipAddress, userAgent, country, referrer, destinationUrl, botScore, botConfidence, botSignals }) {
        const db = await getDb();
        const isBotInt = isBot ? 1 : 0;
        const emoji = isBotInt ? '🤖' : '👤';
        
        console.log(chalk.cyan(`[LINKSTORE] ${emoji} Logging ${isBotInt ? 'BOT' : 'HUMAN'} click for ${linkId}`));

        try {
            // Check if this IP has clicked this link before (unique click tracking)
            let isUnique = 0;
            if (!isBotInt && ipAddress) {
                const existing = await db.get(
                    'SELECT id FROM clicks WHERE linkId = ? AND ipAddress = ? AND isBot = 0 LIMIT 1',
                    [linkId, ipAddress]
                );
                isUnique = existing ? 0 : 1;
            }

            // Serialize bot signals safely (truncated to keep row size sane)
            let signalsJson = null;
            if (Array.isArray(botSignals) && botSignals.length > 0) {
                try {
                    const trimmed = botSignals.slice(0, 12).map(s => String(s).slice(0, 120));
                    signalsJson = JSON.stringify(trimmed);
                    if (signalsJson.length > 1024) signalsJson = signalsJson.slice(0, 1024);
                } catch (_) { signalsJson = null; }
            }

            await db.run(
                `INSERT INTO clicks (linkId, isBot, ipAddress, userAgent, country, referrer, destinationUrl, timestamp, isUnique, botScore, botConfidence, botSignals) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?)`,
                [linkId, isBotInt, ipAddress, userAgent, country, referrer, destinationUrl, isUnique,
                 typeof botScore === 'number' ? botScore : 0,
                 botConfidence || null,
                 signalsJson]
            );
            
            if (isBotInt) {
                await db.run('UPDATE links SET botClicks = COALESCE(botClicks, 0) + 1 WHERE id = ?', linkId);
            } else {
                await db.run('UPDATE links SET clicks = COALESCE(clicks, 0) + 1 WHERE id = ?', linkId);
            }

            // Invalidate cached stats for the link owner (stats will be recalculated on next request)
            try {
                const link = await db.get('SELECT ownerId FROM links WHERE id = ?', [linkId]);
                if (link) {
                    await cache.del(`stats:dashboard:${link.ownerId}`);
                }
            } catch (cacheErr) {
                // Cache invalidation failure is non-critical — stats will remain stale until TTL expires
                console.warn(chalk.yellow(`[LINKSTORE] Cache invalidation failed: ${cacheErr.message}`));
            }
            
            return true;
        } catch (err) {
            console.error(chalk.red(`[LINKSTORE] ✗ Error logging click: ${err.message}`));
            return false;
        }
    },
    
    async getClicksByDay(ownerId, days) {
        const db = await getDb();
        return db.all(`
            SELECT 
                date(timestamp) as date,
                SUM(CASE WHEN isBot = 0 THEN 1 ELSE 0 END) as humanClicks,
                SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END) as botClicks
            FROM clicks 
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?)
            AND timestamp >= date('now', '-' || ? || ' days')
            GROUP BY date(timestamp)
            ORDER BY date(timestamp) ASC
        `, [ownerId, days]);
    },

    async getDetailedClicksForLink(linkId, ownerId) {
        const db = await getDb();
        const link = await db.get('SELECT id FROM links WHERE id = ? AND ownerId = ?', [linkId, ownerId]);
        if (!link) return null;

        const clicks = await db.all(
            'SELECT * FROM clicks WHERE linkId = ? ORDER BY timestamp DESC LIMIT 100',
            linkId
        );
        
        return clicks.map(c => ({
            ...c,
            isBot: c.isBot === 1,
            isUnique: c.isUnique === 1,
            botSignals: c.botSignals ? (() => { try { return JSON.parse(c.botSignals); } catch (_) { return []; } })() : []
        }));
    },

    /**
     * Recent bot click feed for the bot-feed dashboard panel.
     * Returns the latest bot hits across all of the owner's links, with bot score,
     * confidence, signals, and link metadata for display.
     */
    async getBotFeed(ownerId, limit = 100) {
        const db = await getDb();
        const safeLimit = Math.max(1, Math.min(parseInt(limit, 10) || 100, 500));
        const rows = await db.all(`
            SELECT c.id, c.linkId, c.timestamp, c.ipAddress, c.userAgent, c.country,
                   c.referrer, c.botScore, c.botConfidence, c.botSignals,
                   l.destinationUrlDesktop
            FROM clicks c
            JOIN links l ON c.linkId = l.id
            WHERE l.ownerId = ? AND c.isBot = 1
            ORDER BY c.timestamp DESC
            LIMIT ?
        `, [ownerId, safeLimit]);
        return rows.map(r => ({
            ...r,
            botSignals: r.botSignals ? (() => { try { return JSON.parse(r.botSignals); } catch (_) { return []; } })() : []
        }));
    },

    /**
     * Recent verified-human click feed for the human conversions panel.
     */
    async getHumanFeed(ownerId, limit = 100) {
        const db = await getDb();
        const safeLimit = Math.max(1, Math.min(parseInt(limit, 10) || 100, 500));
        const rows = await db.all(`
            SELECT c.id, c.linkId, c.timestamp, c.ipAddress, c.userAgent, c.country,
                   c.referrer, c.isUnique, c.destinationUrl,
                   l.destinationUrlDesktop, l.tags
            FROM clicks c
            JOIN links l ON c.linkId = l.id
            WHERE l.ownerId = ? AND c.isBot = 0
            ORDER BY c.timestamp DESC
            LIMIT ?
        `, [ownerId, safeLimit]);
        return rows.map(r => ({ ...r, isUnique: r.isUnique === 1 }));
    },

    /**
     * Top threats summary — most-frequent bot UAs, countries, and signals over a period.
     * Used by the dashboard "threats" panel.
     */
    async getTopThreats(ownerId, days = 7) {
        const db = await getDb();
        const safeDays = Math.max(1, Math.min(parseInt(days, 10) || 7, 90));

        const topUserAgents = await db.all(`
            SELECT
                substr(c.userAgent, 1, 80) AS userAgent,
                COUNT(*) AS hits
            FROM clicks c
            JOIN links l ON c.linkId = l.id
            WHERE l.ownerId = ? AND c.isBot = 1
              AND c.timestamp >= datetime('now', '-' || ? || ' days')
              AND c.userAgent IS NOT NULL AND c.userAgent != ''
            GROUP BY substr(c.userAgent, 1, 80)
            ORDER BY hits DESC
            LIMIT 10
        `, [ownerId, safeDays]);

        const topCountries = await db.all(`
            SELECT c.country, COUNT(*) AS hits
            FROM clicks c
            JOIN links l ON c.linkId = l.id
            WHERE l.ownerId = ? AND c.isBot = 1
              AND c.timestamp >= datetime('now', '-' || ? || ' days')
              AND c.country IS NOT NULL AND c.country != 'Unknown' AND c.country != ''
            GROUP BY c.country
            ORDER BY hits DESC
            LIMIT 10
        `, [ownerId, safeDays]);

        // Aggregate signals from JSON arrays — done in JS since SQLite has no JSON_EACH guarantee here
        const recent = await db.all(`
            SELECT c.botSignals
            FROM clicks c
            JOIN links l ON c.linkId = l.id
            WHERE l.ownerId = ? AND c.isBot = 1 AND c.botSignals IS NOT NULL
              AND c.timestamp >= datetime('now', '-' || ? || ' days')
            LIMIT 5000
        `, [ownerId, safeDays]);
        const signalCounts = {};
        for (const row of recent) {
            try {
                const sigs = JSON.parse(row.botSignals);
                if (Array.isArray(sigs)) {
                    for (const s of sigs) {
                        const k = String(s).slice(0, 80);
                        signalCounts[k] = (signalCounts[k] || 0) + 1;
                    }
                }
            } catch (_) { /* skip malformed */ }
        }
        const topSignals = Object.entries(signalCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15)
            .map(([signal, hits]) => ({ signal, hits }));

        return {
            period: `${safeDays} days`,
            topUserAgents,
            topCountries,
            topSignals
        };
    },

    /**
     * Per-domain health snapshot for the dashboard.
     * Reports total/bot click counts and a green/amber/red status per custom-domain.
     * Status thresholds: <30% bots = green, 30–60% = amber, >60% = red.
     */
    async getDomainHealth(ownerId, days = 1) {
        const db = await getDb();
        const safeDays = Math.max(1, Math.min(parseInt(days, 10) || 1, 30));

        // Group clicks by host extracted from googleAdsUrl/destinationUrl on the link.
        // We use the link's googleAdsUrl as the proxy for "domain through which the click came".
        const rows = await db.all(`
            SELECT 
                l.googleAdsUrl AS publicUrl,
                SUM(CASE WHEN c.isBot = 1 THEN 1 ELSE 0 END) AS botClicks,
                SUM(CASE WHEN c.isBot = 0 THEN 1 ELSE 0 END) AS humanClicks,
                COUNT(*) AS totalClicks
            FROM clicks c
            JOIN links l ON c.linkId = l.id
            WHERE l.ownerId = ?
              AND c.timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY l.googleAdsUrl
        `, [ownerId, safeDays]);

        // Aggregate by hostname
        const byDomain = new Map();
        for (const r of rows) {
            let host = 'unknown';
            try { host = new URL(r.publicUrl).hostname; } catch (_) {}
            const cur = byDomain.get(host) || { domain: host, totalClicks: 0, botClicks: 0, humanClicks: 0 };
            cur.totalClicks += r.totalClicks || 0;
            cur.botClicks += r.botClicks || 0;
            cur.humanClicks += r.humanClicks || 0;
            byDomain.set(host, cur);
        }
        const domains = Array.from(byDomain.values()).map(d => {
            const ratio = d.totalClicks > 0 ? d.botClicks / d.totalClicks : 0;
            let status = 'green';
            if (d.totalClicks >= 5) {
                if (ratio > 0.6) status = 'red';
                else if (ratio > 0.3) status = 'amber';
            }
            return {
                ...d,
                botRatio: parseFloat((ratio * 100).toFixed(1)),
                status
            };
        }).sort((a, b) => b.totalClicks - a.totalClicks);

        return { period: `${safeDays} days`, domains };
    },

    /**
     * Update link tags and notes
     */
    async updateLinkMeta(linkId, ownerId, { tags, notes }) {
        const db = await getDb();
        const link = await db.get('SELECT id FROM links WHERE id = ? AND ownerId = ?', [linkId, ownerId]);
        if (!link) return false;

        const updates = [];
        const values = [];

        if (tags !== undefined) {
            updates.push('tags = ?');
            values.push(typeof tags === 'string' ? tags : JSON.stringify(tags));
        }
        if (notes !== undefined) {
            updates.push('notes = ?');
            values.push(notes);
        }

        if (updates.length === 0) return false;

        values.push(linkId);
        await db.run(`UPDATE links SET ${updates.join(', ')} WHERE id = ?`, values);
        return true;
    },

    /**
     * Get dashboard summary statistics for a user (optimized: combined query + caching)
     */
    async getDashboardStats(ownerId) {
        const cacheKey = `stats:dashboard:${ownerId}`;
        const cached = await cache.get(cacheKey);
        if (cached) return cached;

        const db = await getDb();

        // Combined query: totals + unique clicks in a single pass
        const combined = await db.get(`
            SELECT 
                COALESCE(SUM(l.clicks), 0) as totalHuman,
                COALESCE(SUM(l.botClicks), 0) as totalBot,
                COUNT(l.id) as totalLinks,
                (SELECT COUNT(*) FROM clicks 
                 WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?) 
                 AND isBot = 0 AND isUnique = 1) as uniqueClicks
            FROM links l WHERE l.ownerId = ?
        `, [ownerId, ownerId]);

        const topCountries = await db.all(`
            SELECT country, COUNT(*) as count 
            FROM clicks 
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?) 
            AND isBot = 0 AND country IS NOT NULL AND country != 'Unknown'
            GROUP BY country 
            ORDER BY count DESC 
            LIMIT 5
        `, [ownerId]);

        const topReferrers = await db.all(`
            SELECT referrer, COUNT(*) as count 
            FROM clicks 
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?) 
            AND isBot = 0 AND referrer IS NOT NULL AND referrer != 'Direct' AND referrer != ''
            GROUP BY referrer 
            ORDER BY count DESC 
            LIMIT 5
        `, [ownerId]);

        const totalClicks = (combined.totalHuman || 0) + (combined.totalBot || 0);
        const conversionRate = totalClicks > 0 
            ? ((combined.totalHuman / totalClicks) * 100).toFixed(1) 
            : '0.0';

        const result = {
            totalHuman: combined.totalHuman || 0,
            totalBot: combined.totalBot || 0,
            totalLinks: combined.totalLinks || 0,
            uniqueClicks: combined.uniqueClicks || 0,
            conversionRate: parseFloat(conversionRate),
            topCountries,
            topReferrers
        };

        await cache.set(cacheKey, result, { EX: CACHE_TTL.dashboardStats });
        return result;
    },

    /**
     * Export clicks data for a user (JSON format for CSV conversion on client)
     */
    async exportClicks(ownerId, { linkId, days = 30, limit = 10000, offset = 0 } = {}) {
        const db = await getDb();

        // Validate pagination params
        const safeLimit = Math.max(1, Math.min(parseInt(limit, 10) || 10000, 10000));
        const safeOffset = Math.max(0, Math.min(parseInt(offset, 10) || 0, 100000));

        let query = `
            SELECT 
                c.timestamp, c.linkId, c.isBot, c.ipAddress, c.country, 
                c.referrer, c.userAgent, c.destinationUrl, c.isUnique,
                l.googleAdsUrl, l.tags, l.notes
            FROM clicks c
            JOIN links l ON c.linkId = l.id
            WHERE l.ownerId = ?
            AND c.timestamp >= datetime('now', '-' || ? || ' days')
        `;
        const params = [ownerId, days];

        if (linkId) {
            query += ' AND c.linkId = ?';
            params.push(linkId);
        }

        query += ' ORDER BY c.timestamp DESC LIMIT ? OFFSET ?';
        params.push(safeLimit, safeOffset);

        const rows = await db.all(query, params);
        return rows.map(r => ({
            ...r,
            isBot: r.isBot === 1,
            isUnique: r.isUnique === 1
        }));
    },

    /**
     * Search links by tag, destination URL, or notes
     */
    async searchLinks(ownerId, query) {
        const db = await getDb();
        const searchTerm = `%${query}%`;
        return db.all(`
            SELECT * FROM links 
            WHERE ownerId = ?
            AND deletedAt IS NULL
            AND (
                destinationUrlDesktop LIKE ? 
                OR tags LIKE ? 
                OR notes LIKE ? 
                OR id LIKE ?
            )
            ORDER BY createdAt DESC
        `, [ownerId, searchTerm, searchTerm, searchTerm, searchTerm]);
    },

    /**
     * Bulk delete links
     */
    async bulkDeleteLinks(linkIds, ownerId) {
        const db = await getDb();
        if (!linkIds || linkIds.length === 0) return 0;

        const placeholders = linkIds.map(() => '?').join(',');
        // Feature 18: bulk soft-delete (was hard-delete) so deletes can be undone.
        const result = await db.run(
            `UPDATE links SET deletedAt = CURRENT_TIMESTAMP WHERE id IN (${placeholders}) AND ownerId = ? AND deletedAt IS NULL`,
            [...linkIds, ownerId]
        );
        return result.changes;
    },

    /**
     * Get hourly click breakdown for the last N hours
     */
    async getHourlyBreakdown(ownerId, hours = 24) {
        const db = await getDb();
        return db.all(`
            SELECT 
                strftime('%Y-%m-%d %H:00', timestamp) as hour,
                SUM(CASE WHEN isBot = 0 THEN 1 ELSE 0 END) as humanClicks,
                SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END) as botClicks,
                COUNT(*) as totalClicks
            FROM clicks
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?)
            AND timestamp >= datetime('now', '-' || ? || ' hours')
            GROUP BY strftime('%Y-%m-%d %H:00', timestamp)
            ORDER BY hour ASC
        `, [ownerId, hours]);
    },

    /**
     * Get geographic summary: clicks grouped by country with percentages
     */
    async getGeoSummary(ownerId) {
        const cacheKey = `stats:geo:${ownerId}`;
        const cached = await cache.get(cacheKey);
        if (cached) return cached;

        const db = await getDb();

        const total = await db.get(`
            SELECT COUNT(*) as count FROM clicks 
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?) AND isBot = 0
        `, [ownerId]);

        const countries = await db.all(`
            SELECT 
                country, 
                COUNT(*) as count
            FROM clicks
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?)
            AND isBot = 0 AND country IS NOT NULL AND country != 'Unknown'
            GROUP BY country
            ORDER BY count DESC
            LIMIT 20
        `, [ownerId]);

        const totalCount = total?.count || 0;
        const result = countries.map(c => ({
            country: c.country,
            count: c.count,
            percentage: totalCount > 0 ? parseFloat(((c.count / totalCount) * 100).toFixed(1)) : 0
        }));

        await cache.set(cacheKey, result, { EX: CACHE_TTL.geoSummary });
        return result;
    },

    /**
     * Get top performing links for a user
     */
    async getTopLinks(ownerId, limit = 10) {
        const cacheKey = `stats:top:${ownerId}:${limit}`;
        const cached = await cache.get(cacheKey);
        if (cached) return cached;

        const db = await getDb();
        const result = await db.all(`
            SELECT 
                l.id,
                l.destinationUrlDesktop,
                l.clicks as humanClicks,
                l.botClicks,
                (l.clicks + l.botClicks) as totalClicks,
                l.tags,
                l.notes,
                l.createdAt,
                l.expiresAt
            FROM links l
            WHERE l.ownerId = ?
            ORDER BY l.clicks DESC
            LIMIT ?
        `, [ownerId, limit]);

        await cache.set(cacheKey, result, { EX: CACHE_TTL.topLinks });
        return result;
    },

    /**
     * Get click rate over time periods (today, this week, this month)
     */
    async getClickRateSummary(ownerId) {
        const db = await getDb();

        const today = await db.get(`
            SELECT 
                COALESCE(SUM(CASE WHEN isBot = 0 THEN 1 ELSE 0 END), 0) as human,
                COALESCE(SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END), 0) as bot
            FROM clicks 
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?)
            AND timestamp >= date('now', 'start of day')
        `, [ownerId]);

        const thisWeek = await db.get(`
            SELECT 
                COALESCE(SUM(CASE WHEN isBot = 0 THEN 1 ELSE 0 END), 0) as human,
                COALESCE(SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END), 0) as bot
            FROM clicks 
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?)
            AND timestamp >= date('now', '-7 days')
        `, [ownerId]);

        const thisMonth = await db.get(`
            SELECT 
                COALESCE(SUM(CASE WHEN isBot = 0 THEN 1 ELSE 0 END), 0) as human,
                COALESCE(SUM(CASE WHEN isBot = 1 THEN 1 ELSE 0 END), 0) as bot
            FROM clicks 
            WHERE linkId IN (SELECT id FROM links WHERE ownerId = ?)
            AND timestamp >= date('now', 'start of month')
        `, [ownerId]);

        const toSummary = (row) => ({ human: row.human, bot: row.bot, total: row.human + row.bot });

        return {
            today:     toSummary(today),
            thisWeek:  toSummary(thisWeek),
            thisMonth: toSummary(thisMonth)
        };
    },

    /**
     * Creates multiple redirect links in a single batch transaction.
     * Each entry in the destinations array becomes its own tracking link.
     * All links share the same batchId for grouping.
     *
     * @param {object} options
     * @param {number} options.ownerId - Owner user ID
     * @param {string} options.publicDomain - Domain for generated URLs
     * @param {string} options.expiresAt - Expiration datetime
     * @param {Array<{url: string, tags?: string, notes?: string}>} options.destinations - Array of destination URLs
     * @param {number} [options.templateId] - Optional template ID
     * @param {boolean} [options.singleUse] - Optional single-use mode
     * @returns {Promise<{batchId: string, links: Array}>}
     */
    async createBatchLinks({ ownerId, publicDomain, expiresAt, destinations, templateId, singleUse }) {
        const db = await getDb();

        if (!destinations || !Array.isArray(destinations) || destinations.length === 0) {
            throw new Error('At least one destination URL is required.');
        }

        const batchId = uuidv4();
        const createdLinks = [];

        await db.run('BEGIN TRANSACTION');
        try {
            for (const dest of destinations) {
                const url = dest.url;
                if (!url || typeof url !== 'string') {
                    throw new Error('Each destination must have a valid URL.');
                }

                const { googleAdsUrl, internalId } = googleAdsRedirector.createRedirect(url, publicDomain);

                await db.run(
                    `INSERT INTO links (id, ownerId, googleAdsUrl, destinationUrlDesktop, expiresAt, clicks, botClicks, templateId, batchId, tags, notes, singleUse) 
                     VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?)`,
                    [internalId, ownerId, googleAdsUrl, url, expiresAt, templateId || null, batchId, dest.tags || null, dest.notes || null, singleUse ? 1 : 0]
                );

                await db.run(
                    `INSERT INTO link_destinations (linkId, url, platform, weight) 
                     VALUES (?, ?, 'desktop', 100)`,
                    [internalId, url]
                );

                createdLinks.push({
                    id: internalId,
                    ownerId,
                    googleAdsUrl,
                    destinationUrlDesktop: url,
                    expiresAt,
                    clicks: 0,
                    botClicks: 0,
                    templateId: templateId || null,
                    batchId,
                    tags: dest.tags || null,
                    notes: dest.notes || null,
                    singleUse: singleUse ? 1 : 0
                });
            }

            await db.run('COMMIT');
            console.log(chalk.green(`[LINKSTORE] ✓ Batch ${batchId}: Created ${createdLinks.length} links for user ${ownerId}`));

            return { batchId, links: createdLinks };
        } catch (error) {
            await db.run('ROLLBACK');
            console.error(chalk.red(`[LINKSTORE] ✗ Batch creation failed: ${error.message}`));
            throw error;
        }
    },

    /**
     * Retrieves all links belonging to a specific batch.
     * @param {string} batchId - The batch UUID
     * @param {number} ownerId - Owner user ID (for authorization)
     * @returns {Promise<Array>}
     */
    async getLinksByBatch(batchId, ownerId) {
        const db = await getDb();
        return db.all(
            'SELECT * FROM links WHERE batchId = ? AND ownerId = ? ORDER BY createdAt ASC',
            [batchId, ownerId]
        );
    },

    /**
     * Lists all batch IDs for a user with summary info.
     * @param {number} ownerId - Owner user ID
     * @returns {Promise<Array>}
     */
    async listBatches(ownerId) {
        const db = await getDb();
        return db.all(`
            SELECT 
                batchId,
                COUNT(*) as linkCount,
                SUM(clicks) as totalClicks,
                SUM(botClicks) as totalBotClicks,
                MIN(createdAt) as createdAt,
                MIN(expiresAt) as expiresAt
            FROM links 
            WHERE ownerId = ? AND batchId IS NOT NULL
            GROUP BY batchId
            ORDER BY MIN(createdAt) DESC
        `, [ownerId]);
    }
};

module.exports = linkStore;
