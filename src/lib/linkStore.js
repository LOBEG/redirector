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
    async createLinkWithRotations({ ownerId, publicDomain, expiresAt, rotations, templateId }) {
        const db = await getDb();
        
        const firstUrl = rotations[0]?.url;
        if (!firstUrl) throw new Error("Invalid rotation data: At least one destination URL is required.");
        
        const { googleAdsUrl, internalId } = googleAdsRedirector.createRedirect(firstUrl, publicDomain);

        await db.run('BEGIN TRANSACTION');
        try {
            // MODIFIED: Added templateId to the INSERT statement
            await db.run(
                `INSERT INTO links (id, ownerId, googleAdsUrl, destinationUrlDesktop, expiresAt, clicks, botClicks, templateId) 
                 VALUES (?, ?, ?, ?, ?, 0, 0, ?)`,
                [internalId, ownerId, googleAdsUrl, firstUrl, expiresAt, templateId]
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
                templateId
            };
        } catch (error) {
            await db.run('ROLLBACK');
            console.error(chalk.red(`[LINKSTORE] Failed to create link: ${error.message}`));
            throw error;
        }
    },

    async getLinksForUser(ownerId) {
        const db = await getDb();
        return db.all('SELECT * FROM links WHERE ownerId = ? ORDER BY createdAt DESC', ownerId);
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

        await db.run('BEGIN TRANSACTION');
        try {
            await db.run('DELETE FROM link_destinations WHERE linkId = ?', id);
            await db.run('DELETE FROM clicks WHERE linkId = ?', id);
            await db.run('DELETE FROM links WHERE id = ?', id);
            await db.run('COMMIT');
            return true;
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
    },
    
    async logClick({ linkId, isBot, ipAddress, userAgent, country, referrer, destinationUrl }) {
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

            await db.run(
                `INSERT INTO clicks (linkId, isBot, ipAddress, userAgent, country, referrer, destinationUrl, timestamp, isUnique) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)`,
                [linkId, isBotInt, ipAddress, userAgent, country, referrer, destinationUrl, isUnique]
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
        
        return clicks.map(c => ({ ...c, isBot: c.isBot === 1, isUnique: c.isUnique === 1 }));
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
        
        await db.run('BEGIN');
        try {
            await db.run(
                `DELETE FROM link_destinations WHERE linkId IN (${placeholders})`,
                linkIds
            );
            await db.run(
                `DELETE FROM clicks WHERE linkId IN (${placeholders})`,
                linkIds
            );
            const result = await db.run(
                `DELETE FROM links WHERE id IN (${placeholders}) AND ownerId = ?`,
                [...linkIds, ownerId]
            );
            await db.run('COMMIT');
            return result.changes;
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
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
     * @returns {Promise<{batchId: string, links: Array}>}
     */
    async createBatchLinks({ ownerId, publicDomain, expiresAt, destinations, templateId }) {
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
                    `INSERT INTO links (id, ownerId, googleAdsUrl, destinationUrlDesktop, expiresAt, clicks, botClicks, templateId, batchId, tags, notes) 
                     VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)`,
                    [internalId, ownerId, googleAdsUrl, url, expiresAt, templateId || null, batchId, dest.tags || null, dest.notes || null]
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
                    notes: dest.notes || null
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
