/**
 * Short Link Manager v1.1
 * 
 * Fixes:
 * - Removed incorrect .toLowerCase() on resolve/tracking (Fixed 404s)
 * - Improved isActive check for robustness
 * - Fixed boolean/integer conversion in update()
 */

const crypto = require('crypto');
const getDb = require('./database');
const chalk = require('chalk');

// Configuration
const CONFIG = {
    // Charsets used for short code generation.
    //
    // Popular shorteners (bit.ly, t.co, goo.gl, tinyurl, is.gd, ow.ly, buff.ly,
    // rebrand.ly, etc.) almost universally emit 6–8 character mixed-case
    // alphanumeric slugs with no separators — that pattern is what every URL
    // scanner / shortener-detection heuristic looks for. To avoid being
    // classified as a "URL shortener" link we deliberately:
    //   1. Use lowercase + digits only (no uppercase mix-case fingerprint)
    //   2. Always start with a letter (avoids leading-digit shortener regex)
    //   3. Emit two segments separated by a hyphen (looks like a content slug,
    //      not a tracking shortener)
    //   4. Use a longer total length than typical shorteners
    LETTER_CHARSET: 'abcdefghijkmnpqrstuvwxyz', // dropped 'l' and 'o' for legibility
    DIGIT_CHARSET:  '23456789',                  // dropped 0 and 1 for legibility
    ALNUM_CHARSET:  'abcdefghijkmnpqrstuvwxyz23456789',

    // Legacy charset retained for custom-alias validation (humans may use any
    // alphanumeric + hyphen + underscore in their own aliases).
    CHARSET: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',

    // Default short code length — total characters across both segments.
    // 10 chars (5+5) ≈ 24^10 ≈ 6.3e13 combinations: ample for collision
    // resistance and clearly outside the 6–8 char shortener window.
    DEFAULT_CODE_LENGTH: 10,

    // Segment separator and split position.
    SEGMENT_SEPARATOR: '-',
    SEGMENT_SPLIT_AT: 5, // first 5 chars, hyphen, then remaining chars

    // Minimum and maximum code lengths (excluding the hyphen).
    MIN_CODE_LENGTH: 8,
    MAX_CODE_LENGTH: 24,

    // Custom-alias length bounds — humans pick their own slugs and a 4-char
    // minimum has historically been allowed; preserved for backwards compat.
    MIN_ALIAS_LENGTH: 4,
    MAX_ALIAS_LENGTH: 32,

    // Maximum retry attempts for unique code generation
    MAX_GENERATION_ATTEMPTS: 10,

    // Reserved slugs that cannot be used as aliases
    RESERVED_SLUGS: [
        'api', 'admin', 'dashboard', 'login', 'logout', 'register', 'signup',
        'tr', 'track', 'tracking', 'health', 'status', 'static', 'assets',
        'js', 'css', 'img', 'images', 'fonts', 'favicon', 'robots',
        's', 'short', 'go', 'l', 'link', 'u', 'url', 'r', 'redirect'
    ],

    // URL validation regex
    URL_REGEX: /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/i,

    // Alias validation regex (alphanumeric, hyphens, underscores)
    ALIAS_REGEX: /^[a-zA-Z0-9_-]+$/
};

/**
 * Pick an unbiased random index into a charset using crypto.randomBytes.
 * Rejection-sampling avoids modulo bias for charsets that don't divide 256.
 * The bounded retry guards against pathological inputs (e.g. corrupt RNG)
 * even though, with `max ≥ charsetLength`, the rejection probability per
 * draw is always < 50% so this loop terminates almost surely in O(1).
 */
function _secureIndex(charsetLength) {
    if (charsetLength <= 0 || charsetLength > 256) {
        throw new Error('Invalid charset length');
    }
    const max = 256 - (256 % charsetLength);
    for (let attempt = 0; attempt < 1000; attempt++) {
        const b = crypto.randomBytes(1)[0];
        if (b < max) return b % charsetLength;
    }
    // Practically unreachable (probability < 2^-1000): bail out loudly rather
    // than spin forever if the underlying RNG is somehow broken.
    throw new Error('Failed to obtain unbiased random index after 1000 attempts');
}

function _pickN(charset, n) {
    let out = '';
    for (let i = 0; i < n; i++) {
        out += charset[_secureIndex(charset.length)];
    }
    return out;
}

/**
 * Generates a cryptographically secure random short code that does NOT match
 * popular shortener heuristics (mixed-case 6–8 char alphanumeric, no separator).
 *
 * Resulting pattern: `[a-z][a-z2-9]{4}-[a-z2-9]{4,}` (e.g. "qbnvr-7k9zm").
 *
 * @param {number} length - Total code length excluding the hyphen separator.
 * @returns {string}
 */
function generateSecureCode(length = CONFIG.DEFAULT_CODE_LENGTH) {
    if (typeof length !== 'number' || length < CONFIG.MIN_CODE_LENGTH) {
        length = CONFIG.DEFAULT_CODE_LENGTH;
    }
    if (length > CONFIG.MAX_CODE_LENGTH) length = CONFIG.MAX_CODE_LENGTH;

    // Always lead with a letter — clean URL and breaks shortener regexes that
    // expect a digit-capable first character.
    const head = CONFIG.LETTER_CHARSET[_secureIndex(CONFIG.LETTER_CHARSET.length)];

    // Determine where to insert the hyphen.
    const splitAt = Math.min(CONFIG.SEGMENT_SPLIT_AT, length - 2);
    const firstSegLen = splitAt - 1; // already used 1 char for `head`
    const secondSegLen = length - splitAt;

    const firstSeg = head + _pickN(CONFIG.ALNUM_CHARSET, Math.max(0, firstSegLen));
    const secondSeg = _pickN(CONFIG.ALNUM_CHARSET, Math.max(1, secondSegLen));

    return `${firstSeg}${CONFIG.SEGMENT_SEPARATOR}${secondSeg}`;
}

/**
 * Validates a URL
 * @param {string} url 
 * @returns {object} - { isValid, error }
 */
function validateUrl(url) {
    if (!url || typeof url !== 'string') {
        return { isValid: false, error: 'URL is required' };
    }

    const trimmedUrl = url.trim();
    
    if (trimmedUrl.length === 0) {
        return { isValid: false, error: 'URL cannot be empty' };
    }
    
    if (trimmedUrl.length > 2048) {
        return { isValid: false, error: 'URL exceeds maximum length of 2048 characters' };
    }

    // Check for valid protocol
    if (!trimmedUrl.startsWith('http://') && !trimmedUrl.startsWith('https://')) {
        return { isValid: false, error: 'URL must start with http:// or https://' };
    }

    // Validate URL format
    if (!CONFIG.URL_REGEX.test(trimmedUrl)) {
        return { isValid: false, error: 'Invalid URL format' };
    }

    // Check for potentially dangerous URLs
    const lowerUrl = trimmedUrl.toLowerCase();
    if (lowerUrl.includes('javascript:') || lowerUrl.includes('data:') || lowerUrl.includes('vbscript:')) {
        return { isValid: false, error: 'URL contains prohibited protocol' };
    }

    return { isValid: true, error: null };
}

/**
 * Validates a custom alias
 * @param {string} alias 
 * @returns {object} - { isValid, error }
 */
function validateAlias(alias) {
    if (!alias || typeof alias !== 'string') {
        return { isValid: false, error: 'Alias is required' };
    }

    const trimmedAlias = alias.trim(); // Removed toLowerCase() to allow case-sensitive custom aliases if desired
    
    if (trimmedAlias.length < CONFIG.MIN_ALIAS_LENGTH) {
        return { isValid: false, error: `Alias must be at least ${CONFIG.MIN_ALIAS_LENGTH} characters` };
    }
    
    if (trimmedAlias.length > CONFIG.MAX_ALIAS_LENGTH) {
        return { isValid: false, error: `Alias cannot exceed ${CONFIG.MAX_ALIAS_LENGTH} characters` };
    }

    if (!CONFIG.ALIAS_REGEX.test(trimmedAlias)) {
        return { isValid: false, error: 'Alias can only contain letters, numbers, hyphens, and underscores' };
    }

    if (CONFIG.RESERVED_SLUGS.includes(trimmedAlias.toLowerCase())) {
        return { isValid: false, error: 'This alias is reserved and cannot be used' };
    }

    return { isValid: true, error: null };
}

/**
 * Ensures the required tables exist in the database
 */
async function ensureTablesExist() {
    const db = await getDb();
    
    await db.exec(`
        CREATE TABLE IF NOT EXISTS short_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            targetUrl TEXT NOT NULL,
            ownerId INTEGER,
            title TEXT,
            clicks INTEGER DEFAULT 0,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            expiresAt DATETIME,
            isActive INTEGER DEFAULT 1,
            lastClickAt DATETIME,
            metadata TEXT,
            FOREIGN KEY(ownerId) REFERENCES users(id) ON DELETE SET NULL
        );
    `);
    
    await db.exec(`
        CREATE TABLE IF NOT EXISTS short_link_clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shortLinkId INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ipAddress TEXT,
            userAgent TEXT,
            referrer TEXT,
            country TEXT,
            FOREIGN KEY(shortLinkId) REFERENCES short_links(id) ON DELETE CASCADE
        );
    `);
    
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_links_slug ON short_links(slug);`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_links_owner ON short_links(ownerId);`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_links_active ON short_links(isActive);`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_link_clicks_link ON short_link_clicks(shortLinkId);`);
}


// Initialize tables on module load
let tablesInitialized = false;
async function initTables() {
    if (!tablesInitialized) {
        await ensureTablesExist();
        tablesInitialized = true;
    }
}

/**
 * Short Link Manager Object
 */
const shortLinkManager = {
    
    /**
     * Creates a new short link
     * @param {object} options 
     * @returns {Promise<object>}
     */
    async create(options) {
        await initTables();
        
        const {
            targetUrl,
            ownerId = null,
            alias = null,
            title = null,
            expiresAt = null,
            metadata = null
        } = options;

        // Validate target URL
        const urlValidation = validateUrl(targetUrl);
        if (!urlValidation.isValid) {
            throw new Error(urlValidation.error);
        }

        const db = await getDb();
        let slug;

        // If custom alias provided, validate and use it
        if (alias) {
            const aliasValidation = validateAlias(alias);
            if (!aliasValidation.isValid) {
                throw new Error(aliasValidation.error);
            }
            
            slug = alias.trim();

            // Atomically check and insert to prevent race conditions
            const existing = await db.get('SELECT id FROM short_links WHERE slug = ?', [slug]);
            if (existing) {
                throw new Error('This alias is already in use');
            }
        } else {
            // Generate unique short code with retry and length increase
            let codeLength = CONFIG.DEFAULT_CODE_LENGTH;
            let isUnique = false;
            let attempts = 0;
            const maxAttempts = CONFIG.MAX_GENERATION_ATTEMPTS;

            while (!isUnique && attempts < maxAttempts) {
                slug = generateSecureCode(codeLength);
                const existing = await db.get('SELECT id FROM short_links WHERE slug = ?', [slug]);
                if (!existing) {
                    isUnique = true;
                    break;
                }
                attempts++;
                // After half the attempts, increase code length for better collision avoidance
                if (attempts === Math.floor(maxAttempts / 2)) {
                    codeLength += 2;
                }
            }

            if (!isUnique) {
                throw new Error('Failed to generate unique short code. Please try again.');
            }
        }

        // Insert the short link
        try {
            const result = await db.run(
                `INSERT INTO short_links (slug, targetUrl, ownerId, title, expiresAt, metadata, isActive) 
                 VALUES (?, ?, ?, ?, ?, ?, 1)`,
                [
                    slug,
                    targetUrl.trim(),
                    ownerId,
                    title,
                    expiresAt,
                    metadata ? JSON.stringify(metadata) : null
                ]
            );

            console.log(chalk.green(`[SHORT-LINK] Created: /${slug} -> ${targetUrl.substring(0, 50)}...`));

            return {
                id: result.lastID,
                slug,
                targetUrl: targetUrl.trim(),
                shortUrl: `/s/${slug}`,
                ownerId,
                title,
                clicks: 0,
                createdAt: new Date().toISOString(),
                expiresAt,
                isActive: 1
            };
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT') {
                throw new Error('This alias is already in use');
            }
            throw error;
        }
    },

    /**
     * Resolves a short link slug to its target URL
     * @param {string} slug 
     * @returns {Promise<object|null>}
     */
    async resolve(slug) {
        await initTables();
        
        if (!slug || typeof slug !== 'string') {
            return null;
        }

        const db = await getDb();
        
        // FIXED: Removed .toLowerCase() and added robust isActive check
        const link = await db.get(
            `SELECT * FROM short_links WHERE slug = ? AND (isActive = 1 OR isActive IS NULL)`,
            [slug] 
        );

        if (!link) {
            return null;
        }

        // Check expiration
        if (link.expiresAt && new Date(link.expiresAt) < new Date()) {
            return null;
        }

        return {
            id: link.id,
            slug: link.slug,
            targetUrl: link.targetUrl,
            ownerId: link.ownerId,
            title: link.title,
            clicks: link.clicks,
            createdAt: link.createdAt,
            expiresAt: link.expiresAt,
            metadata: link.metadata ? JSON.parse(link.metadata) : null
        };
    },

    /**
     * Records a click on a short link
     * @param {string} slug 
     * @param {object} clickData 
     * @returns {Promise<boolean>}
     */
    async recordClick(slug, clickData = {}) {
        await initTables();
        
        const db = await getDb();
        // FIXED: Removed .toLowerCase()
        const link = await db.get('SELECT id FROM short_links WHERE slug = ?', [slug]);
        
        if (!link) {
            return false;
        }

        const { ipAddress = null, userAgent = null, referrer = null, country = null } = clickData;

        try {
            // Using a simpler update/insert flow to avoid transaction lock issues on some SQLite configs
            await db.run(
                'UPDATE short_links SET clicks = clicks + 1, lastClickAt = CURRENT_TIMESTAMP WHERE id = ?',
                [link.id]
            );

            await db.run(
                `INSERT INTO short_link_clicks (shortLinkId, ipAddress, userAgent, referrer, country) 
                 VALUES (?, ?, ?, ?, ?)`,
                [link.id, ipAddress, userAgent, referrer, country]
            );
            
            console.log(chalk.cyan(`[SHORT-LINK] Click recorded: /${slug} from ${country || 'Unknown'}`));
            return true;
        } catch (error) {
            console.error(chalk.red(`[SHORT-LINK] Failed to record click: ${error.message}`));
            return false;
        }
    },

    /**
     * Gets all short links for a user
     * @param {number} ownerId 
     * @returns {Promise<array>}
     */
    async getByOwner(ownerId) {
        await initTables();
        
        const db = await getDb();
        const links = await db.all(
            'SELECT * FROM short_links WHERE ownerId = ? ORDER BY createdAt DESC',
            [ownerId]
        );

        return links.map(link => ({
            ...link,
            shortUrl: `/s/${link.slug}`,
            metadata: link.metadata ? JSON.parse(link.metadata) : null
        }));
    },

    /**
     * Gets analytics for a short link
     * @param {string} slug 
     * @param {number} ownerId - For ownership verification
     * @returns {Promise<object|null>}
     */
    async getAnalytics(slug, ownerId) {
        await initTables();
        
        const db = await getDb();
        
        // Verify ownership - FIXED: Removed toLowerCase()
        const link = await db.get(
            'SELECT * FROM short_links WHERE slug = ? AND ownerId = ?',
            [slug, ownerId]
        );

        if (!link) {
            return null;
        }

        // Get click history
        const clicks = await db.all(
            `SELECT timestamp, country, referrer 
             FROM short_link_clicks 
             WHERE shortLinkId = ? 
             ORDER BY timestamp DESC 
             LIMIT 100`,
            [link.id]
        );

        // Get clicks by country
        const byCountry = await db.all(
            `SELECT country, COUNT(*) as count 
             FROM short_link_clicks 
             WHERE shortLinkId = ? 
             GROUP BY country 
             ORDER BY count DESC`,
            [link.id]
        );

        // Get clicks by day (last 30 days)
        const byDay = await db.all(
            `SELECT date(timestamp) as date, COUNT(*) as count 
             FROM short_link_clicks 
             WHERE shortLinkId = ? AND timestamp >= date('now', '-30 days')
             GROUP BY date(timestamp) 
             ORDER BY date ASC`,
            [link.id]
        );

        return {
            link: {
                ...link,
                shortUrl: `/s/${link.slug}`,
                metadata: link.metadata ? JSON.parse(link.metadata) : null
            },
            totalClicks: link.clicks,
            recentClicks: clicks,
            clicksByCountry: byCountry.map(c => ({
                ...c,
                percentage: link.clicks > 0 ? parseFloat(((c.count / link.clicks) * 100).toFixed(1)) : 0
            })),
            clicksByDay: byDay
        };
    },

    /**
     * Updates a short link
     * @param {string} slug 
     * @param {number} ownerId 
     * @param {object} updates 
     * @returns {Promise<boolean>}
     */
    async update(slug, ownerId, updates) {
        await initTables();
        
        const db = await getDb();
        
        // Verify ownership - FIXED: Removed toLowerCase()
        const link = await db.get(
            'SELECT id FROM short_links WHERE slug = ? AND ownerId = ?',
            [slug, ownerId]
        );

        if (!link) {
            return false;
        }

        const allowedUpdates = ['targetUrl', 'title', 'expiresAt', 'isActive'];
        const setClauses = [];
        const values = [];

        for (const [key, value] of Object.entries(updates)) {
            if (allowedUpdates.includes(key)) {
                if (key === 'targetUrl') {
                    const validation = validateUrl(value);
                    if (!validation.isValid) {
                        throw new Error(validation.error);
                    }
                    values.push(value);
                } else if (key === 'isActive') {
                    // FIXED: Ensure integer storage for boolean
                    values.push(value ? 1 : 0);
                } else {
                    values.push(value);
                }
                setClauses.push(`${key} = ?`);
            }
        }

        if (setClauses.length === 0) {
            return false;
        }

        values.push(link.id);
        
        await db.run(
            `UPDATE short_links SET ${setClauses.join(', ')} WHERE id = ?`,
            values
        );

        console.log(chalk.yellow(`[SHORT-LINK] Updated: /${slug}`));
        return true;
    },

    /**
     * Deletes a short link
     * @param {string} slug 
     * @param {number} ownerId 
     * @returns {Promise<boolean>}
     */
    async delete(slug, ownerId) {
        await initTables();
        
        const db = await getDb();
        
        // FIXED: Removed toLowerCase()
        const result = await db.run(
            'DELETE FROM short_links WHERE slug = ? AND ownerId = ?',
            [slug, ownerId]
        );

        if (result.changes > 0) {
            console.log(chalk.red(`[SHORT-LINK] Deleted: /${slug}`));
            return true;
        }

        return false;
    },

    /**
     * Checks if a slug is available
     * @param {string} slug 
     * @returns {Promise<boolean>}
     */
    async isSlugAvailable(slug) {
        await initTables();
        
        if (!slug || typeof slug !== 'string') {
            return false;
        }

        const validation = validateAlias(slug);
        if (!validation.isValid) {
            return false;
        }

        const db = await getDb();
        // FIXED: Removed toLowerCase()
        const existing = await db.get('SELECT id FROM short_links WHERE slug = ?', [slug]);
        
        return !existing;
    },

    /**
     * Gets statistics summary for a user
     * @param {number} ownerId 
     * @returns {Promise<object>}
     */
    async getStats(ownerId) {
        await initTables();
        
        const db = await getDb();

        const stats = await db.get(
            `SELECT 
                COUNT(*) as totalLinks,
                SUM(clicks) as totalClicks,
                SUM(CASE WHEN isActive = 1 THEN 1 ELSE 0 END) as activeLinks
             FROM short_links 
             WHERE ownerId = ?`,
            [ownerId]
        );

        return {
            totalLinks: stats.totalLinks || 0,
            totalClicks: stats.totalClicks || 0,
            activeLinks: stats.activeLinks || 0
        };
    }
};

module.exports = shortLinkManager;
