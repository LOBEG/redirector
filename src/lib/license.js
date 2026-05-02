const config = require('../config');
const chalk = require('chalk');
const getDb = require('./database');

// In-memory usage cache with per-key timestamps for accurate reset tracking
const usage = new Map();
const MAX_USAGE_ENTRIES = 10000; // Prevent unbounded Map growth

/**
 * Resets usage for keys whose individual reset window has elapsed.
 * Runs periodically but only clears keys that have exceeded their window.
 */
setInterval(() => {
    const now = Date.now();
    const resetInterval = config.license.resetInterval || 3600000;
    for (const [key, data] of usage) {
        if (now - data.windowStart >= resetInterval) {
            usage.delete(key);
        }
    }
}, 60 * 1000); // Check every minute

/**
 * Checks if a license key is valid and if the user has not exceeded their usage limit.
 * Keys are loaded from the database (users table) and fall back to static config.
 * @param {string} key - The license key provided by the user.
 * @returns {Promise<{ok: boolean, error?: string, plan?: string, remaining?: number}>}
 */
exports.check = async (key) => {
    if (!key || typeof key !== 'string') {
        return { ok: false, error: 'License key is required' };
    }

    // Sanitize key — strip whitespace, limit length
    const sanitizedKey = key.trim();
    if (sanitizedKey.length === 0 || sanitizedKey.length > 256) {
        return { ok: false, error: 'Invalid license key format' };
    }

    // Look up the key in the database first (users table accessKey)
    let plan = null;
    let planName = null;
    try {
        const db = await getDb();
        const user = await db.get(
            'SELECT id, role FROM users WHERE accessKey = ? AND isActive = 1',
            [sanitizedKey]
        );
        if (user) {
            // Map user roles to license plans
            const rolePlanMap = { admin: 'enterprise', user: 'pro' };
            planName = rolePlanMap[user.role] || 'free';
            plan = config.license.plans[planName];
        }
    } catch (err) {
        console.error(chalk.red('[LICENSE] Database lookup error:'), err.message);
        // Graceful degradation: deny if DB is unreachable rather than crash
        return { ok: false, error: 'License validation temporarily unavailable' };
    }

    if (!plan) {
        return { ok: false, error: 'Invalid license key' };
    }

    // Initialize per-key usage tracking with individual window start
    const now = Date.now();
    const resetInterval = config.license.resetInterval || 3600000;

    // Evict oldest entry if at capacity (prevent memory leak)
    if (!usage.has(sanitizedKey) && usage.size >= MAX_USAGE_ENTRIES) {
        const oldestKey = usage.keys().next().value;
        usage.delete(oldestKey);
    }

    if (!usage.has(sanitizedKey)) {
        usage.set(sanitizedKey, { count: 0, windowStart: now });
    }

    const keyUsage = usage.get(sanitizedKey);

    // Reset if this key's individual window has elapsed
    if (now - keyUsage.windowStart >= resetInterval) {
        keyUsage.count = 0;
        keyUsage.windowStart = now;
    }

    // Check if the user has exceeded their limit
    if (keyUsage.count >= plan.limit) {
        return { ok: false, error: `Usage limit of ${plan.limit} for ${plan.name} plan exceeded.` };
    }

    // Increment usage count
    keyUsage.count++;

    return {
        ok: true,
        plan: planName,
        remaining: plan.limit === Infinity ? Infinity : (plan.limit - keyUsage.count)
    };
};
