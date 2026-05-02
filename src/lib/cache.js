const redis = require('redis');
const chalk = require('chalk');

let cache;
const useRedis = !!process.env.REDIS_URL;

if (useRedis) {
    // --- REDIS-BASED CACHE WITH RECONNECT STRATEGY ---
    const client = redis.createClient({
        url: process.env.REDIS_URL,
        socket: {
            reconnectStrategy: (retries) => {
                if (retries > 10) {
                    console.error(chalk.red('[CACHE] Redis: max reconnect attempts reached, giving up'));
                    return new Error('Max reconnect attempts reached');
                }
                const delay = Math.min(retries * 200, 5000); // Cap at 5s
                console.warn(chalk.yellow(`[CACHE] Redis: reconnecting in ${delay}ms (attempt ${retries})`));
                return delay;
            }
        }
    });

    client.on('error', (err) => console.error(chalk.red('[CACHE] Redis Client Error:'), err.message));
    client.on('connect', () => console.log(chalk.green('[CACHE] Connected to Redis server.')));
    client.on('reconnecting', () => console.warn(chalk.yellow('[CACHE] Redis: reconnecting...')));

    client.connect().catch(err => {
        console.error(chalk.red('[CACHE] Redis initial connection failed:'), err.message);
    });

    cache = {
        async get(key) {
            try {
                const value = await client.get(key);
                return value ? JSON.parse(value) : null;
            } catch (err) {
                console.error(chalk.red('[CACHE] Redis GET error:'), err.message);
                return null;
            }
        },
        async set(key, value, options = {}) {
            try {
                const defaultOptions = { EX: 3600, ...options }; // 1-hour default expiration
                await client.set(key, JSON.stringify(value), defaultOptions);
            } catch (err) {
                console.error(chalk.red('[CACHE] Redis SET error:'), err.message);
            }
        },
        async del(key) {
            try {
                await client.del(key);
            } catch (err) {
                console.error(chalk.red('[CACHE] Redis DEL error:'), err.message);
            }
        },
        async quit() {
            if (client.isOpen) {
                await client.quit();
            }
        },
        stats() {
            return { type: 'redis', connected: client.isOpen };
        }
    };
    console.log(chalk.yellow('[CACHE] Strategy: Redis.'));

} else {
    // --- IN-MEMORY FALLBACK CACHE WITH TTL AND SIZE LIMIT ---
    const memoryCache = new Map();
    const MAX_CACHE_SIZE = 10000; // Maximum number of entries
    let hits = 0;
    let misses = 0;

    // Periodic cleanup of expired entries (every 60 seconds)
    setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of memoryCache) {
            if (entry.expiresAt && now > entry.expiresAt) {
                memoryCache.delete(key);
            }
        }
    }, 60 * 1000);

    cache = {
        async get(key) {
            const entry = memoryCache.get(key);
            if (!entry) {
                misses++;
                return null;
            }
            if (entry.expiresAt && Date.now() > entry.expiresAt) {
                memoryCache.delete(key);
                misses++;
                return null;
            }
            hits++;
            return entry.value;
        },
        async set(key, value, options = {}) {
            // Evict oldest entries if cache exceeds size limit
            if (memoryCache.size >= MAX_CACHE_SIZE && !memoryCache.has(key)) {
                const firstKey = memoryCache.keys().next().value;
                memoryCache.delete(firstKey);
            }
            const ttlSeconds = options.EX || 3600; // Default 1-hour TTL
            memoryCache.set(key, {
                value,
                expiresAt: Date.now() + (ttlSeconds * 1000)
            });
        },
        async del(key) {
            memoryCache.delete(key);
        },
        async quit() {
            memoryCache.clear();
        },
        get size() {
            return memoryCache.size;
        },
        stats() {
            return {
                type: 'memory',
                size: memoryCache.size,
                maxSize: MAX_CACHE_SIZE,
                hits,
                misses,
                hitRate: (hits + misses) > 0 ? ((hits / (hits + misses)) * 100).toFixed(1) + '%' : '0%'
            };
        }
    };
    console.log(chalk.yellow(`[CACHE] Strategy: In-memory (max ${MAX_CACHE_SIZE} entries). No REDIS_URL found.`));
}

module.exports = cache;
