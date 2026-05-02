const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const path = require('path');
const chalk = require('chalk');

let dbPromise = null;

async function initializeDatabase() {
    try {
        // Railway.app persistent volume path vs Local development path
        const mountPath = process.env.RAILWAY_VOLUME_MOUNT_PATH;
        const dbPath = mountPath 
            ? path.join(mountPath, 'production.db')
            : path.join(__dirname, '../../production.db'); // Stored in project root for local dev

        console.log(chalk.blue.bold(`[DATABASE] Connecting to: ${dbPath}`));
        
        const db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });

        console.log(chalk.green('[DATABASE] Connection successful. Checking schema... '));
        
        // Performance optimizations
        await db.exec(`PRAGMA journal_mode = WAL;`);
        await db.exec(`PRAGMA foreign_keys = ON;`);
        
        // 1. Users Table (Access Key based auth)
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                accessKey TEXT UNIQUE,
                keyExpiresAt DATETIME,
                isActive INTEGER DEFAULT 1,
                role TEXT DEFAULT 'user' NOT NULL,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 2. Links Table
        // Updated Foreign Key reference to use link_templates
        await db.exec(`
            CREATE TABLE IF NOT EXISTS links (
                id TEXT PRIMARY KEY,
                ownerId INTEGER NOT NULL,
                googleAdsUrl TEXT NOT NULL,
                destinationUrlDesktop TEXT,
                templateId INTEGER,
                clicks INTEGER DEFAULT 0,
                botClicks INTEGER DEFAULT 0,
                isActive INTEGER DEFAULT 1,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                expiresAt DATETIME NOT NULL,
                FOREIGN KEY(ownerId) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(templateId) REFERENCES link_templates(id) ON DELETE SET NULL
            );
        `);
        
        // 3. Link Destinations
        await db.exec(`
            CREATE TABLE IF NOT EXISTS link_destinations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                linkId TEXT NOT NULL,
                url TEXT NOT NULL,
                weight INTEGER DEFAULT 100 NOT NULL,
                platform TEXT DEFAULT 'desktop' NOT NULL,
                FOREIGN KEY(linkId) REFERENCES links(id) ON DELETE CASCADE
            );
        `);

        // 4. Clicks Table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                linkId TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                isBot INTEGER DEFAULT 0,
                ipAddress TEXT,
                userAgent TEXT,
                country TEXT,
                referrer TEXT,
                destinationUrl TEXT,
                isUnique INTEGER DEFAULT 0,
                FOREIGN KEY(linkId) REFERENCES links(id) ON DELETE CASCADE
            );
        `);

        // 5. Custom Domains
        await db.exec(`
            CREATE TABLE IF NOT EXISTS custom_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ownerId INTEGER NOT NULL,
                hostname TEXT UNIQUE NOT NULL,
                purpose TEXT DEFAULT 'link' NOT NULL,
                templateId INTEGER DEFAULT NULL,
                dnsVerified INTEGER DEFAULT 0,
                sslStatus TEXT DEFAULT 'pending',
                railwayDomainId TEXT DEFAULT NULL,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(ownerId) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(templateId) REFERENCES link_templates(id) ON DELETE SET NULL
            );
        `);

        // 6. Short Links Table
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

        // 7. Short Link Clicks Table
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

        // 8. Link Templates Table (Renamed from html_templates to match server code)
        await db.exec(`
            CREATE TABLE IF NOT EXISTS link_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ownerId INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                htmlContent TEXT NOT NULL,
                isDefault INTEGER DEFAULT 0,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(ownerId) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(ownerId, name)
            );
        `);

        // --- SCHEMA MIGRATIONS WITH VERSION TRACKING ---
        // Store migration version to avoid re-running checks on every startup
        await db.exec(`
            CREATE TABLE IF NOT EXISTS _migration_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL DEFAULT 0,
                lastRunAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        `);
        const migMeta = await db.get('SELECT version FROM _migration_meta WHERE id = 1');
        const currentVersion = migMeta ? migMeta.version : 0;
        const TARGET_VERSION = 7; // Increment when adding new migrations

        if (currentVersion < TARGET_VERSION) {
            console.log(chalk.yellow(`[DATABASE] Checking for necessary schema migrations (v${currentVersion} -> v${TARGET_VERSION})...`));
            try {
                // Gather all table info once to avoid redundant PRAGMA calls
                const usersInfo = await db.all("PRAGMA table_info(users)");
                const linksInfo = await db.all("PRAGMA table_info(links)");
                const shortLinksInfo = await db.all("PRAGMA table_info(short_links)");
                const clicksInfo = await db.all("PRAGMA table_info(clicks)");
                const domainsInfo = await db.all("PRAGMA table_info(custom_domains)");

                const userCols = new Set(usersInfo.map(c => c.name));
                const linkCols = new Set(linksInfo.map(c => c.name));
                const shortLinkCols = new Set(shortLinksInfo.map(c => c.name));
                const clickCols = new Set(clicksInfo.map(c => c.name));
                const domainCols = new Set(domainsInfo.map(c => c.name));

                // Run all migrations inside a single transaction for safety
                await db.exec('BEGIN TRANSACTION');

                try {
                    // MIGRATION: Transition users table from password-based to access-key-based auth
                    if (!userCols.has('accessKey')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding access-key columns to users table...'));
                        await db.exec(`ALTER TABLE users ADD COLUMN accessKey TEXT`);
                        await db.exec(`ALTER TABLE users ADD COLUMN keyExpiresAt DATETIME`);
                        await db.exec(`ALTER TABLE users ADD COLUMN isActive INTEGER DEFAULT 1`);
                        await db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_accessKey ON users(accessKey)`);
                        console.log(chalk.green('[DATABASE] ✓ Users table migrated to access-key auth.'));
                    }

                    // FIX 1: Rename html_templates to link_templates if it exists
                    const htmlTemplatesExists = await db.all("SELECT name FROM sqlite_master WHERE type='table' AND name='html_templates'");
                    if (htmlTemplatesExists.length > 0) {
                        const linkTemplatesExists = await db.all("SELECT name FROM sqlite_master WHERE type='table' AND name='link_templates'");
                        if (linkTemplatesExists.length === 0) {
                            console.log(chalk.cyan('[DATABASE] Migrating: Renaming html_templates to link_templates...'));
                            await db.exec('ALTER TABLE html_templates RENAME TO link_templates');
                        }
                    }

                    // FIX 2: Check 'links' table for missing columns
                    if (!linkCols.has('templateId')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding missing "templateId" column to links...'));
                        await db.exec(`ALTER TABLE links ADD COLUMN templateId INTEGER DEFAULT NULL`);
                    }
                    if (!linkCols.has('tags')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "tags" column to links...'));
                        await db.exec(`ALTER TABLE links ADD COLUMN tags TEXT`);
                    }
                    if (!linkCols.has('notes')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "notes" column to links...'));
                        await db.exec(`ALTER TABLE links ADD COLUMN notes TEXT`);
                    }
                    if (!linkCols.has('isActive')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "isActive" column to links...'));
                        await db.exec(`ALTER TABLE links ADD COLUMN isActive INTEGER DEFAULT 1`);
                    }

                    // FIX 3: Check 'short_links' table for missing columns
                    if (!shortLinkCols.has('isActive')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding missing "isActive" column to short_links...'));
                        await db.exec(`ALTER TABLE short_links ADD COLUMN isActive INTEGER DEFAULT 1`);
                    }
                    if (!shortLinkCols.has('lastClickAt')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding missing "lastClickAt" column to short_links...'));
                        await db.exec(`ALTER TABLE short_links ADD COLUMN lastClickAt DATETIME`);
                    }
                    if (!shortLinkCols.has('metadata')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding missing "metadata" column to short_links...'));
                        await db.exec(`ALTER TABLE short_links ADD COLUMN metadata TEXT`);
                    }

                    // FIX 4: Check 'clicks' table for missing columns
                    if (!clickCols.has('isUnique')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "isUnique" column to clicks...'));
                        await db.exec(`ALTER TABLE clicks ADD COLUMN isUnique INTEGER DEFAULT 0`);
                    }

                    // FIX 5: Check 'custom_domains' for missing columns
                    if (!domainCols.has('purpose')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "purpose" column to custom_domains...'));
                        await db.exec(`ALTER TABLE custom_domains ADD COLUMN purpose TEXT DEFAULT 'link'`);
                    }

                    // FIX 6: Per-domain template assignment + DNS/SSL columns
                    if (!domainCols.has('templateId')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "templateId" column to custom_domains...'));
                        await db.exec(`ALTER TABLE custom_domains ADD COLUMN templateId INTEGER DEFAULT NULL`);
                    }
                    if (!domainCols.has('dnsVerified')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "dnsVerified" column to custom_domains...'));
                        await db.exec(`ALTER TABLE custom_domains ADD COLUMN dnsVerified INTEGER DEFAULT 0`);
                    }
                    if (!domainCols.has('sslStatus')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "sslStatus" column to custom_domains...'));
                        await db.exec(`ALTER TABLE custom_domains ADD COLUMN sslStatus TEXT DEFAULT 'pending'`);
                    }

                    // FIX 7: Add batchId column for batch redirect generation
                    if (!linkCols.has('batchId')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "batchId" column to links...'));
                        await db.exec(`ALTER TABLE links ADD COLUMN batchId TEXT`);
                        await db.exec(`CREATE INDEX IF NOT EXISTS idx_links_batchId ON links(batchId)`);
                    }

                    // FIX 8: Bot redirect events table for safe redirect chain tracking
                    await db.exec(`
                        CREATE TABLE IF NOT EXISTS bot_redirect_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            linkId TEXT NOT NULL,
                            hopIndex INTEGER NOT NULL,
                            ipAddress TEXT,
                            userAgent TEXT,
                            country TEXT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(linkId) REFERENCES links(id) ON DELETE CASCADE
                        )
                    `);
                    await db.exec(`CREATE INDEX IF NOT EXISTS idx_bot_redirect_linkId ON bot_redirect_events(linkId)`);
                    await db.exec(`CREATE INDEX IF NOT EXISTS idx_bot_redirect_timestamp ON bot_redirect_events(timestamp)`);

                    // FIX 9: Railway domain registration tracking
                    if (!domainCols.has('railwayDomainId')) {
                        console.log(chalk.cyan('[DATABASE] Migrating: Adding "railwayDomainId" column to custom_domains...'));
                        await db.exec(`ALTER TABLE custom_domains ADD COLUMN railwayDomainId TEXT DEFAULT NULL`);
                    }

                    // Update migration version
                    await db.run(
                        `INSERT INTO _migration_meta (id, version, lastRunAt) VALUES (1, ?, CURRENT_TIMESTAMP)
                         ON CONFLICT(id) DO UPDATE SET version = ?, lastRunAt = CURRENT_TIMESTAMP`,
                        [TARGET_VERSION, TARGET_VERSION]
                    );

                    await db.exec('COMMIT');
                    console.log(chalk.green(`[DATABASE] ✓ All migrations completed (now at v${TARGET_VERSION}).`));
                } catch (migInnerErr) {
                    await db.exec('ROLLBACK');
                    throw migInnerErr;
                }

            } catch (migError) {
                console.warn(chalk.yellow('[DATABASE] Migration warning (non-fatal):'), migError.message);
            }
        } else {
            console.log(chalk.green(`[DATABASE] Schema is up to date (v${currentVersion}).`));
        }
        // ------------------------------------------------

        // Create indexes for new tables
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_links_slug ON short_links(slug);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_links_owner ON short_links(ownerId);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_links_active ON short_links(isActive);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_short_link_clicks_link ON short_link_clicks(shortLinkId);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_templates_owner ON link_templates(ownerId);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_links_template ON links(templateId);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_clicks_linkid ON clicks(linkId);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_clicks_timestamp ON clicks(timestamp);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_clicks_ip ON clicks(ipAddress);`);
        await db.exec(`CREATE INDEX IF NOT EXISTS idx_links_batchId ON links(batchId);`);

        // --- SELF-HEALING ---
        // Fixes any potential data integrity issues on startup
        console.log(chalk.yellow('[DATABASE] Running self-healing consistency check... '));
        
        await db.run(`UPDATE links SET clicks = 0 WHERE clicks IS NULL`);
        await db.run(`UPDATE links SET botClicks = 0 WHERE botClicks IS NULL`);
        await db.run(`UPDATE clicks SET isBot = 0 WHERE isBot IS NULL`);
        await db.run(`UPDATE short_links SET clicks = 0 WHERE clicks IS NULL`);
        await db.run(`UPDATE short_links SET isActive = 1 WHERE isActive IS NULL`);

        console.log(chalk.green.bold('[DATABASE] Database is healthy and ready. '));
        return db;

    } catch (error) {
        console.error(chalk.red.bold('[DATABASE] FATAL ERROR:'), error);
        process.exit(1);
    }
}

function getDb() {
    if (!dbPromise) {
        dbPromise = initializeDatabase();
    }
    return dbPromise;
}

module.exports = getDb;
