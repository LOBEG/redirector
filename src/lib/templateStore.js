/**
 * Template Store v1.2
 * 
 * Manages custom HTML templates for redirect pages. 
 * Allows users to save, retrieve, and manage multiple templates.
 * 
 * Uses 'link_templates' table (migrated from 'html_templates' in database.js).
 */

const getDb = require('./database');
const { validateTemplate } = require('./htmlTemplateProcessor');
const chalk = require('chalk');

// Table name constant — database.js handles migration from html_templates
const TABLE = 'link_templates';

// Maximum template HTML size (500KB — protects against oversized uploads)
const MAX_TEMPLATE_SIZE = 500 * 1024;

// Ensure table exists
async function ensureTableExists() {
    const db = await getDb();
    
    await db.exec(`
        CREATE TABLE IF NOT EXISTS ${TABLE} (
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
        
        CREATE INDEX IF NOT EXISTS idx_templates_owner ON ${TABLE}(ownerId);
    `);
}

let initialized = false;
async function init() {
    if (!initialized) {
        await ensureTableExists();
        initialized = true;
    }
}

const templateStore = {
    
    /**
     * Saves a new template or updates existing one
     * @param {object} options 
     * @returns {Promise<object>}
     */
    async save(options) {
        await init();
        
        const {
            ownerId,
            name,
            description = null,
            htmlContent,
            isDefault = false
        } = options;

        if (!ownerId) throw new Error('Owner ID is required');
        if (!name || typeof name !== 'string') throw new Error('Template name is required');
        if (!htmlContent || typeof htmlContent !== 'string') throw new Error('HTML content is required');

        // Input sanitization: trim name
        const trimmedName = name.trim();
        if (trimmedName.length === 0) throw new Error('Template name cannot be empty');
        if (trimmedName.length > 100) throw new Error('Template name must be 100 characters or fewer');

        // Size validation: prevent oversized template uploads
        if (htmlContent.length > MAX_TEMPLATE_SIZE) {
            throw new Error(`Template content exceeds maximum size of ${Math.round(MAX_TEMPLATE_SIZE / 1024)}KB`);
        }

        // Validate template
        const validation = validateTemplate(htmlContent);
        if (!validation.isValid) {
            throw new Error(`Invalid template: ${validation.errors.join(', ')}`);
        }

        const db = await getDb();

        // If setting as default, unset other defaults first
        if (isDefault) {
            await db.run(
                `UPDATE ${TABLE} SET isDefault = 0 WHERE ownerId = ?`,
                [ownerId]
            );
        }

        try {
            // Try to update existing
            const existing = await db.get(
                `SELECT id FROM ${TABLE} WHERE ownerId = ? AND name = ?`,
                [ownerId, trimmedName]
            );

            if (existing) {
                // Feature 9: snapshot the prior version before overwriting.
                // Best-effort — failure to write a revision must not block save.
                try {
                    const prior = await db.get(
                        `SELECT htmlContent, description FROM ${TABLE} WHERE id = ?`,
                        [existing.id]
                    );
                    if (prior && prior.htmlContent) {
                        await db.run(
                            'INSERT INTO link_template_revisions (templateId, ownerId, htmlContent, description) VALUES (?, ?, ?, ?)',
                            [existing.id, ownerId, prior.htmlContent, prior.description || null]
                        );
                    }
                } catch (e) { /* non-fatal — table may not exist on first run */ }

                await db.run(
                    `UPDATE ${TABLE} 
                     SET htmlContent = ?, description = ?, isDefault = ?, updatedAt = CURRENT_TIMESTAMP 
                     WHERE id = ?`,
                    [htmlContent, description, isDefault ? 1 : 0, existing.id]
                );

                console.log(chalk.green(`[TEMPLATE] Updated: ${trimmedName}`));
                
                return {
                    id: existing.id,
                    name: trimmedName,
                    description,
                    isDefault,
                    warnings: validation.warnings,
                    updated: true
                };
            } else {
                const result = await db.run(
                    `INSERT INTO ${TABLE} (ownerId, name, description, htmlContent, isDefault) 
                     VALUES (?, ?, ?, ?, ?)`,
                    [ownerId, trimmedName, description, htmlContent, isDefault ? 1 : 0]
                );

                console.log(chalk.green(`[TEMPLATE] Created: ${trimmedName}`));

                return {
                    id: result.lastID,
                    name: trimmedName,
                    description,
                    isDefault,
                    warnings: validation.warnings,
                    created: true
                };
            }
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT') {
                throw new Error(`A template named "${trimmedName}" already exists for this account`);
            }
            throw error;
        }
    },

    /**
     * Gets a template by name for a user
     * @param {number} ownerId 
     * @param {string} name 
     * @returns {Promise<object|null>}
     */
    async get(ownerId, name) {
        await init();
        
        const db = await getDb();
        return db.get(
            `SELECT * FROM ${TABLE} WHERE ownerId = ? AND name = ?`,
            [ownerId, name]
        );
    },

    /**
     * Gets a template by its ID
     * @param {number} templateId 
     * @returns {Promise<object|null>}
     */
    async getById(templateId) {
        if (!templateId) return null;
        await init();
        
        const db = await getDb();
        return db.get(
            `SELECT * FROM ${TABLE} WHERE id = ?`,
            [templateId]
        );
    },

    /**
     * Gets the default template for a user
     * @param {number} ownerId 
     * @returns {Promise<object|null>}
     */
    async getDefault(ownerId) {
        await init();
        
        const db = await getDb();
        return db.get(
            `SELECT * FROM ${TABLE} WHERE ownerId = ? AND isDefault = 1`,
            [ownerId]
        );
    },

    /**
     * Gets all templates for a user
     * @param {number} ownerId 
     * @returns {Promise<array>}
     */
    async getAll(ownerId) {
        await init();
        
        const db = await getDb();
        return db.all(
            `SELECT id, name, description, isDefault, createdAt, updatedAt, 
                    LENGTH(htmlContent) as contentSize 
             FROM ${TABLE} 
             WHERE ownerId = ? 
             ORDER BY isDefault DESC, updatedAt DESC`,
            [ownerId]
        );
    },

    /**
     * Deletes a template
     * @param {number} ownerId 
     * @param {string} name 
     * @returns {Promise<boolean>}
     */
    async delete(ownerId, name) {
        await init();
        
        const db = await getDb();
        const result = await db.run(
            `DELETE FROM ${TABLE} WHERE ownerId = ? AND name = ?`,
            [ownerId, name]
        );

        if (result.changes > 0) {
            console.log(chalk.red(`[TEMPLATE] Deleted: ${name}`));
            return true;
        }

        return false;
    },

    /**
     * Sets a template as default
     * @param {number} ownerId 
     * @param {string} name 
     * @returns {Promise<boolean>}
     */
    async setDefault(ownerId, name) {
        await init();
        
        const db = await getDb();

        // Verify template exists
        const template = await db.get(
            `SELECT id FROM ${TABLE} WHERE ownerId = ? AND name = ?`,
            [ownerId, name]
        );

        if (!template) return false;

        // Unset all defaults
        await db.run(`UPDATE ${TABLE} SET isDefault = 0 WHERE ownerId = ?`, [ownerId]);

        // Set new default
        await db.run(`UPDATE ${TABLE} SET isDefault = 1 WHERE id = ?`, [template.id]);

        console.log(chalk.yellow(`[TEMPLATE] Set default: ${name}`));
        return true;
    }
};

module.exports = templateStore;
