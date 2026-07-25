/**
 * apiKeyManager.js — API keys / personal access tokens (Feature 11).
 *
 * Keys are issued as a single base64url string with a short prefix (rdr_)
 * for easy identification in user-facing UIs. Only a SHA-256 hash of the key
 * is stored — the plaintext is shown ONCE at creation time.
 *
 * The middleware authenticates `Authorization: Bearer rdr_…` and populates
 * req.user with the same shape as JWT auth ({ id, user, role }), so all
 * existing protected endpoints work unchanged.
 */
'use strict';

const crypto = require('crypto');
const getDb = require('./database');

const KEY_PREFIX = 'rdr_';

function _hash(key) {
    return crypto.createHash('sha256').update(String(key)).digest('hex');
}

/** Generate and persist a new API key. Returns the plaintext ONCE. */
async function createApiKey({ ownerId, name, scopes = 'read,write' }) {
    if (!ownerId) throw new Error('ownerId is required');
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        throw new Error('name is required');
    }
    const trimmed = name.trim().slice(0, 100);
    const raw = crypto.randomBytes(32).toString('base64url');
    const plain = KEY_PREFIX + raw;
    const hash = _hash(plain);
    const prefix = plain.slice(0, 12); // shown in UI: rdr_AbCdEf…

    const db = await getDb();
    const result = await db.run(
        'INSERT INTO api_keys (ownerId, name, keyHash, keyPrefix, scopes) VALUES (?, ?, ?, ?, ?)',
        [ownerId, trimmed, hash, prefix, scopes]
    );
    return { id: result.lastID, name: trimmed, scopes, prefix, key: plain };
}

/** List API keys for a user (without secret material). */
async function listApiKeys(ownerId) {
    const db = await getDb();
    return db.all(
        'SELECT id, name, keyPrefix, scopes, lastUsedAt, createdAt, revokedAt FROM api_keys WHERE ownerId = ? ORDER BY createdAt DESC',
        [ownerId]
    );
}

/** Revoke an API key (sets revokedAt). */
async function revokeApiKey(ownerId, id) {
    const db = await getDb();
    const result = await db.run(
        'UPDATE api_keys SET revokedAt = CURRENT_TIMESTAMP WHERE id = ? AND ownerId = ? AND revokedAt IS NULL',
        [id, ownerId]
    );
    return result.changes > 0;
}

/**
 * Resolve an API key plaintext to the owning user record.
 * Returns null if not found, expired, or revoked.
 */
async function resolveApiKey(plaintext) {
    if (!plaintext || typeof plaintext !== 'string') return null;
    if (!plaintext.startsWith(KEY_PREFIX)) return null;
    const hash = _hash(plaintext);
    const db = await getDb();
    const row = await db.get(
        `SELECT k.id as keyId, k.ownerId, k.scopes, k.revokedAt, u.username, u.role, u.isActive
         FROM api_keys k JOIN users u ON u.id = k.ownerId
         WHERE k.keyHash = ?`,
        [hash]
    );
    if (!row) return null;
    if (row.revokedAt) return null;
    if (!row.isActive) return null;

    // Update last-used asynchronously — don't await
    db.run('UPDATE api_keys SET lastUsedAt = CURRENT_TIMESTAMP WHERE id = ?', [row.keyId]).catch(() => {});

    return {
        id: row.ownerId,
        user: row.username,
        role: row.role,
        viaApiKey: true,
        scopes: (row.scopes || '').split(',').map(s => s.trim()).filter(Boolean)
    };
}

/**
 * Express middleware that accepts EITHER a JWT or an API key.
 * Wraps the existing JWT authenticator: tries API key first, then falls
 * through to JWT verification.
 */
function makeApiKeyAwareAuth(jwtAuthenticate) {
    return async (req, res, next) => {
        const header = req.headers['authorization'];
        const token = header && header.split(' ')[1];
        if (token && token.startsWith(KEY_PREFIX)) {
            const user = await resolveApiKey(token);
            if (user) {
                req.user = user;
                return next();
            }
            return res.status(401).json({ error: 'Invalid or revoked API key' });
        }
        return jwtAuthenticate(req, res, next);
    };
}

module.exports = {
    KEY_PREFIX,
    createApiKey,
    listApiKeys,
    revokeApiKey,
    resolveApiKey,
    makeApiKeyAwareAuth
};
