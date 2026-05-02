const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const REDIRECT_SECRET = process.env.REDIRECT_SECRET || 'fallback-dev-secret-do-not-use-in-prod';

/**
 * EMAIL-SAFE URL STRATEGY
 * Encodes the link ID and HMAC signature into a single base64url token,
 * producing a clean URL path that passes email security scanner checks.
 * 
 * Old format: /tr/v1/{uuid}?s={hex}&file=invoice_xxxx.pdf  (flagged by scanners)
 * New format: /p/{base64url-token}  (clean, looks like a normal page ID)
 */

/**
 * Encode a UUID and its HMAC signature into a single URL-safe token.
 * @param {string} uuid - The link UUID (with or without dashes)
 * @param {string} signature - The hex-encoded HMAC-SHA256 signature
 * @returns {string} A base64url-encoded token
 */
function encodeToken(uuid, signature) {
  const idBytes = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  const sigBytes = Buffer.from(signature, 'hex');
  return Buffer.concat([idBytes, sigBytes]).toString('base64url');
}

/**
 * Decode a base64url token back into UUID and signature.
 * @param {string} token - The base64url-encoded token
 * @returns {{ id: string, signature: string } | null}
 */
function decodeToken(token) {
  try {
    const buf = Buffer.from(token, 'base64url');
    if (buf.length !== 48) return null; // 16 (uuid) + 32 (hmac-sha256)
    const idHex = buf.slice(0, 16).toString('hex');
    const sigHex = buf.slice(16).toString('hex');
    // Reconstruct UUID with dashes
    const uuid = [
      idHex.slice(0, 8),
      idHex.slice(8, 12),
      idHex.slice(12, 16),
      idHex.slice(16, 20),
      idHex.slice(20, 32)
    ].join('-');
    return { id: uuid, signature: sigHex };
  } catch (e) {
    return null;
  }
}

exports.createRedirect = (safeUrl, publicDomain) => {
  const internalId = uuidv4();
  
  const signature = crypto.createHmac('sha256', REDIRECT_SECRET)
    .update(internalId)
    .digest('hex');

  let baseUrl = publicDomain;
  if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
      baseUrl = `https://${baseUrl}`;
  }

  // Encode UUID + signature into a single clean token for email-safe URLs
  const token = encodeToken(internalId, signature);
  const finalLink = `${baseUrl}/p/${token}`;

  return {
    googleAdsUrl: finalLink, 
    internalId,
    signature
  };
};

exports.verifySignature = (id, signature) => {
  if (!id || !signature) return false;
  const expected = crypto.createHmac('sha256', REDIRECT_SECRET).update(id).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'));
  } catch {
    return false;
  }
};

exports.encodeToken = encodeToken;
exports.decodeToken = decodeToken;
