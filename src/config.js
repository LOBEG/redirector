require('dotenv').config();
const crypto = require('crypto');

// Robust Fallback: Generate a random secret if missing.
// In Production, warn heavily but still start — this allows platform healthchecks
// to pass while the user configures env vars. Sessions won't persist across restarts.
const DEFAULT_SECRET = crypto.randomBytes(32).toString('hex');
const isProduction = process.env.NODE_ENV === 'production';
const log = isProduction ? console.error.bind(console) : console.warn.bind(console);

if (!process.env.JWT_SECRET) {
  log('[CONFIG] WARNING: JWT_SECRET not set — using random fallback. Sessions will not persist across restarts.');
}
if (!process.env.REDIRECTOR_SECRET) {
  log('[CONFIG] WARNING: REDIRECTOR_SECRET not set — using random fallback.');
}
if (isProduction && (!process.env.JWT_SECRET || !process.env.REDIRECTOR_SECRET)) {
  log('[CONFIG] Set JWT_SECRET and REDIRECTOR_SECRET in your Northflank environment variables for production use.');
}
if (!process.env.ADMIN_EMAIL) {
  console.warn('[CONFIG] WARNING: ADMIN_EMAIL not set — using default admin@proctektexas.org.');
}

module.exports = {
  // Server configuration
  port: process.env.PORT || 10000,
  env: process.env.NODE_ENV || 'development',

  // Admin email — configurable via ADMIN_EMAIL env var
  adminEmail: process.env.ADMIN_EMAIL || 'admin@proctektexas.org',

  // Link Domain — dedicated domain used exclusively for generated tracking links.
  linkDomain: process.env.LINK_DOMAIN || '',

  // Northflank hostname — set manually to your Northflank public hostname (usually *.code.run).
  northflankHostname: process.env.NORTHFLANK_PUBLIC_DOMAIN || '',

  // Explicit CNAME target — set this to your platform hostname (e.g., your-service.code.run)
  // when NORTHFLANK_PUBLIC_DOMAIN is a custom domain. This is the hostname users should CNAME to.
  cnameTarget: process.env.CNAME_TARGET || '',

  // Northflank API — for automatic custom domain registration.
  // NORTHFLANK_API_TOKEN must be generated in Northflank and set manually.
  // Project/service identifiers must also be configured manually.
  northflankApiToken: process.env.NORTHFLANK_API_TOKEN || '',
  northflankProjectId: process.env.NORTHFLANK_PROJECT_ID || '',
  northflankServiceId: process.env.NORTHFLANK_SERVICE_ID || '',
  northflankPortName: process.env.NORTHFLANK_PORT_NAME || 'p01',
  
  // JWT Authentication
  jwt: {
    secret: process.env.JWT_SECRET || DEFAULT_SECRET,
    expiresIn: '24h'
  },
  
  // Redis Cache Configuration (Optional)
  redis: {
    enabled: !!process.env.REDIS_URL,
    url: process.env.REDIS_URL || 'redis://localhost:6379'
  },

  // Redirector / Cloaker Configuration
  redirector: {
    secret: process.env.REDIRECTOR_SECRET || DEFAULT_SECRET,
    tokenTtl: 2 * 60 * 1000, // 2 minutes
    fallbackUrl: process.env.FALLBACK_URL || 'https://www.google.com'
  },
  
  // Advanced Fraud detection settings
  fraud: {
    thresholds: {
      high: 80,
      medium: 50
    },
    allowedCountries: [], 
    datacenterAsn: [
      15169,  // Google
      16509,  // Amazon AWS
      8075,   // Microsoft Azure
      14061,  // DigitalOcean
      24940,  // Hetzner
      16276,  // OVH
      63949,  // Linode / Akamai
      20473,  // Choopa / Vultr
      13335,  // Cloudflare
      393406, // DigitalOcean
      14618,  // AWS
      32934,  // Facebook
      15133,  // Edgecast/Verizon
      54113,  // Fastly
      36351   // SoftLayer/IBM
    ]
  },

  // Bot Detector tuning — overrideable via env vars
  botDetection: {
    threshold: parseInt(process.env.BOT_DETECTION_THRESHOLD, 10) || 50,
    highConfidenceThreshold: parseInt(process.env.BOT_HIGH_CONFIDENCE_THRESHOLD, 10) || 80
  },

  // Link configuration
  link: {
    expiresIn: 7 * 24 * 60 * 60 * 1000,
    cacheTTL: 60 * 60 // 1 hour
  },

  // License configuration
  license: {
    plans: {
      free: { limit: 100, name: 'Free' },
      pro: { limit: 1000, name: 'Pro' },
      enterprise: { limit: Infinity, name: 'Enterprise' }
    },
    resetInterval: 60 * 60 * 1000 // 1 hour
  }
};
