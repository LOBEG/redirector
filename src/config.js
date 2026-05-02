require('dotenv').config();
const crypto = require('crypto');

// Robust Fallback: Generate a random secret if missing.
// In Production, warn heavily but still start — this allows Railway healthchecks
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
  log('[CONFIG] Set JWT_SECRET and REDIRECTOR_SECRET in your Railway environment variables for production use.');
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

  // Railway hostname — auto-set by Railway via RAILWAY_PUBLIC_DOMAIN (may be custom domain or .railway.app).
  railwayHostname: process.env.RAILWAY_PUBLIC_DOMAIN || '',

  // Explicit CNAME target — set this to your platform hostname (e.g., your-app.up.railway.app)
  // when RAILWAY_PUBLIC_DOMAIN is a custom domain. This is the hostname users should CNAME to.
  cnameTarget: process.env.CNAME_TARGET || '',

  // Railway API — for automatic custom domain registration.
  // RAILWAY_TOKEN must be generated in Railway dashboard (Account → Tokens) and set manually.
  // RAILWAY_SERVICE_ID and RAILWAY_ENVIRONMENT_ID are auto-injected by Railway at runtime.
  railwayToken: process.env.RAILWAY_TOKEN || '',
  railwayServiceId: process.env.RAILWAY_SERVICE_ID || '',
  railwayEnvironmentId: process.env.RAILWAY_ENVIRONMENT_ID || '',
  
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
      393406  // DigitalOcean
    ]
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
