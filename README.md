# Paris Engine — Advanced Link Cloaking & Redirect System

A production-ready redirect link cloaker, tracker, and manager with multi-layer bot detection, AES-256-GCM encrypted payloads, HMAC-signed URLs, custom HTML templates, and safe unlimited batch redirect generation.

---

## Table of Contents

- [How It Works — System Architecture](#how-it-works--system-architecture)
- [The Redirect Flow (Step by Step)](#the-redirect-flow-step-by-step)
- [Safe Unlimited Batch Redirects](#safe-unlimited-batch-redirects)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Custom HTML Templates](#custom-html-templates)
- [Custom Domains](#custom-domains)
- [Short Links](#short-links)

---

## How It Works — System Architecture

Paris Engine is a server-side redirect cloaker. The core idea is: **the real destination URL is never exposed in HTML source code**. Instead, every tracking link goes through a multi-step security pipeline before the visitor reaches the final destination.

### Core Components

| Component | File | Purpose |
|---|---|---|
| **Server** | `src/server.js` | Express HTTP server, all API routes, tracking/unlock handlers |
| **Link Store** | `src/lib/linkStore.js` | CRUD operations for links, clicks, analytics, batch generation |
| **Google Ads Redirector** | `src/lib/googleAdsRedirector.js` | Creates HMAC-signed, email-safe `/p/{token}` tracking URLs |
| **Cloaker** | `src/lib/cloaker.js` | AES-256-GCM encryption/decryption of destination URLs |
| **Bot Detector** | `src/lib/botDetector.js` | Multi-layer bot detection (UA, headers, Sec-Fetch, client signals) |
| **Template Processor** | `src/lib/htmlTemplateProcessor.js` | Sanitizes user HTML templates, neutralizes all redirects, injects freezer |
| **Template Store** | `src/lib/templateStore.js` | Saves/retrieves custom HTML templates per user |
| **Short Link Manager** | `src/lib/shortLinkManager.js` | Creates and resolves short `/s/{slug}` links |
| **Database** | `src/lib/database.js` | SQLite with WAL mode, auto-migration, self-healing |
| **Auth** | `src/lib/auth.js` | Access key generation, JWT signing/verification |
| **Config** | `src/config.js` | Central configuration from environment variables |

### Security Layers

1. **HMAC-SHA256 URL Signing** — Every tracking URL contains a cryptographic signature. Tampered URLs are rejected.
2. **AES-256-GCM Payload Encryption** — The real destination URL is encrypted server-side. The ciphertext is embedded in the page; only the server can decrypt it.
3. **Multi-Layer Bot Detection** — Server-side UA analysis + HTTP header inspection + client-side JavaScript fingerprinting (canvas, WebGL, plugins, screen, WebDriver).
4. **Challenge Tokens** — Short-lived JWTs prevent direct POST attacks to the unlock endpoint.
5. **Referer Validation** — The unlock endpoint verifies that the request originated from the same domain.
6. **Nuclear Freezer** — Injected script overwrites `window.location`, `setTimeout`, `setInterval`, `eval`, `window.open`, and `history` APIs to prevent user-uploaded templates from performing their own redirects.
7. **Safe Unlimited Redirect Chain** — Bots are redirected into an infinite chain of legitimate-looking pages (security checks, DDoS protection, loading screens). Each hop is JWT-signed and the chain cycles through 8 themes forever. Bots never see the real destination URL.
8. **Rate Limiting** — All endpoints are rate-limited to prevent abuse.

---

## The Redirect Flow (Step by Step)

When a visitor clicks a tracking link, this is what happens:

```
Visitor clicks:  https://yourdomain.com/p/IZoc4KoZS7mr7r4d...
                           │
                           ▼
              ┌─────────────────────────┐
              │  1. URL SIGNATURE CHECK │
              │  Decode base64url token │
              │  Verify HMAC-SHA256     │
              │  Invalid → 404          │
              └──────────┬──────────────┘
                         │ Valid
                         ▼
              ┌─────────────────────────┐
              │  2. FETCH LINK FROM DB  │
              │  Check if exists        │
              │  Check if active        │
              │  Get destination URL    │
              └──────────┬──────────────┘
                         │ Found
                         ▼
              ┌─────────────────────────┐
              │  3. BOT DETECTION       │
              │  User-Agent analysis    │
              │  HTTP header checks     │
              │  Sec-Fetch analysis     │
              └─────┬───────────┬───────┘
                    │           │
              Bot detected    Human
                    │           │
                    ▼           ▼
     ┌──────────────────┐    (continues below)
     │ SAFE REDIRECT    │
     │ CHAIN (Infinite) │
     │ 302 → /sr/:token │
     │ Theme 1: Security│
     │ Theme 2: DDoS    │
     │ Theme 3: Loading │
     │ ... 8 themes ... │
     │ ↻ loops forever  │
     │ Bot NEVER sees   │
     │ real destination  │
     └──────────────────┘
                         ▼
              ┌─────────────────────────┐
              │  4. BUILD CLOAKED PAGE  │
              │  Load user template     │
              │  Sanitize all redirects │
              │  Inject Nuclear Freezer │
              │  Encrypt dest URL (AES) │
              │  Embed unlock script    │
              └──────────┬──────────────┘
                         │
                         ▼
              ┌─────────────────────────┐
              │  5. BROWSER EXECUTES    │
              │  Client bot detection   │
              │  Canvas/WebGL probes    │
              │  Collect device signals │
              │  POST to /tr/v2/unlock  │
              └──────────┬──────────────┘
                         │
                         ▼
              ┌─────────────────────────┐
              │  6. UNLOCK ENDPOINT     │
              │  Verify challenge token │
              │  Verify referer         │
              │  Re-check bot (server)  │
              │  Decrypt AES payload    │
              │  Loop detection         │
              │  Set unlock cookie      │
              │  → Return destination   │
              └──────────┬──────────────┘
                         │
                         ▼
              ┌─────────────────────────┐
              │  7. FINAL REDIRECT      │
              │  Browser navigates to   │
              │  the real destination   │
              └─────────────────────────┘
```

### Key Points

- **The destination URL never appears in HTML source.** It is AES-256-GCM encrypted and only decrypted server-side at the unlock step.
- **Bots see a scanner-safe page** — a clean HTML page with no scripts or redirects. This passes email security scanner checks.
- **The template is frozen** — even if a user uploads a template that contains `window.location = "..."`, the Nuclear Freezer script neutralizes it. Only the system unlock script (using a saved backdoor `__sys_ops`) can perform the actual redirect.
- **Click logging happens before the cloaked page is served**, so analytics capture every hit regardless of whether the visitor completes the unlock.

---

## Safe Unlimited Batch Redirects

The Batch Redirect Generator lets you create **any number of tracking redirect links in a single API call**. Each link gets its own:

- Unique UUID
- HMAC-SHA256 signed tracking URL
- AES-256-GCM encrypted payload
- Individual click tracking and analytics
- Optional tags and notes

All links in a batch are grouped under a shared `batchId` for easy retrieval and management.

### Why It's "Safe"

1. **No hardcoded limits** — The batch endpoint accepts any number of destinations. There is no artificial cap.
2. **Atomic transactions** — All links in a batch are created inside a single database transaction. If any link fails, the entire batch rolls back — no partial batches.
3. **Individual security** — Each link has its own HMAC signature and encrypted payload. Compromising one link does not affect others.
4. **XSS-safe HTML export** — The HTML export endpoint escapes all output through `escapeHtml()` to prevent cross-site scripting.
5. **Owner-scoped access** — Batch retrieval is scoped to the authenticated user. You can only see your own batches.

### How to Use Batch Redirects

#### Step 1: Create a Batch

Send a POST request with an array of destination URLs:

```bash
curl -X POST https://yourdomain.com/api/links/batch \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "destinations": [
      { "url": "https://example.com/page1", "tags": "campaign-a", "notes": "Landing page v1" },
      { "url": "https://example.com/page2", "tags": "campaign-a", "notes": "Landing page v2" },
      { "url": "https://example.com/page3", "tags": "campaign-b" },
      { "url": "https://another-site.com/offer", "notes": "Partner offer" },
      { "url": "https://store.example.com/product/123" }
    ],
    "expiresAt": "2026-12-31T23:59:59Z",
    "customDomain": "links.mydomain.com",
    "templateId": 5
  }'
```

**Request body fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `destinations` | Array | ✅ | Array of objects, each with a `url` string (required), plus optional `tags` and `notes` |
| `expiresAt` | String | No | ISO 8601 datetime for link expiration |
| `customDomain` | String | No | Override domain for the generated URLs (defaults to your preferred domain) |
| `templateId` | Number | No | Template ID to use for the redirect page |

**Response:**

```json
{
  "success": true,
  "batchId": "47212948-feb9-4c03-961b-9aafcc5ab1cd",
  "count": 5,
  "links": [
    {
      "id": "1ac231fc-cc7e-4cef-9c02-e4b38c61c3e3",
      "ownerId": 1,
      "googleAdsUrl": "https://links.mydomain.com/p/GsIx_Mx-TO-cAuSzjGHD...",
      "destinationUrlDesktop": "https://example.com/page1",
      "expiresAt": "2026-12-31T23:59:59Z",
      "clicks": 0,
      "botClicks": 0,
      "batchId": "47212948-feb9-4c03-961b-9aafcc5ab1cd",
      "tags": "campaign-a",
      "notes": "Landing page v1"
    },
    ...
  ]
}
```

The `googleAdsUrl` field in each link is the tracking URL you share with your audience. When someone clicks it, the full redirect flow (described above) activates.

#### Step 2: List All Batches

```bash
curl https://yourdomain.com/api/links/batches \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Response:**

```json
[
  {
    "batchId": "47212948-feb9-4c03-961b-9aafcc5ab1cd",
    "linkCount": 5,
    "totalClicks": 142,
    "totalBotClicks": 23,
    "createdAt": "2026-03-05 00:56:58",
    "expiresAt": "2026-12-31T23:59:59Z"
  }
]
```

#### Step 3: Get All Links in a Batch

```bash
curl https://yourdomain.com/api/links/batch/47212948-feb9-4c03-961b-9aafcc5ab1cd \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Step 4: Export Batch as HTML

Get a self-contained HTML document with all tracking links in a styled table:

```bash
curl https://yourdomain.com/api/links/batch/47212948-feb9-4c03-961b-9aafcc5ab1cd/html \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -o batch-links.html
```

This generates a clean HTML page you can open in a browser, save, print, or share. It shows each link's tracking URL, destination, tags, and notes in a table.

---

## Getting Started

### Prerequisites

- **Node.js 20.x**
- No external database required (uses SQLite with WAL mode)
- Optional: Redis for caching (`REDIS_URL`)

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd vxpscript

# Install dependencies
npm install

# Create .env file (see Environment Variables below)
cp .env.example .env  # or create manually

# Start the server
npm start

# For development with auto-reload
npm run dev
```

### First-Time Setup

1. Start the server. The default admin user is created automatically using the `ADMIN_EMAIL` env var.
2. Open the dashboard at `http://localhost:10000` (or your configured PORT).
3. Log in with the Admin Email tab using the email from `ADMIN_EMAIL`.
4. Alternatively, use the Setup page to claim your admin access key.

---

## Environment Variables

Create a `.env` file in the project root:

```env
# Required in production
JWT_SECRET=your-secret-jwt-key-here
REDIRECTOR_SECRET=your-secret-redirector-key-here
REDIRECT_SECRET=your-secret-redirect-hmac-key-here

# Admin email (used for initial login)
ADMIN_EMAIL=admin@yourdomain.com

# Server
PORT=10000
NODE_ENV=production

# Optional: Dedicated link domain (separates tracking URLs from dashboard)
LINK_DOMAIN=links.yourdomain.com

# Optional: Northflank public hostname (for CNAME target in custom domain setup)
# Set this to your service's .code.run hostname, or set CNAME_TARGET explicitly.
NORTHFLANK_PUBLIC_DOMAIN=your-service.code.run

# Optional: Explicit platform CNAME target for custom domains
CNAME_TARGET=your-service.code.run

# Optional: Northflank API auto-registration for custom domains
NORTHFLANK_API_TOKEN=your-team-api-token
NORTHFLANK_PROJECT_ID=your-project-id
NORTHFLANK_SERVICE_ID=your-service-id
NORTHFLANK_PORT_NAME=p01
NORTHFLANK_VOLUME_MOUNT_PATH=/data

# Optional: Redis cache
REDIS_URL=redis://localhost:6379

# Optional: CORS
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Optional: Logging
LOG_DIR=/var/log/paris-engine
LOG_LEVEL=info
```

---

## API Reference

All API endpoints (except auth and health) require a JWT token in the `Authorization: Bearer <token>` header.

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/admin-email` | Login with admin email |
| POST | `/api/auth/access` | Login with access key |
| POST | `/api/admin/generate-key` | Generate access key for a user (admin only) |
| GET | `/api/setup/status` | Check if initial setup is needed |
| POST | `/api/setup/claim` | Claim initial admin access key |

### Link Management

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/links` | List all links for the authenticated user |
| POST | `/api/links` | Create a single link with rotation destinations |
| DELETE | `/api/links/:id` | Delete a link |
| PATCH | `/api/links/:id` | Update link tags and notes |
| PATCH | `/api/links/:id/status` | Pause or resume a link (`{ "active": true/false }`) |
| GET | `/api/links/search?q=term` | Search links by URL, tags, notes, or ID |
| POST | `/api/links/bulk-delete` | Delete multiple links at once |

### Batch Redirects

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/links/batch` | Create multiple redirect links at once |
| GET | `/api/links/batches` | List all batches with summary stats |
| GET | `/api/links/batch/:batchId` | Get all links in a specific batch |
| GET | `/api/links/batch/:batchId/html` | Export batch as HTML document |

### Analytics

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/links/:id/analytics` | Detailed click log for a specific link |
| GET | `/api/stats/dashboard` | Dashboard summary (total clicks, countries, referrers) |
| GET | `/api/stats/clicks-by-day?days=14` | Daily click breakdown |
| GET | `/api/stats/hourly?hours=24` | Hourly click breakdown |
| GET | `/api/stats/geo-summary` | Click geography summary |
| GET | `/api/stats/top-links?limit=10` | Top performing links |
| GET | `/api/stats/rate-summary` | Click rate (today, this week, this month) |
| GET | `/api/stats/export?days=30` | Export click data as JSON |
| GET | `/api/stats/bot-chains?days=7` | Bot redirect chain analytics (hops, unique bots, deepest chains) |

### Templates

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/templates` | List all saved templates |
| POST | `/api/templates` | Save a new template |
| GET | `/api/templates/:name` | Get a specific template |
| PUT | `/api/templates/:name/default` | Set a template as default |
| DELETE | `/api/templates/:name` | Delete a template |
| POST | `/api/templates/validate` | Validate template HTML |
| POST | `/api/templates/preview` | Preview processed template |
| GET | `/api/templates/tokens` | List supported template tokens |
| GET | `/api/templates/default-system` | Get the system default template |

### Custom Domains

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/domains` | List all custom domains |
| POST | `/api/domains` | Add a custom domain |
| PATCH | `/api/domains/:id` | Assign a template to a domain |
| DELETE | `/api/domains/:id` | Remove a custom domain |
| GET | `/api/domains/:id/dns-check` | Check DNS & SSL status |
| GET | `/api/northflank-status` | Check if Northflank auto-registration is configured |
| POST | `/api/domains/:id/northflank-register` | Retry Northflank domain registration |

### Short Links

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/short-links` | Create a short link |
| GET | `/api/short-links` | List all short links |
| GET | `/api/short-links/stats` | Short link statistics |
| GET | `/api/short-links/check/:slug` | Check if a slug is available |
| GET | `/api/short-links/:slug/analytics` | Analytics for a specific short link |
| PUT | `/api/short-links/:slug` | Update a short link |
| DELETE | `/api/short-links/:slug` | Delete a short link |

### Other

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check (returns `{ status: 'ok' }`) |
| GET | `/api/me` | Current user profile |
| GET | `/api/dns/cname-target` | Get CNAME target for custom domain setup |

### Tracking Routes (Public)

These routes are hit by visitors clicking tracking links:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/p/:token` | Email-safe tracking URL (primary) |
| GET | `/tr/v1/:id` | Legacy tracking URL |
| GET | `/s/:slug` | Short link redirect |
| GET | `/sr/:token` | Safe redirect chain hop (bots cycle through these) |
| POST | `/tr/v2/unlock` | Unlock endpoint (called by client-side script) |

---

## Custom HTML Templates

You can upload custom HTML templates that are displayed during the redirect process. Templates are sanitized to prevent unauthorized redirects while preserving visual design.

### Supported Tokens

Use these tokens in your HTML and they will be replaced at render time:

| Token | Description |
|---|---|
| `%%DESTINATION_URL%%` | The destination URL placeholder (set to `#` in cloaked mode) |
| `%%RAY_ID%%` | Unique request identifier |
| `%%TIMESTAMP%%` | Current Unix timestamp |
| `%%LINK_ID%%` | The tracking link ID |
| `%%COUNTRY%%` | Visitor's country code |
| `%%DOMAIN%%` | Current domain name |

### Template Priority

When resolving which template to show, the system checks in this order:

1. **Link-level template** — Template assigned directly to the link
2. **Domain-level template** — Template assigned to the custom domain the request came through
3. **User's default template** — The user's default template
4. **System default** — Built-in security check page with captcha

### What Gets Sanitized

- `<meta http-equiv="refresh">` tags are removed
- `window.location`, `document.location`, `location.href` assignments are neutralized
- `window.open()`, `history.pushState()`, `history.replaceState()` are blocked
- `javascript:` URLs are replaced with `#`
- Inline event handlers containing redirect keywords are stripped
- `<base href>` tags are removed
- `setTimeout` and `setInterval` are disabled (to prevent hide-content animations)
- Base64/hex obfuscated code is recursively decoded and sanitized

---

## Custom Domains

You can add custom domains for link generation and tracking. Each domain can have a purpose:

- **`link`** — Used for tracking URLs. The dashboard is hidden on link domains (404 for all non-tracking paths).
- **`web`** — Used for the dashboard/web interface.

### Setup

1. Deploy the service on Northflank from this repository using a Node/buildpack service. Keep the start command as `npm start`, expose port `p01`, and set the HTTP health check path to `/health`.
2. Set `NORTHFLANK_PUBLIC_DOMAIN` to the service `.code.run` hostname, or set `CNAME_TARGET` explicitly.
3. Add your custom domain via the dashboard or API.
4. In Northflank, go to Project → Service → Ports & DNS and link the verified domain/subdomain to the service port.
5. Create a CNAME record pointing to your Northflank `.code.run` hostname (shown in DNS check).
6. If using Cloudflare: enable proxy (orange cloud), set SSL to "Full" or "Full (Strict)".
7. Run the DNS check endpoint to verify.

`northflank.json` is included as a template for Northflank's Infrastructure as Code import. Replace its placeholder `vcsData.projectUrl`, project id, branch, and billing plan with your real Northflank/GitHub values. If your workspace requires different template fields, mirror the dashboard setup above and keep the service command as `npm start`.

---

## Short Links

Short links (`/s/{slug}`) provide simple URL shortening with:

- Custom aliases or auto-generated slugs
- Click tracking and analytics
- Bot detection (bots see a scanner-safe page, humans get redirected)
- Template-based redirect pages

---

## License

MIT