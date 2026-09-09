const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const httpProxy = require('http-proxy');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const proxy = httpProxy.createProxyServer({});
const PORT = process.env.PORT || 8000;
const PYTHON_PORT = 8001;

// Trust Railway's proxy layer so rate limiting and logging see the real client IP,
// not Railway's internal proxy IP for every single request.
app.set('trust proxy', 1);

// --- SECURITY HEADERS ---
// CSP is disabled for now: the app uses inline <script> blocks throughout, which a
// strict CSP would silently break. A proper fix means adding nonces to every inline
// script — worth doing later, but not swapped in blind right now since it would need
// testing against every page. Every other helmet protection (HSTS, X-Frame-Options,
// X-Content-Type-Options, etc.) is still active.
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

// --- RATE LIMITING (second layer, behind Cloudflare) ---
// Generous global limit — this exists to blunt anything Cloudflare's edge rules miss,
// not to be the primary defense. Auth routes get a stricter limit since they're the
// highest-value target for brute force / credential stuffing.
const globalLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' },
});
app.use(globalLimiter);
app.use('/auth', authLimiter);

// IMPORTANT: proxy routes must be registered BEFORE express.json()/urlencoded()
// Otherwise Express consumes the request body stream, and the proxy forwards
// an empty body while still sending a Content-Length header — causing FastAPI
// to hang forever waiting for body bytes that will never arrive.
app.all(['/api*', '/auth*'], (req, res) => {
  proxy.web(req, res, { target: `http://127.0.0.1:${PYTHON_PORT}` }, (err) => {
    res.status(502).json({ error: 'Backend protocol service unavailable.' });
  });
});

// Explicit size limits — prevents a single request with a huge body from
// tying up server resources (a simple, cheap denial-of-service vector).
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'online', protocol: 'SOCIA Escrow Engine' });
});

app.get('/admin', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'terms.html'));
});

app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'privacy.html'));
});

// --- SEO: robots.txt, sitemap.xml, llms.txt ---
// robots.txt explicitly allows every major search-engine crawler AND the AI answer-engine
// crawlers (GPTBot, ChatGPT-User, ClaudeBot, PerplexityBot, Google-Extended, etc.) — these
// don't always inherit a bare "User-agent: *" allow the way search crawlers do, and some
// sites accidentally block them without realizing it, which is the single most common reason
// a site never shows up in AI-generated summaries at all.
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
`# SOCIA Protocol — every crawler below is explicitly welcomed, not just left to a bare
# wildcard. AI answer engines in particular don't always inherit a "User-agent: *" allow the
# way search crawlers do, so each is named individually — this is the single most common
# reason a site never gets cited in AI-generated summaries.

User-agent: *
Allow: /

# --- General search engines ---
User-agent: Googlebot
Allow: /

User-agent: Bingbot
Allow: /

User-agent: DuckDuckBot
Allow: /

User-agent: Applebot
Allow: /

# --- AI answer-engine / training crawlers ---
User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: OAI-SearchBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: Claude-SearchBot
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Perplexity-User
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: Applebot-Extended
Allow: /

User-agent: Amazonbot
Allow: /

User-agent: meta-externalagent
Allow: /

User-agent: FacebookBot
Allow: /

User-agent: YouBot
Allow: /

User-agent: DuckAssistBot
Allow: /

User-agent: cohere-ai
Allow: /

User-agent: CCBot
Allow: /

User-agent: Diffbot
Allow: /

User-agent: Bytespider
Allow: /

Sitemap: https://www.contactsocia.com/sitemap.xml`
  );
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').send(
`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://www.contactsocia.com/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://www.contactsocia.com/terms</loc>
    <changefreq>monthly</changefreq>
    <priority>0.3</priority>
  </url>
  <url>
    <loc>https://www.contactsocia.com/privacy</loc>
    <changefreq>monthly</changefreq>
    <priority>0.3</priority>
  </url>
</urlset>`
  );
});

// llms.txt: an emerging convention some AI crawlers and agent tools check for a clean,
// plain-text summary of a site, separate from the rendered HTML. Not a guarantee any given
// AI product reads it, but it's a free, low-risk signal to provide.
app.get('/llms.txt', (req, res) => {
  res.type('text/plain').send(
`# SOCIA Protocol

> SOCIA Protocol is an escrow-based marketplace that matches sponsors and influencers using an algorithmic compatibility engine, holding every payment in escrow until deliverables are approved.

SOCIA Protocol lets brands (sponsors) and influencers/content creators post listings, get algorithmically matched on niche, budget, audience size and engagement, platform overlap, brand safety, collaboration type and content format, content tone and values alignment, creative-control fit, turnaround time, and each account's real track record on SOCIA. Once a deal is agreed, the sponsor's payment is held in escrow and released to the influencer only after deliverables are approved.

## Key facts
- Free to create an account and publish a listing.
- Platform takes a small fee on escrow-settled deals; an optional paid "Sovereign Pass" subscription tier exists.
- Payments are protected by escrow — funds release only after deliverable approval.
- Matching is algorithmic, not manual browsing.

## Pages
- Homepage / app: https://www.contactsocia.com/
- Terms of Service: https://www.contactsocia.com/terms
- Privacy Policy: https://www.contactsocia.com/privacy`
  );
});

app.use(express.static(path.join(__dirname), { index: false }));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Instead of calling the external "uvicorn" command shell binary, 
// invoke python3 to run a mini inline script that executes uvicorn programmatically.
const pythonInlineRunner = `
import uvicorn
from main import app
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=${PYTHON_PORT})
`;

const pythonProcess = spawn('python3', ['-c', pythonInlineRunner], {
  stdio: 'inherit',
  shell: false,
  env: { ...process.env, PYTHONUNBUFFERED: "true" }
});

pythonProcess.on('error', (err) => {
  console.error('Failed to start FastAPI subprocess:', err);
});

app.listen(PORT, () => {
  console.log(`[SOCIA GATEWAY] Node server active on port ${PORT}. Proxying API to FastAPI on port ${PYTHON_PORT}.`);
});