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