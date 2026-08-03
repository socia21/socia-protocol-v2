const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const httpProxy = require('http-proxy');
const fs = require('fs');
require('dotenv').config();

const app = express();
const proxy = httpProxy.createProxyServer({});
const PORT = process.env.PORT || 8000;
const PYTHON_PORT = 8001;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. Health check for Railway
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'online', protocol: 'SOCIA Escrow Engine' });
});

// 2. Proxy API and Auth requests to FastAPI running on port 8001
app.all(['/api*', '/auth*'], (req, res) => {
  proxy.web(req, res, { target: `http://127.0.0.1:${PYTHON_PORT}` }, (err) => {
    res.status(502).json({ error: 'Backend protocol service unavailable.' });
  });
});

// 3. Serve static frontend files
app.use(express.static(path.join(__dirname)));

// 4. Fallback to index.html for frontend single-page routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Resolve the correct python executable or virtual environment path automatically
const pythonCmd = fs.existsSync('/opt/venv/bin/python') ? '/opt/venv/bin/python' : 'python3';

// Spawn Python FastAPI child process safely using explicit paths
const pythonProcess = spawn(pythonCmd, ['-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', PYTHON_PORT.toString()], {
  stdio: ['inherit', 'inherit', 'pipe'],
  shell: false,
  env: { ...process.env, PYTHONUNBUFFERED: "true" }
});

pythonProcess.stderr.on('data', (data) => {
  console.error(`[FastAPI Error]: ${data.toString()}`);
});

pythonProcess.on('exit', (code, signal) => {
  console.error(`[FastAPI Process exited with code ${code} and signal ${signal}]`);
});

app.listen(PORT, () => {
  console.log(`[SOCIA GATEWAY] Node server active on port ${PORT}. Proxying API to FastAPI on port ${PYTHON_PORT}.`);
});
```[cite: 2, 3]