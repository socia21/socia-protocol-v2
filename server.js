const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const httpProxy = require('http-proxy');
require('dotenv').config();

const app = express();
const proxy = httpProxy.createProxyServer({});
const PORT = process.env.PORT || 8000;
const PYTHON_PORT = 8001;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'online', protocol: 'SOCIA Escrow Engine' });
});

app.all(['/api*', '/auth*'], (req, res) => {
  proxy.web(req, res, { target: `http://127.0.0.1:${PYTHON_PORT}` }, (err) => {
    res.status(502).json({ error: 'Backend protocol service unavailable.' });
  });
});

app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const pythonProcess = spawn('uvicorn', ['main:app', '--host', '127.0.0.1', '--port', PYTHON_PORT.toString()], {
  stdio: 'inherit',
  shell: true
});

pythonProcess.on('error', (err) => {
  console.error('Failed to start FastAPI subprocess:', err);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SOCIA GATEWAY] Node server active on port ${PORT}. Proxying API to FastAPI on port ${PYTHON_PORT}.`);
});