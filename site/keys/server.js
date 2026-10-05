const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const KOUZZLE_HOST = process.env.KOUZZLE_HOST || '127.0.0.1';
const KOUZZLE_PORT = Number(process.env.KOUZZLE_PORT || 7512);
const KOUZZLE_KEY = process.env.KOUZZLE_ADMIN_KEY;
const INDEX = process.env.KEYS_INDEX || 'sleeps_tmc_dev';
const COLLECTION = process.env.KEYS_COLLECTION || 'players';
const ALLOWED_NETWORKS = (process.env.ALLOWED_NETWORKS || '127.0.0.1').split(',').map(s => s.trim()).filter(Boolean);

if (!KOUZZLE_KEY) {
  console.error('KOUZZLE_ADMIN_KEY is required');
  process.exit(1);
}

function kuzzle(method, kpath, body) {
  return new Promise((resolve, reject) => {
    const url = `http://${KOUZZLE_HOST}:${KOUZZLE_PORT}${kpath}`;
    const data = body ? JSON.stringify(body) : undefined;
    const req = http.request(url, {
      method,
      headers: {
        'Authorization': `Bearer ${KOUZZLE_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': data ? Buffer.byteLength(data) : 0
      }
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, body }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function randomPassword() {
  return 'svc-' + Math.random().toString(36).slice(2) + '!';
}

function mint() {
  const userBody = { content: { profileIds: [ INDEX + '-mint-profile' ] } };
  return kuzzle('POST', '/users/_create', userBody)
    .then(r => {
      const kuid = (r.body && r.body.result && r.body.result._id) || null;
      if (!kuid) throw new Error('user create failed: ' + JSON.stringify(r.body));
      return kuid;
    });
}

function setCredentials(kuid, password) {
  return kuzzle('POST', `/credentials/local/${kuid}/_create`, { username: kuid, password });
}

function mintKey(password) {
  return kuzzle('POST', `/users/${encodeURIComponent(kuid)}/api-keys/_create`,
    { description: INDEX + '-' + COLLECTION + '-devkey' });
}

const server = http.createServer(async (req, res) => {
  const remote = req.socket.remoteAddress || '';
  if (!ALLOWED_NETWORKS.some(n => remote.endsWith(n) || n === remote)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('forbidden');
  }

  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    fs.readFile(path.join(__dirname, 'index.html'), 'utf8', (err, html) => {
      if (err) { res.writeHead(500); return res.end('error'); }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html.replace('<%= INDEX %>', INDEX).replace('<%= COLLECTION %>', COLLECTION));
    });
    return;
  }

  if (req.method === 'POST' && req.url === '/keys/mint') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      let expiresIn = '12h';
      try {
        const parsed = JSON.parse(body);
        if (parsed && parsed.expiresIn) expiresIn = parsed.expiresIn;
      } catch {}
      try {
        const kuid = await mint();
        const password = randomPassword();
        await setCredentials(kuid, password);
        const keyBody = { description: INDEX + '-devkey' };
        const keyUrl = `/users/${encodeURIComponent(kuid)}/api-keys/_create`;
        if (expiresIn) keyUrl += '?expiresIn=' + encodeURIComponent(expiresIn);
        const keyResp = await kuzzle('POST', keyUrl, keyBody);
        const token = (keyResp.body && keyResp.body.result && keyResp.body.result.token) || null;
        const keyId = (keyResp.body && keyResp.body.result && keyResp.body.result._id) || null;
        if (!token) throw new Error('key create failed: ' + JSON.stringify(keyResp.body));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, keyId, index: INDEX, collection: COLLECTION, expiresIn }, null, 2));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: e && e.message ? e.message : String(e) }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('not found');
});

server.listen(PORT, () => console.log('keys page listening on :' + PORT));
