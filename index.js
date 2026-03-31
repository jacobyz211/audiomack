const express = require('express');
const cors    = require('cors');
const axios   = require('axios');
const crypto  = require('crypto');
const Redis   = require('ioredis');

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

// ─── Jamendo client_id (register free at devportal.jamendo.com) ───────────────
const JAMENDO_CLIENT_ID = process.env.JAMENDO_CLIENT_ID || null;

if (JAMENDO_CLIENT_ID) {
  console.log('[Jamendo] client_id loaded from environment.');
} else {
  console.warn('[Jamendo] WARNING: JAMENDO_CLIENT_ID not set. Search/stream will fail until you add it to Render env vars.');
}

// ─── Redis ────────────────────────────────────────────────────────────────────
let redis = null;
if (process.env.REDIS_URL) {
  redis = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 3, enableReadyCheck: false });
  redis.on('connect', function() { console.log('[Redis] Connected'); });
  redis.on('error',   function(e) { console.error('[Redis] ' + e.message); });
} else {
  console.warn('[Redis] No REDIS_URL — tokens will not persist across restarts.');
}

async function redisSave(token, entry) {
  if (!redis) return;
  try {
    await redis.set('jm:token:' + token, JSON.stringify({
      createdAt: entry.createdAt, lastUsed: entry.lastUsed, reqCount: entry.reqCount
    }));
  } catch (e) { console.error('[Redis] Save: ' + e.message); }
}

async function redisLoad(token) {
  if (!redis) return null;
  try { var d = await redis.get('jm:token:' + token); return d ? JSON.parse(d) : null; }
  catch (e) { return null; }
}

// ─── Token store ──────────────────────────────────────────────────────────────
const TOKEN_CACHE = new Map();
const IP_CREATES  = new Map();
const RATE_MAX       = 60;
const RATE_WINDOW_MS = 60000;

function generateToken() { return crypto.randomBytes(14).toString('hex'); }

function getOrCreateIpBucket(ip) {
  var now = Date.now(); var b = IP_CREATES.get(ip);
  if (!b || now > b.resetAt) { b = { count: 0, resetAt: now + 86400000 }; IP_CREATES.set(ip, b); }
  return b;
}

async function getTokenEntry(token) {
  if (TOKEN_CACHE.has(token)) return TOKEN_CACHE.get(token);
  var saved = await redisLoad(token);
  if (!saved) return null;
  var entry = { createdAt: saved.createdAt, lastUsed: saved.lastUsed, reqCount: saved.reqCount || 0, rateWin: [] };
  TOKEN_CACHE.set(token, entry); return entry;
}

function checkRateLimit(entry) {
  var now = Date.now();
  entry.rateWin = (entry.rateWin || []).filter(function(t) { return now - t < RATE_WINDOW_MS; });
  if (entry.rateWin.length >= RATE_MAX) return false;
  entry.rateWin.push(now); entry.lastUsed = now; entry.reqCount = (entry.reqCount || 0) + 1; return true;
}

async function tokenMiddleware(req, res, next) {
  var entry = await getTokenEntry(req.params.token);
  if (!entry) return res.status(404).json({ error: 'Invalid token. Generate a new one at ' + getBaseUrl(req) });
  if (!checkRateLimit(entry)) return res.status(429).json({ error: 'Rate limit exceeded (60 req/min).' });
  req.tokenEntry = entry;
  if (entry.reqCount % 20 === 0) redisSave(req.params.token, entry);
  next();
}

function getBaseUrl(req) {
  return (req.headers['x-forwarded-proto'] || req.protocol) + '://' + req.get('host');
}

// ─── Jamendo API ─────────────────────────────────────────────────────────────
var JM_BASE = 'https://api.jamendo.com/v3.0';

async function jmGet(path, params) {
  if (!JAMENDO_CLIENT_ID) throw new Error('JAMENDO_CLIENT_ID not configured on server.');
  var p = Object.assign({ client_id: JAMENDO_CLIENT_ID, format: 'json' }, params || {});
  var qs = Object.keys(p).map(function(k) { return encodeURIComponent(k) + '=' + encodeURIComponent(p[k]); }).join('&');
  var res = await axios.get(JM_BASE + path + '?' + qs, {
    headers: { 'User-Agent': 'EclipseAddon/1.0', 'Accept': 'application/json' },
    timeout: 10000,
    responseType: 'text'
  });
  var body = res.data;
  return typeof body === 'string' ? JSON.parse(body) : body;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function cleanText(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }

function mapTrack(t) {
  if (!t || !t.id) return null;
  return {
    id:         String(t.id),
    title:      cleanText(t.name)        || 'Unknown Title',
    artist:     cleanText(t.artist_name) || 'Unknown Artist',
    album:      cleanText(t.album_name)  || null,
    duration:   t.duration ? parseInt(t.duration, 10) : null,
    artworkURL: t.album_image || t.image || null,
    format:     'mp3'
  };
}

// ─── Config page ─────────────────────────────────────────────────────────────
function buildConfigPage(baseUrl) {
  var ready       = !!JAMENDO_CLIENT_ID;
  var statusBadge = ready
    ? '<span class="pill green">\u2713 Server ready</span>'
    : '<span class="pill red">\u26a0 Not configured \u2014 contact addon owner</span>';

  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Eclipse \u2022 Jamendo Addon</title><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0f0f0f;color:#e8e8e8;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:48px 20px 64px}.logo{margin-bottom:20px}.card{background:#161616;border:1px solid #232323;border-radius:18px;padding:36px;max-width:520px;width:100%;box-shadow:0 24px 64px rgba(0,0,0,.5)}h1{font-size:22px;font-weight:700;margin-bottom:6px;color:#fff}p.sub{font-size:14px;color:#777;margin-bottom:22px;line-height:1.6}.pills{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:32px}.pill{border-radius:20px;font-size:11px;font-weight:600;padding:4px 10px;background:#0f1a0f;color:#5fd45f;border:1px solid #1a3a1a}.pill.green{background:#0d1f0d;color:#6db86d;border-color:#1e3a1e}.pill.red{background:#1f0d0d;color:#e06060;border-color:#3a1e1e}button.primary{width:100%;background:#1db954;border:none;border-radius:10px;color:#fff;font-size:15px;font-weight:700;padding:14px;cursor:pointer;transition:background .15s;margin-bottom:18px}button.primary:hover{background:#17a349}button.primary:disabled{background:#252525;color:#444;cursor:not-allowed}.result{display:none;background:#0f0f0f;border:1px solid #1e1e1e;border-radius:12px;padding:18px;margin-bottom:18px}.rlabel{font-size:10px;color:#555;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}.rurl{font-size:12px;color:#1db954;word-break:break-all;font-family:"SF Mono",monospace;margin-bottom:14px;line-height:1.5}button.copy{width:100%;background:#1a1a1a;border:1px solid #222;border-radius:8px;color:#aaa;font-size:13px;font-weight:600;padding:10px;cursor:pointer;transition:all .15s}button.copy:hover{background:#202020;color:#fff}.divider{border:none;border-top:1px solid #1a1a1a;margin:28px 0}.steps{display:flex;flex-direction:column;gap:14px}.step{display:flex;gap:14px;align-items:flex-start}.step-n{background:#1a1a1a;border:1px solid #252525;border-radius:50%;width:26px;height:26px;min-width:26px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#666}.step-t{font-size:13px;color:#666;line-height:1.6}.step-t strong{color:#aaa}.note{background:#0a180a;border:1px solid #1a3a1a;border-radius:10px;padding:14px 16px;margin-top:24px;font-size:12px;color:#4a8a4a;line-height:1.7}footer{margin-top:36px;font-size:12px;color:#333;text-align:center}</style></head><body>'
    + '<svg class="logo" width="52" height="52" viewBox="0 0 52 52" fill="none"><circle cx="26" cy="26" r="26" fill="#1db954"/><text x="26" y="34" font-family="Arial Black,sans-serif" font-size="16" font-weight="900" fill="#fff" text-anchor="middle">JAM</text></svg>'
    + '<div class="card"><h1>Jamendo for Eclipse</h1><p class="sub">Get your personal Jamendo addon URL for Eclipse. No login needed \u2014 just click Generate and you\u2019re done.</p>'
    + '<div class="pills"><span class="pill green">\u2713 No signup needed</span><span class="pill">\u2713 Full tracks</span><span class="pill">\u2713 Unique per user</span><span class="pill">\u2713 Persists across restarts</span>' + statusBadge + '</div>'
    + '<button class="primary" id="genBtn" onclick="generate()" ' + (ready ? '' : 'disabled') + '>' + (ready ? 'Generate My Addon URL' : 'Server not ready') + '</button>'
    + '<div class="result" id="result"><div class="rlabel">Your addon URL \u2014 paste this into Eclipse</div><div class="rurl" id="rurl"></div><button class="copy" onclick="copyUrl()">\u29c3 Copy URL</button></div>'
    + '<hr class="divider"><div class="steps">'
    + '<div class="step"><div class="step-n">1</div><div class="step-t">Click Generate and copy your URL</div></div>'
    + '<div class="step"><div class="step-n">2</div><div class="step-t">Open <strong>Eclipse Music</strong> \u2192 Library \u2192 Cloud \u2192 Add Connection \u2192 Addon</div></div>'
    + '<div class="step"><div class="step-n">3</div><div class="step-t">Paste your URL and tap Install</div></div>'
    + '<div class="step"><div class="step-n">4</div><div class="step-t"><strong>Jamendo</strong> appears in your search \u2014 full tracks, Creative Commons music</div></div>'
    + '</div><div class="note">\u2139\ufe0f Jamendo hosts 600,000+ free, legal, full-length tracks under Creative Commons licenses. Your URL is saved to Redis and survives server restarts.</div>'
    + '</div><footer>Eclipse Jamendo Addon \u2022 ' + baseUrl + '</footer>'
    + '<script>var gurl="";function generate(){var btn=document.getElementById("genBtn");btn.disabled=true;btn.textContent="Generating...";fetch("/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({})}).then(function(r){return r.json();}).then(function(d){if(d.error){alert(d.error);btn.disabled=false;btn.textContent="Generate My Addon URL";return;}gurl=d.manifestUrl;document.getElementById("rurl").textContent=gurl;document.getElementById("result").style.display="block";btn.textContent="Regenerate URL";btn.disabled=false;}).catch(function(e){alert("Failed: "+e.message);btn.disabled=false;btn.textContent="Generate My Addon URL";});}function copyUrl(){if(!gurl)return;navigator.clipboard.writeText(gurl).then(function(){var b=document.querySelector(".copy");b.textContent="Copied!";setTimeout(function(){b.textContent="\u29c3 Copy URL";},1500);});}<\/script></body></html>';
}

// ─── Routes ──────────────────────────────────────────────────────────────────

app.get('/', function(req, res) {
  res.setHeader('Content-Type', 'text/html');
  res.send(buildConfigPage(getBaseUrl(req)));
});

app.post('/generate', async function(req, res) {
  if (!JAMENDO_CLIENT_ID) return res.status(503).json({ error: 'Server not configured yet. The addon owner needs to set JAMENDO_CLIENT_ID in Render env vars.' });

  var ip     = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  var bucket = getOrCreateIpBucket(ip);
  if (bucket.count >= 10) return res.status(429).json({ error: 'Too many tokens from this IP today.' });

  var token = generateToken();
  var entry = { createdAt: Date.now(), lastUsed: Date.now(), reqCount: 0, rateWin: [] };
  TOKEN_CACHE.set(token, entry);
  await redisSave(token, entry);
  bucket.count++;

  console.log('[TOKEN] Created. IP: ' + ip + ' | total: ' + TOKEN_CACHE.size);
  res.json({ token: token, manifestUrl: getBaseUrl(req) + '/u/' + token + '/manifest.json' });
});

app.get('/u/:token/manifest.json', tokenMiddleware, function(req, res) {
  res.json({
    id:          'com.eclipse.jamendo.' + req.params.token.slice(0, 8),
    name:        'Jamendo',
    version:     '1.0.0',
    description: 'Search and stream 600,000+ free full-length tracks from Jamendo.',
    icon:        'https://www.jamendo.com/favicon.ico',
    resources:   ['search', 'stream'],
    types:       ['track']
  });
});

// Search — GET /tracks with full audio URLs
app.get('/u/:token/search', tokenMiddleware, async function(req, res) {
  var q = cleanText(req.query.q || '');
  if (!q) return res.json({ tracks: [] });
  try {
    var data   = await jmGet('/tracks/', {
      search:       q,
      limit:        25,
      include:      'musicinfo',
      audioformat:  'mp32',
      order:        'relevance'
    });
    var results = (data && data.results) ? data.results : [];
    var tracks  = results.map(mapTrack).filter(Boolean);
    console.log('[/search] q="' + q + '" \u2192 ' + tracks.length + ' results');
    res.json({ tracks: tracks });
  } catch (err) {
    console.error('[/search] ' + err.message);
    res.status(500).json({ error: 'Search failed: ' + err.message, tracks: [] });
  }
});

// Stream — fetch fresh audio URL for the track ID
app.get('/u/:token/stream/:id', tokenMiddleware, async function(req, res) {
  var id = req.params.id;
  if (!id || !/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid track ID.' });
  try {
    var data    = await jmGet('/tracks/', { id: id, audioformat: 'mp32', include: 'musicinfo' });
    var results = (data && data.results) ? data.results : [];
    var track   = results[0];
    if (!track) return res.status(404).json({ error: 'Track not found on Jamendo.' });

    // audio field is the full MP3 stream URL
    var streamUrl = track.audio || track.audiodownload;
    if (!streamUrl) return res.status(404).json({ error: 'No audio URL available for this track.' });

    console.log('[/stream] OK id=' + id + ' | ' + cleanText(track.name));
    res.json({
      url:      streamUrl,
      format:   'mp3',
      duration: track.duration ? parseInt(track.duration, 10) : null
    });
  } catch (err) {
    console.error('[/stream] ' + err.message);
    res.status(500).json({ error: 'Stream failed: ' + err.message });
  }
});

app.get('/health', function(_req, res) {
  res.json({
    status:           'ok',
    clientIdReady:    !!JAMENDO_CLIENT_ID,
    redisConnected:   !!(redis && redis.status === 'ready'),
    activeTokens:     TOKEN_CACHE.size,
    uptime:           Math.floor(process.uptime()) + 's'
  });
});

app.listen(PORT, function() {
  console.log('Eclipse Jamendo Addon on port ' + PORT);
});
