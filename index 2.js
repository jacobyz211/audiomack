const express = require('express');
const cors    = require('cors');
const axios   = require('axios');
const crypto  = require('crypto');
const Redis   = require('ioredis');

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

// ─── Shared server credentials (fallback when user doesn't provide their own) ─
const SHARED_KEY    = process.env.AM_CONSUMER_KEY    || null;
const SHARED_SECRET = process.env.AM_CONSUMER_SECRET || null;

if (SHARED_KEY && SHARED_SECRET) {
  console.log('[AM] Shared Audiomack credentials loaded from environment.');
} else {
  console.warn('[AM] No shared credentials set. Users must provide their own keys.');
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
    await redis.set('am:token:' + token, JSON.stringify({
      consumerKey: entry.consumerKey, consumerSecret: entry.consumerSecret,
      createdAt: entry.createdAt, lastUsed: entry.lastUsed, reqCount: entry.reqCount
    }));
  } catch (e) { console.error('[Redis] Save: ' + e.message); }
}

async function redisLoad(token) {
  if (!redis) return null;
  try { var d = await redis.get('am:token:' + token); return d ? JSON.parse(d) : null; }
  catch (e) { return null; }
}

// ─── Token store ──────────────────────────────────────────────────────────────
const TOKEN_CACHE = new Map();
const IP_CREATES  = new Map();
const MAX_TOKENS_PER_IP = 10;
const RATE_MAX          = 60;
const RATE_WINDOW_MS    = 60000;

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
  var entry = { consumerKey: saved.consumerKey || null, consumerSecret: saved.consumerSecret || null, createdAt: saved.createdAt, lastUsed: saved.lastUsed, reqCount: saved.reqCount, rateWin: [] };
  TOKEN_CACHE.set(token, entry); return entry;
}

function checkRateLimit(entry) {
  var now = Date.now();
  entry.rateWin = (entry.rateWin || []).filter(function(t) { return now - t < RATE_WINDOW_MS; });
  if (entry.rateWin.length >= RATE_MAX) return false;
  entry.rateWin.push(now); entry.lastUsed = now; entry.reqCount = (entry.reqCount || 0) + 1; return true;
}

async function tokenMiddleware(req, res, next) {
  var token = req.params.token; var entry = await getTokenEntry(token);
  if (!entry) return res.status(404).json({ error: 'Invalid token. Generate a new one at ' + getBaseUrl(req) });
  if (!checkRateLimit(entry)) return res.status(429).json({ error: 'Rate limit exceeded (60 req/min).' });
  req.tokenEntry = entry;
  if (entry.reqCount % 20 === 0) redisSave(token, entry);
  next();
}

function getBaseUrl(req) { var proto = req.headers['x-forwarded-proto'] || req.protocol; return proto + '://' + req.get('host'); }

function effectiveCredentials(entry) {
  return {
    key:    (entry && entry.consumerKey)    ? entry.consumerKey    : SHARED_KEY,
    secret: (entry && entry.consumerSecret) ? entry.consumerSecret : SHARED_SECRET
  };
}

// ─── Audiomack OAuth 1.0a ─────────────────────────────────────────────────────
function enc(s) { return encodeURIComponent(String(s)); }

function oauthSign(method, url, params, key, secret) {
  var op = { oauth_consumer_key: key, oauth_nonce: crypto.randomBytes(16).toString('hex'), oauth_signature_method: 'HMAC-SHA1', oauth_timestamp: Math.floor(Date.now() / 1000).toString(), oauth_version: '1.0' };
  var all = Object.assign({}, params, op);
  var pstr = Object.keys(all).sort().map(function(k) { return enc(k) + '=' + enc(String(all[k])); }).join('&');
  var base = method.toUpperCase() + '&' + enc(url) + '&' + enc(pstr);
  op.oauth_signature = crypto.createHmac('sha1', enc(secret) + '&').update(base).digest('base64');
  return op;
}

function oauthHeader(op) {
  return 'OAuth ' + Object.keys(op).filter(function(k) { return k.indexOf('oauth_') === 0; }).map(function(k) { return k + '="' + enc(op[k]) + '"'; }).join(', ');
}

async function amGet(key, secret, path, params) {
  if (!key || !secret) throw new Error('No Audiomack credentials available.');
  params = params || {};
  var url = 'https://api.audiomack.com/v1' + path;
  var op  = oauthSign('GET', url, params, key, secret);
  var qs  = Object.keys(params).map(function(k) { return enc(k) + '=' + enc(params[k]); }).join('&');
  var res = await axios.get(url + (qs ? '?' + qs : ''), { headers: { 'Authorization': oauthHeader(op), 'User-Agent': 'EclipseAddon/1.0', 'Accept': 'application/json' }, timeout: 12000 });
  return res.data;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function cleanText(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }
function makeId(a, t) { return Buffer.from(a + '|' + t).toString('base64url'); }
function parseId(id) { try { var p = Buffer.from(id, 'base64url').toString().split('|'); return { artistSlug: p[0], trackSlug: p.slice(1).join('|') }; } catch (e) { return null; } }
function artworkUrl(img) { if (!img) return null; return String(img).replace('{w}', '500').replace('{h}', '500').replace(/\?.*$/, ''); }

// ─── Config page ──────────────────────────────────────────────────────────────
function buildConfigPage(baseUrl) {
  var sharedAvailable = !!(SHARED_KEY && SHARED_SECRET);
  var sharedBadge = sharedAvailable
    ? '<span class="pill green">\u2713 Shared keys available</span>'
    : '<span class="pill dim">\u25cb No shared keys \u2014 paste your own below</span>';

  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Eclipse \u2022 Audiomack Addon</title><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0f0f0f;color:#e8e8e8;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:48px 20px 64px}.logo{margin-bottom:20px}.card{background:#161616;border:1px solid #232323;border-radius:18px;padding:36px;max-width:540px;width:100%;box-shadow:0 24px 64px rgba(0,0,0,.5)}h1{font-size:22px;font-weight:700;margin-bottom:6px;color:#fff}p.sub{font-size:14px;color:#777;margin-bottom:22px;line-height:1.6}.pills{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:28px}.pill{border-radius:20px;font-size:11px;font-weight:600;padding:4px 10px;background:#1a1a14;color:#ffb300;border:1px solid #3a3000}.pill.green{background:#0d1f0d;color:#6db86d;border-color:#1e3a1e}.pill.dim{background:#1a1a1a;color:#555;border-color:#2a2a2a}.section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#555;margin-bottom:8px}.option-box{background:#0f0f0f;border:1px solid #1e1e1e;border-radius:12px;padding:16px;margin-bottom:16px}.option-box.active{border-color:#3a3000}.option-header{display:flex;align-items:center;gap:10px;margin-bottom:0;cursor:pointer;user-select:none}.option-radio{width:16px;height:16px;min-width:16px;border-radius:50%;border:2px solid #333;display:flex;align-items:center;justify-content:center;transition:border-color .15s}.option-radio.checked{border-color:#ffb300}.option-radio.checked::after{content:"";width:8px;height:8px;border-radius:50%;background:#ffb300}.option-label{font-size:14px;font-weight:600;color:#ccc}.option-sub{font-size:12px;color:#555;margin-top:3px;margin-left:26px}.option-fields{margin-top:14px;margin-left:0;display:none}.option-fields.show{display:block}input[type=text]{width:100%;background:#111;border:1px solid #222;border-radius:8px;color:#e8e8e8;font-size:14px;padding:11px 13px;margin-bottom:10px;outline:none;transition:border-color .15s}input[type=text]:focus{border-color:#ffb300}input[type=text]::placeholder{color:#333}.hint{font-size:12px;color:#444;margin-bottom:4px;line-height:1.7}.hint a{color:#ffb300;text-decoration:none}.hint code{background:#1a1a1a;padding:1px 5px;border-radius:4px;color:#777}button.primary{width:100%;background:#ffb300;border:none;border-radius:10px;color:#000;font-size:15px;font-weight:700;padding:14px;cursor:pointer;transition:background .15s;margin-top:8px;margin-bottom:18px}button.primary:hover{background:#e6a000}button.primary:disabled{background:#252525;color:#444;cursor:not-allowed}.result{display:none;background:#0f0f0f;border:1px solid #1e1e1e;border-radius:12px;padding:18px;margin-bottom:18px}.rlabel{font-size:10px;color:#555;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}.rurl{font-size:12px;color:#ffb300;word-break:break-all;font-family:"SF Mono",monospace;margin-bottom:14px;line-height:1.5}button.copy{width:100%;background:#1a1a1a;border:1px solid #222;border-radius:8px;color:#aaa;font-size:13px;font-weight:600;padding:10px;cursor:pointer;transition:all .15s}button.copy:hover{background:#202020;color:#fff}.divider{border:none;border-top:1px solid #1a1a1a;margin:28px 0}.steps{display:flex;flex-direction:column;gap:14px}.step{display:flex;gap:14px;align-items:flex-start}.step-n{background:#1a1a1a;border:1px solid #252525;border-radius:50%;width:26px;height:26px;min-width:26px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#666}.step-t{font-size:13px;color:#666;line-height:1.6}.step-t strong{color:#aaa}.warn{background:#140f00;border:1px solid #2e2000;border-radius:10px;padding:14px 16px;margin-top:24px;font-size:12px;color:#8a6a00;line-height:1.7}footer{margin-top:36px;font-size:12px;color:#333;text-align:center}</style></head><body><svg class="logo" width="52" height="52" viewBox="0 0 52 52" fill="none"><circle cx="26" cy="26" r="26" fill="#ffb300"/><text x="26" y="34" font-family="Arial Black,sans-serif" font-size="22" font-weight="900" fill="#000" text-anchor="middle">am</text></svg><div class="card"><h1>Audiomack for Eclipse</h1><p class="sub">Generate your personal addon URL. Use the shared server keys or bring your own for full independence.</p><div class="pills"><span class="pill">\u2713 Unique per user</span><span class="pill">\u2713 Persists across restarts</span>' + sharedBadge + '</div><div class="section-title">Choose your setup</div><div class="option-box active" id="box-shared" onclick="selectMode(\'shared\')""><div class="option-header"><div class="option-radio checked" id="radio-shared"></div><div><div class="option-label">Use shared keys</div><div class="option-sub">No setup needed. May share rate limits with other users.</div></div></div></div><div class="option-box" id="box-own" onclick="selectMode(\'own\')"><div class="option-header"><div class="option-radio" id="radio-own"></div><div><div class="option-label">Use my own API keys</div><div class="option-sub">Completely independent. Free at audiomack.com/data-api/docs</div></div></div><div class="option-fields" id="own-fields"><div style="height:12px"></div><input type="text" id="consumerKey" placeholder="Consumer Key"><input type="text" id="consumerSecret" placeholder="Consumer Secret"><div class="hint">Go to <a href="https://audiomack.com/data-api/docs" target="_blank">audiomack.com/data-api/docs</a> \u2192 sign up \u2192 create an app \u2192 copy your <code>Consumer Key</code> and <code>Consumer Secret</code>.</div></div></div><button class="primary" id="genBtn" onclick="generate()">Generate My Addon URL</button><div class="result" id="result"><div class="rlabel">Your addon URL \u2014 paste this into Eclipse</div><div class="rurl" id="rurl"></div><button class="copy" onclick="copyUrl()">\u29c3 Copy URL</button></div><hr class="divider"><div class="steps"><div class="step"><div class="step-n">1</div><div class="step-t">Generate and copy your URL above</div></div><div class="step"><div class="step-n">2</div><div class="step-t">Open <strong>Eclipse Music</strong> \u2192 Library \u2192 Cloud \u2192 Add Connection \u2192 Addon</div></div><div class="step"><div class="step-n">3</div><div class="step-t">Paste your URL and tap Install</div></div><div class="step"><div class="step-n">4</div><div class="step-t"><strong>Audiomack</strong> appears in your search with full catalog access</div></div></div><div class="warn">\u26a0\ufe0f Your URL is saved to Redis and survives restarts. Bookmark this page to regenerate if needed.</div></div><footer>Eclipse Audiomack Addon \u2022 ' + baseUrl + '</footer><script>var gurl="";var mode="shared";function selectMode(m){mode=m;document.getElementById("radio-shared").className="option-radio"+(m==="shared"?" checked":"");document.getElementById("radio-own").className="option-radio"+(m==="own"?" checked":"");document.getElementById("box-shared").className="option-box"+(m==="shared"?" active":"");document.getElementById("box-own").className="option-box"+(m==="own"?" active":"");document.getElementById("own-fields").className="option-fields"+(m==="own"?" show":"");}function generate(){var btn=document.getElementById("genBtn");var key=mode==="own"?document.getElementById("consumerKey").value.trim():null;var secret=mode==="own"?document.getElementById("consumerSecret").value.trim():null;if(mode==="own"&&(!key||!secret)){alert("Please enter both Consumer Key and Consumer Secret.");return;}btn.disabled=true;btn.textContent="Generating...";fetch("/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({consumerKey:key,consumerSecret:secret})}).then(function(r){return r.json();}).then(function(d){if(d.error){alert(d.error);btn.disabled=false;btn.textContent="Generate My Addon URL";return;}gurl=d.manifestUrl;document.getElementById("rurl").textContent=gurl;document.getElementById("result").style.display="block";btn.textContent="Regenerate URL";btn.disabled=false;}).catch(function(e){alert("Failed: "+e.message);btn.disabled=false;btn.textContent="Generate My Addon URL";});}function copyUrl(){if(!gurl)return;navigator.clipboard.writeText(gurl).then(function(){var b=document.querySelector(".copy");b.textContent="Copied!";setTimeout(function(){b.textContent="\u29c3 Copy URL";},1500);});}<\/script></body></html>';
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/', function(req, res) {
  res.setHeader('Content-Type', 'text/html');
  res.send(buildConfigPage(getBaseUrl(req)));
});

app.post('/generate', async function(req, res) {
  var ip     = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  var bucket = getOrCreateIpBucket(ip);
  if (bucket.count >= MAX_TOKENS_PER_IP) return res.status(429).json({ error: 'Too many tokens from this IP today.' });

  var consumerKey    = req.body && req.body.consumerKey    ? String(req.body.consumerKey).trim()    : null;
  var consumerSecret = req.body && req.body.consumerSecret ? String(req.body.consumerSecret).trim() : null;

  // If user provided keys, validate them
  if (consumerKey || consumerSecret) {
    if (!consumerKey || !consumerSecret) return res.status(400).json({ error: 'Provide both Consumer Key and Consumer Secret, or neither.' });
    if (consumerKey.length < 10 || consumerSecret.length < 10) return res.status(400).json({ error: 'Keys look too short. Double-check your Audiomack credentials.' });
    // Quick API test
    try {
      await amGet(consumerKey, consumerSecret, '/music/search', { q: 'test', type: 'song', limit: 1 });
    } catch (err) {
      var s = err.response && err.response.status;
      if (s === 401 || s === 403) return res.status(400).json({ error: 'Invalid API credentials. Check your Consumer Key and Secret.' });
      console.warn('[generate] API test non-auth error: ' + err.message);
    }
  } else {
    // Using shared keys — make sure they exist
    if (!SHARED_KEY || !SHARED_SECRET) return res.status(503).json({ error: 'No shared keys configured on this server. Please provide your own Consumer Key and Secret.' });
    consumerKey    = null; // stored as null = use shared
    consumerSecret = null;
  }

  var token = generateToken();
  var entry = { consumerKey: consumerKey, consumerSecret: consumerSecret, createdAt: Date.now(), lastUsed: Date.now(), reqCount: 0, rateWin: [] };
  TOKEN_CACHE.set(token, entry);
  await redisSave(token, entry);
  bucket.count++;

  var manifestUrl = getBaseUrl(req) + '/u/' + token + '/manifest.json';
  console.log('[TOKEN] Created. IP: ' + ip + ' | ownKeys: ' + !!(consumerKey) + ' | total: ' + TOKEN_CACHE.size);
  res.json({ token: token, manifestUrl: manifestUrl });
});

app.get('/u/:token/manifest.json', tokenMiddleware, function(req, res) {
  res.json({
    id:          'com.eclipse.audiomack.' + req.params.token.slice(0, 8),
    name:        'Audiomack',
    version:     '1.2.0',
    description: 'Search and stream Audiomack — hip-hop, Afrobeats, R&B and independent music.',
    icon:        'https://audiomack.com/static/favicon/favicon-96x96.png',
    resources:   ['search', 'stream'],
    types:       ['track']
  });
});

app.get('/u/:token/search', tokenMiddleware, async function(req, res) {
  var q = cleanText(req.query.q || '');
  if (!q) return res.json({ tracks: [] });
  var creds = effectiveCredentials(req.tokenEntry);
  if (!creds.key || !creds.secret) return res.status(503).json({ error: 'No Audiomack credentials available.', tracks: [] });
  try {
    var data    = await amGet(creds.key, creds.secret, '/music/search', { q: q, type: 'song', limit: 20 });
    var results = (data && data.results) ? data.results : (Array.isArray(data) ? data : []);
    var tracks  = results.map(function(t) {
      return {
        id:         makeId(cleanText(t.artist_slug || t.url_slug || ''), cleanText(t.url_slug || '')),
        title:      cleanText(t.title)  || 'Unknown Title',
        artist:     cleanText(t.artist) || 'Unknown Artist',
        album:      cleanText(t.album)  || null,
        duration:   t.duration ? parseInt(t.duration, 10) : null,
        artworkURL: artworkUrl(t.image || t.artwork_url),
        format:     'mp3'
      };
    }).filter(function(t) { return t.id; });
    res.json({ tracks: tracks });
  } catch (err) {
    console.error('[/search] ' + err.message);
    var s = err.response && err.response.status;
    if (s === 401 || s === 403) return res.status(401).json({ error: 'Audiomack credentials invalid. Regenerate your addon URL with valid keys.', tracks: [] });
    res.status(500).json({ error: 'Search failed.', tracks: [] });
  }
});

app.get('/u/:token/stream/:id', tokenMiddleware, async function(req, res) {
  var creds  = effectiveCredentials(req.tokenEntry);
  if (!creds.key || !creds.secret) return res.status(503).json({ error: 'No Audiomack credentials available.' });
  var parsed = parseId(req.params.id);
  if (!parsed) return res.status(400).json({ error: 'Invalid track ID.' });
  try {
    var data      = await amGet(creds.key, creds.secret, '/music/' + enc(parsed.artistSlug) + '/' + enc(parsed.trackSlug), { hq: 1 });
    var streamUrl = data && (data.stream_url || data.audio || data.url);
    if (!streamUrl) return res.status(404).json({ error: 'No stream URL returned by Audiomack.' });
    console.log('[/stream] OK: ' + parsed.artistSlug + '/' + parsed.trackSlug);
    res.json({ url: streamUrl, format: 'mp3', quality: data.hq ? 'hq' : 'standard', expiresAt: Math.floor(Date.now() / 1000) + 3600 });
  } catch (err) {
    console.error('[/stream] ' + err.message);
    var s = err.response && err.response.status;
    if (s === 401 || s === 403) return res.status(401).json({ error: 'Audiomack credentials invalid.' });
    if (s === 404) return res.status(404).json({ error: 'Track not found.' });
    res.status(500).json({ error: 'Stream failed.' });
  }
});

app.get('/health', function(_req, res) {
  res.json({ status: 'ok', sharedKeysReady: !!(SHARED_KEY && SHARED_SECRET), redisConnected: !!(redis && redis.status === 'ready'), activeTokens: TOKEN_CACHE.size, timestamp: new Date().toISOString() });
});

app.listen(PORT, function() {
  console.log('Eclipse Audiomack Addon on port ' + PORT);
});
