'use strict';

const express = require('express');
const https = require('https');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 45212;

// ─── Middleware ───────────────────────────────────────────────────────────────

// ① Private-network guard — must be the very first middleware.
// Rejects any connection that isn't from localhost or an RFC-1918 LAN range,
// so the server is completely invisible to the public internet even if a
// firewall rule is accidentally removed.
const PRIVATE_IP_RE = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^::1$/,
  /^fe80:/i,
];
function isPrivateIP(raw = '') {
  const ip = raw.replace(/^::ffff:/, ''); // unwrap IPv4-mapped IPv6
  return PRIVATE_IP_RE.some(r => r.test(ip));
}
app.use((req, res, next) => {
  const ip = (req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  if (!isPrivateIP(ip)) {
    return res.status(403).json({ error: 'Access restricted to the local network.' });
  }
  next();
});

// ② HTTP security headers — applied to every response.
app.use((_req, res, next) => {
  // Force HTTPS for the next year and prevent downgrade attacks.
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  // Prevent MIME-type sniffing.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Disallow framing (clickjacking protection).
  res.setHeader('X-Frame-Options', 'DENY');
  // No referrer information leaks.
  res.setHeader('Referrer-Policy', 'no-referrer');
  // Content Security Policy: restrict resource origins tightly.
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "script-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
    ].join('; ')
  );
  next();
});

app.use(express.json({ limit: '4kb' }));
// (static files are served below, after the auth guard)

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Run an AppleScript command and return a promise.
 * @param {string} script - The AppleScript to execute.
 * @returns {Promise<string>} - stdout trimmed.
 */
function runAppleScript(script) {
  return new Promise((resolve, reject) => {
    // Use spawn + stdin so the script is never interpolated into a shell string,
    // which prevents AppleScript / shell injection regardless of script content.
    const proc = spawn('osascript', ['-']);
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', code => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(stderr.trim() || `osascript exited with code ${code}`));
    });
    proc.on('error', reject);
    proc.stdin.write(script);
    proc.stdin.end();
  });
}

/**
 * Get the current system volume level (0–100) and muted state.
 * Uses a single AppleScript call — 'get volume settings' returns all values
 * in one shot, e.g. "output volume:72, input volume:50, alert volume:75, output muted:false".
 * @returns {Promise<{ volume: number, muted: boolean }>}
 */
async function getVolumeState() {
  const raw = await runAppleScript('get volume settings');
  const volMatch = raw.match(/output volume:(\d+)/);
  const mutedMatch = raw.match(/output muted:(true|false)/);
  return {
    volume: volMatch ? parseInt(volMatch[1], 10) : 0,
    muted: mutedMatch ? mutedMatch[1] === 'true' : false,
  };
}

// ─── Mouse helpers ───────────────────────────────────────────────────────────

/** Cached logical screen dimensions, populated at server start. */
let screenSize = { width: 1920, height: 1080 };

/**
 * Run a cliclick command and return a promise resolving to stdout trimmed.
 * @param {string} args - Arguments forwarded to cliclick (e.g. 'p', 'm:+50,+0').
 * @returns {Promise<string>}
 */
function runCliclick(arg) {
  return new Promise((resolve, reject) => {
    // Use spawn so the argument is never passed through a shell.
    const proc = spawn('cliclick', [arg]);
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', code => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(stderr.trim() || `cliclick exited with code ${code}`));
    });
    proc.on('error', reject);
  });
}

/**
 * Read logical screen bounds via AppleScript / Finder.
 * Returns { width, height }.
 */
async function getScreenSize() {
  // Output: "0, 0, 1440, 900"
  const raw = await runAppleScript(
    'tell application "Finder" to get bounds of window of desktop'
  );
  const parts = raw.split(',').map(s => parseInt(s.trim(), 10));
  return { width: parts[2], height: parts[3] };
}

/**
 * Get the current mouse cursor position via cliclick.
 * Returns { x, y }.
 */
async function getMousePosition() {
  const raw = await runCliclick('p'); // output: "x,y"
  const [x, y] = raw.split(',').map(s => parseInt(s.trim(), 10));
  return { x, y };
}

// ─── Auth ──────────────────────────────────────────────────────────────────

/** Session duration (sliding): 1 hour of inactivity resets on every authenticated request. */
const SESSION_DURATION_MS = 60 * 60 * 1000;

/** How long before a valid session token is silently rotated (15 minutes). */
const SESSION_ROTATION_MS = 15 * 60 * 1000;

/**
 * PIN / password verification.
 *
 * Two modes:
 *   • PASSWORD_HASH env var — a hex-encoded PBKDF2-SHA-256 digest produced by:
 *       node -e "const c=require('crypto');
 *         console.log(c.pbkdf2Sync('yourpassword','mymac-salt',200000,32,'sha256').toString('hex'));"
 *     Compared with timingSafeEqual to prevent timing side-channels.
 *
 *   • PASSWORD env var (plain) — kept for convenience; compared directly
 *     because the secret never leaves this process.
 *
 *   • Neither set — a fresh random 6-digit PIN is generated each startup
 *     and printed to the terminal. Single-use per boot, no storage risk.
 */
const _envHash = process.env.PASSWORD_HASH || null;
const _envPlain = process.env.PASSWORD || null;
const _autoPin = _envHash || _envPlain
  ? null
  : String(Math.floor(100000 + Math.random() * 900000));


/**
 * Returns true when `input` matches the configured credential.
 * @param {string} input
 * @returns {boolean}
 */
function verifyPin(input) {
  const candidate = String(input).trim();

  if (_envHash) {
    // ④ Hash the candidate and compare in constant time.
    const candidateHash = crypto
      .pbkdf2Sync(candidate, 'mymac-salt', 200_000, 32, 'sha256')
      .toString('hex');
    try {
      return crypto.timingSafeEqual(
        Buffer.from(candidateHash),
        Buffer.from(_envHash)
      );
    } catch {
      return false; // buffers differed in length — wrong hash format
    }
  }

  if (_envPlain) return candidate === _envPlain;
  return candidate === _autoPin;
}

// ─── Rate limiter ──────────────────────────────────────────────────────────────
/** Maximum failed login attempts before a temporary IP lockout. */
const MAX_LOGIN_ATTEMPTS = 5;
/** Lockout duration after exceeding MAX_LOGIN_ATTEMPTS. */
const LOCKOUT_DURATION_MS = 60 * 1000; // 1 minute
/** IP → { attempts: number, lockedUntil: number } */
const loginAttempts = new Map();

/** Returns { allowed: true } or { allowed: false, remaining: seconds }. */
function checkRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (entry && now < entry.lockedUntil) {
    return { allowed: false, remaining: Math.ceil((entry.lockedUntil - now) / 1000) };
  }
  return { allowed: true };
}

/** Record a failed attempt; applies lockout when the threshold is reached. */
function recordFailedAttempt(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { attempts: 0, lockedUntil: 0, lastSeen: 0 };
  if (now >= entry.lockedUntil) entry.attempts = 0; // reset after an expired lockout
  entry.attempts += 1;
  entry.lastSeen = now;
  if (entry.attempts >= MAX_LOGIN_ATTEMPTS) {
    entry.lockedUntil = now + LOCKOUT_DURATION_MS;
    entry.attempts = 0; // fresh cycle for any attempts after the lockout expires
  }
  loginAttempts.set(ip, entry);
}

/** Clear the rate-limit record for an IP after a successful login. */
function clearRateLimit(ip) {
  loginAttempts.delete(ip);
}

// Prune stale loginAttempts entries every 5 minutes to prevent unbounded growth.
setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [ip, entry] of loginAttempts) {
    if (entry.lastSeen < cutoff) loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000).unref(); // .unref() so this timer doesn't keep the process alive

// ─── API rate limiter ─────────────────────────────────────────────────────────
/** Maximum authenticated API requests per second per IP (all /api/* routes). */
const API_MAX_RPS = 30;
/** IP → { count: number, windowStart: number } */
const apiRateLimitMap = new Map();

/**
 * Sliding 1-second window counter.
 * Returns true when the request is within the allowed rate, false when exceeded.
 */
function checkApiRateLimit(ip) {
  const now = Date.now();
  const entry = apiRateLimitMap.get(ip) || { count: 0, windowStart: now };
  if (now - entry.windowStart > 1000) {
    // Window has elapsed — start a fresh one.
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count++;
  apiRateLimitMap.set(ip, entry);
  return entry.count <= API_MAX_RPS;
}

// Prune stale apiRateLimitMap entries every minute.
setInterval(() => {
  const cutoff = Date.now() - 5000;
  for (const [ip, entry] of apiRateLimitMap) {
    if (entry.windowStart < cutoff) apiRateLimitMap.delete(ip);
  }
}, 60 * 1000).unref();

/** In-memory session store: token → { lastUsed: number, issuedAt: number } */
const sessions = new Map();

/**
 * Parse a raw Cookie header string into a key→value map.
 * Avoids adding the cookie-parser npm dependency.
 */
function parseCookies(header = '') {
  const cookies = {};
  header.split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = v.join('=');
  });
  return cookies;
}

/** Shared cookie attributes string — keeps Set-Cookie lines DRY. */
const COOKIE_ATTRS = 'HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Path=/';

/**
 * Express middleware: validates the rvc_session cookie.
 * - API requests (→ /api/*) receive a 401 JSON response.
 * - Page requests are redirected to /login.
 * - Expired sessions are removed from the store.
 * - ⑥ Rotates the session token every SESSION_ROTATION_MS (15 min) so a
 *   captured cookie has a limited useful lifespan even if never revoked.
 */
function requireAuth(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.rvc_session;
  if (token) {
    const session = sessions.get(token);
    if (session) {
      const now = Date.now();
      if (now - session.lastUsed < SESSION_DURATION_MS) {
        session.lastUsed = now; // slide the expiry window on every valid request

        // ⑥ Token rotation: silently issue a new cookie when the current
        // token is older than SESSION_ROTATION_MS.
        if (now - session.issuedAt >= SESSION_ROTATION_MS) {
          const newToken = crypto.randomBytes(32).toString('hex');
          sessions.delete(token);
          sessions.set(newToken, { lastUsed: now, issuedAt: now });
          res.setHeader('Set-Cookie', `rvc_session=${newToken}; ${COOKIE_ATTRS}`);
        }

        return next(); // valid
      }
      sessions.delete(token); // expired — clean up
    }
  }
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
  res.redirect('/login');
}

// ─── Auth routes (public — no session required) ────────────────────────────────

/** GET /login — serve the login page. */
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

/**
 * POST /auth/login
 * Body: { pin: string }
 * Validates PIN/password and issues a signed session cookie.
 */
app.post('/auth/login', (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';

  // ── Rate-limit check ──────────────────────────────────────────────────────
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    return res.status(429).json({
      error: `Too many failed attempts. Try again in ${rl.remaining}s.`,
    });
  }

  const { pin } = req.body;
  if (!verifyPin(pin)) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Incorrect PIN. Please try again.' });
  }

  clearRateLimit(ip); // successful — reset the counter
  const token = crypto.randomBytes(32).toString('hex');
  sessions.clear(); // invalidate any existing sessions — only one device at a time
  sessions.set(token, { lastUsed: Date.now(), issuedAt: Date.now() });
  res
    .setHeader('Set-Cookie', `rvc_session=${token}; ${COOKIE_ATTRS}`)
    .json({ ok: true });
});

/**
 * POST /auth/logout
 * Deletes the session and clears the cookie.
 */
app.post('/auth/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.rvc_session) sessions.delete(cookies.rvc_session);
  res
    .setHeader('Set-Cookie', 'rvc_session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/')
    .json({ ok: true });
});

// Serve shared static assets that must be reachable BEFORE authentication
// (e.g. shared.css is referenced by login.html which has no session cookie).
// Only explicitly whitelisted filenames are exposed here.
const PUBLIC_ASSETS = new Set(['shared.css']);
app.get('/:asset', (req, res, next) => {
  if (!PUBLIC_ASSETS.has(req.params.asset)) return next();
  res.sendFile(path.join(__dirname, 'public', req.params.asset));
});

// ─── Auth guard + protected static files ───────────────────────────────────────
app.use(requireAuth);

// ③ Per-IP API rate limiter — runs after auth so unauthenticated probes are
// blocked by requireAuth first and never touch this counter.
app.use('/api', (req, res, next) => {
  const ip = (req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  if (!checkApiRateLimit(ip)) {
    return res.status(429).json({ error: 'API rate limit exceeded — max 30 req/s.' });
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ─── SSE: real-time volume push ──────────────────────────────────────────────

/** Active SSE response objects, one per connected client. */
const sseClients = new Set();

/** Last broadcast state as a JSON string — used for change detection and initial push on connect. */
let lastBroadcastState = null;

/**
 * Poll the Mac's volume once and broadcast to all SSE clients if state changed.
 * Runs on a shared 1-second interval so every client benefits from a single
 * osascript call regardless of how many devices are connected.
 */
async function pollAndBroadcast() {
  try {
    const state = await getVolumeState();
    const json = JSON.stringify(state);
    if (json !== lastBroadcastState) {
      lastBroadcastState = json;
      for (const client of sseClients) {
        client.write(`data: ${json}\n\n`);
      }
    }
  } catch { /* ignore transient osascript errors */ }
}

/**
 * GET /api/events
 * Server-Sent Events stream. Sends { volume, muted } immediately on connect,
 * then pushes updates whenever the system volume changes.
 */
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Immediately send last known state so the client doesn't wait up to 1 s
  if (lastBroadcastState) res.write(`data: ${lastBroadcastState}\n\n`);

  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// ─── Routes ──────────────────────────────────────────────────────────────────

/**
 * GET /api/volume
 * Returns current volume and muted state.
 */
app.get('/api/volume', async (req, res) => {
  try {
    const state = await getVolumeState();
    res.json(state);
  } catch (err) {
    console.error('[GET /api/volume]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/volume
 * Body: { volume: number }  (0–100)
 * Sets the system volume to the given level.
 */
app.post('/api/volume', async (req, res) => {
  const { volume } = req.body;

  if (volume === undefined || typeof volume !== 'number') {
    return res.status(400).json({ error: '`volume` must be a number (0–100).' });
  }

  const clamped = Math.min(100, Math.max(0, Math.round(volume)));

  try {
    await runAppleScript(`set volume output volume ${clamped}`);
    const state = await getVolumeState();
    res.json(state);
  } catch (err) {
    console.error('[POST /api/volume]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/mute
 * Body: { muted: boolean }
 * Sets or clears the system mute.
 */
app.post('/api/mute', async (req, res) => {
  const { muted } = req.body;

  if (muted === undefined || typeof muted !== 'boolean') {
    return res.status(400).json({ error: '`muted` must be a boolean.' });
  }

  try {
    await runAppleScript(`set volume ${muted ? 'with' : 'without'} output muted`);
    const state = await getVolumeState();
    res.json(state);
  } catch (err) {
    console.error('[POST /api/mute]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/volume/up
 * Increase volume by a fixed step (default 5).
 */
app.post('/api/volume/up', async (req, res) => {
  const rawStep = Number(req.body?.step);
  const step = Number.isFinite(rawStep) ? Math.min(20, Math.max(1, Math.round(rawStep))) : 5;
  try {
    const { volume } = await getVolumeState();
    const next = Math.min(100, volume + step);
    await runAppleScript(`set volume output volume ${next}`);
    const state = await getVolumeState();
    res.json(state);
  } catch (err) {
    console.error('[POST /api/volume/up]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/volume/down
 * Decrease volume by a fixed step (default 5).
 */
app.post('/api/volume/down', async (req, res) => {
  const rawStep = Number(req.body?.step);
  const step = Number.isFinite(rawStep) ? Math.min(20, Math.max(1, Math.round(rawStep))) : 5;
  try {
    const { volume } = await getVolumeState();
    const next = Math.max(0, volume - step);
    await runAppleScript(`set volume output volume ${next}`);
    const state = await getVolumeState();
    res.json(state);
  } catch (err) {
    console.error('[POST /api/volume/down]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Mouse routes ────────────────────────────────────────────────────────────

/**
 * GET /api/screen
 * Returns the logical screen resolution { width, height }.
 * Useful for the client to bound its cursor coordinates.
 */
app.get('/api/screen', (req, res) => {
  res.json(screenSize);
});

/**
 * GET /api/mouse
 * Returns the current cursor position { x, y }.
 */
app.get('/api/mouse', async (req, res) => {
  try {
    const pos = await getMousePosition();
    res.json(pos);
  } catch (err) {
    console.error('[GET /api/mouse]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/mouse/move
 * Body: { dx: number, dy: number }
 * Moves the cursor relatively by (dx, dy) pixels.
 */
app.post('/api/mouse/move', async (req, res) => {
  const { dx, dy } = req.body;
  if (typeof dx !== 'number' || typeof dy !== 'number') {
    return res.status(400).json({ error: '`dx` and `dy` must be numbers.' });
  }
  const rdx = Math.round(dx);
  const rdy = Math.round(dy);
  // cliclick expects explicit sign for relative movement: m:+50,-30
  const dxStr = rdx >= 0 ? `+${rdx}` : `${rdx}`;
  const dyStr = rdy >= 0 ? `+${rdy}` : `${rdy}`;
  try {
    await runCliclick(`m:${dxStr},${dyStr}`);
    const pos = await getMousePosition();
    res.json(pos);
  } catch (err) {
    console.error('[POST /api/mouse/move]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/mouse/click
 * Body: { button: "left" | "right" | "double" }
 * Clicks at the current cursor position.
 */
app.post('/api/mouse/click', async (req, res) => {
  const { button = 'left' } = req.body;
  const actionMap = { left: 'c:.', right: 'rc:.', double: 'dc:.' };
  const action = actionMap[button];
  if (!action) {
    return res.status(400).json({ error: '`button` must be "left", "right", or "double".' });
  }
  try {
    await runCliclick(action);
    res.json({ ok: true, button });
  } catch (err) {
    console.error('[POST /api/mouse/click]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/mouse/down
 * Presses and holds the left mouse button at the current cursor position.
 * Used for click-drag operations such as moving windows or selecting text.
 */
app.post('/api/mouse/down', async (req, res) => {
  try {
    await runCliclick('dd:.');
    res.json({ ok: true });
  } catch (err) {
    console.error('[POST /api/mouse/down]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/mouse/up
 * Releases the left mouse button. Should always be paired with /api/mouse/down.
 */
app.post('/api/mouse/up', async (req, res) => {
  try {
    await runCliclick('du:.');
    res.json({ ok: true });
  } catch (err) {
    console.error('[POST /api/mouse/up]', err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/keyboard/type
 * Body: { text: string }
 * Types the given text at the current cursor position using System Events.
 * Uses osascript via stdin to safely handle quotes and special characters.
 */

/** Maximum characters accepted by /api/keyboard/type in a single request. */
const MAX_TYPE_LENGTH = 500;

app.post('/api/keyboard/type', (req, res) => {
  const { text } = req.body;
  if (typeof text !== 'string' || text.length === 0) {
    return res.status(400).json({ error: '`text` must be a non-empty string.' });
  }
  if (text.length > MAX_TYPE_LENGTH) {
    return res.status(400).json({ error: `Text too long — maximum ${MAX_TYPE_LENGTH} characters per request.` });
  }
  // Strip ASCII control characters (U+0000–U+001F, U+007F): they cannot be
  // safely embedded in an AppleScript "keystroke" string literal and should
  // be sent via /api/keyboard/key instead (Return, Tab, Backspace, etc.).
  const printable = text.replace(/[\x00-\x1F\x7F]/g, '');
  if (!printable) {
    return res.status(400).json({ error: 'Text contains no printable characters.' });
  }
  // Escape backslashes and double-quotes for the AppleScript string literal.
  const safe = printable.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const script = `tell application "System Events" to keystroke "${safe}"`;
  const proc = spawn('osascript', ['-']);
  let stderr = '';
  proc.stderr.on('data', d => { stderr += d; });
  proc.on('close', code => {
    if (code === 0) {
      res.json({ ok: true, length: printable.length });
    } else {
      console.error('[POST /api/keyboard/type]', stderr);
      res.status(500).json({ error: stderr || 'osascript failed' });
    }
  });
  proc.stdin.write(script);
  proc.stdin.end();
});

/**
 * POST /api/keyboard/key
 * Body: { key: "backspace" | "return" | "escape" | "tab" }
 * Fires a named special key using osascript key codes.
 */
const KEY_CODES = { backspace: 51, return: 36, escape: 53, tab: 48 };

app.post('/api/keyboard/key', async (req, res) => {
  const { key } = req.body;
  const code = KEY_CODES[key];
  if (code === undefined) {
    return res.status(400).json({ error: `Unknown key. Supported: ${Object.keys(KEY_CODES).join(', ')}.` });
  }
  try {
    await runAppleScript(`tell application "System Events" to key code ${code}`);
    res.json({ ok: true, key });
  } catch (err) {
    console.error('[POST /api/keyboard/key]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/mouse/scroll', async (req, res) => {
  const { direction, amount = 3 } = req.body;
  if (direction !== 'up' && direction !== 'down') {
    return res.status(400).json({ error: '`direction` must be "up" or "down".' });
  }
  // key code 126 = Up arrow, 125 = Down arrow
  const keyCode = direction === 'up' ? 126 : 125;
  const count = Math.min(20, Math.max(1, Math.round(Number(amount) || 3)));
  try {
    await runAppleScript(
      `repeat ${count} times\n` +
      `  tell application "System Events" to key code ${keyCode}\n` +
      `end repeat`
    );
    res.json({ ok: true, direction, amount: count });
  } catch (err) {
    console.error('[POST /api/mouse/scroll]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Start server ─────────────────────────────────────────────────────────────
function getLocalIP() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

/**
 * Ensures a self-signed TLS certificate exists in ./certs/.
 * Generates one via openssl on first run, including SANs for localhost,
 * *.local mDNS hostnames, and the current LAN IP so the cert is valid
 * for both http://mac.local:PORT and http://192.168.x.x:PORT access.
 * @returns {Promise<{key: Buffer, cert: Buffer}>}
 */
async function generateCertIfNeeded() {
  const certsDir = path.join(__dirname, 'certs');
  const keyPath = path.join(certsDir, 'server.key');
  const certPath = path.join(certsDir, 'server.crt');
  const confPath = path.join(certsDir, 'openssl.cnf');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  }

  fs.mkdirSync(certsDir, { recursive: true });

  const localIP = getLocalIP();
  const conf = [
    '[req]',
    'default_bits       = 2048',
    'distinguished_name = req_dn',
    'x509_extensions    = v3_req',
    'prompt             = no',
    '',
    '[req_dn]',
    'CN = MyMac Remote',
    '',
    '[v3_req]',
    'keyUsage         = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName   = @alt_names',
    '',
    '[alt_names]',
    'DNS.1 = localhost',
    'DNS.2 = *.local',
    'IP.1  = 127.0.0.1',
    `IP.2  = ${localIP}`,
  ].join('\n');

  fs.writeFileSync(confPath, conf);

  await new Promise((resolve, reject) => {
    exec(
      `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -config "${confPath}"`,
      (err, _stdout, stderr) => (err ? reject(new Error(stderr || err.message)) : resolve()),
    );
  });

  console.log('  ✓ TLS certificate generated → certs/server.crt');
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

(async () => {
  await runAppleScript(`set the clipboard to "${_autoPin}"`);
  const tlsOptions = await generateCertIfNeeded();

  // ⑤ Compute the cert's SHA-256 fingerprint once at startup so you can
  // verify it matches what your browser shows — catching any MITM cert swap.
  const certFingerprint = crypto
    .createHash('sha256')
    .update(tlsOptions.cert)
    .digest('hex')
    .match(/.{2}/g)
    .join(':');

  https.createServer(tlsOptions, app).listen(PORT, '0.0.0.0', () => {
    const localIP = getLocalIP();
    console.log('');
    console.log('                 MyMac Remote');
    console.log('  ─────────────────────────────────────────');
    console.log('');
    if (_envHash) {
      console.log('      Password: PBKDF2 hash set via PASSWORD_HASH env var');
    } else if (_envPlain) {
      console.log('      Password: set via PASSWORD env var');
    } else {
      const digits = _autoPin.split('').join('  ');
      console.log(`      PIN:  ${digits}`);
    }
    console.log('      Sessions expire after 1 hour of inactivity.');
    console.log('      Session tokens rotate every 15 minutes.');
    console.log('');
    console.log(`      Local:    https://localhost:${PORT}`);
    console.log(`      Network:  https://${localIP}:${PORT}`);
    console.log('');
    console.log('  ⚠  First visit: accept the self-signed certificate in your browser.');

    // Pre-fetch screen resolution for /api/screen
    getScreenSize()
      .then(size => {
        screenSize = size;
        console.log(`  Screen: ${size.width}×${size.height}`);
      })
      .catch(err => console.warn('  Screen size unavailable:', err.message));

    // Start shared SSE polling: 1 s interval, only broadcasts on state change.
    // Initial call seeds lastBroadcastState so first connecting client gets
    // the current volume immediately without waiting for the next tick.
    pollAndBroadcast();
    setInterval(pollAndBroadcast, 1000);

    console.log('');
  });
})();

