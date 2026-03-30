require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { Pool } = require('pg');

// Auth & encryption config
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) console.log('[Auth] WARNING: No JWT_SECRET set — tokens will be invalidated on restart. Set JWT_SECRET env var for persistence.');
if (!process.env.ENCRYPTION_KEY) console.log('[Auth] WARNING: No ENCRYPTION_KEY set — encrypted data will be unreadable after restart. Set ENCRYPTION_KEY env var for persistence.');

// Simple bcrypt-like hashing using crypto (no extra dependency)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === testHash;
}

// AES-256-GCM encryption for sensitive fields
function encrypt(text) {
  if (!text) return null;
  try {
    const keyHex = ENCRYPTION_KEY.replace(/[^0-9a-fA-F]/g, '').substring(0, 64).padEnd(64, '0');
    const key = Buffer.from(keyHex, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${tag}:${encrypted}`;
  } catch (e) {
    console.error('[Encrypt] Failed:', e.message);
    return `plain:${text}`; // fallback: store unencrypted with prefix
  }
}

function decrypt(encrypted) {
  if (!encrypted) return null;
  try {
    // Handle fallback plain text storage
    if (encrypted.startsWith('plain:')) return encrypted.substring(6);
    const [ivHex, tagHex, data] = encrypted.split(':');
    const keyHex = ENCRYPTION_KEY.replace(/[^0-9a-fA-F]/g, '').substring(0, 64).padEnd(64, '0');
    const key = Buffer.from(keyHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    let decrypted = decipher.update(data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('[Decrypt] Failed:', e.message);
    return null;
  }
}

// JWT-like token (simple, no dependency)
function createToken(userId) {
  const payload = JSON.stringify({ userId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }); // 7 days
  const hmac = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
  return Buffer.from(payload).toString('base64url') + '.' + hmac;
}

function verifyToken(token) {
  try {
    const [payloadB64, hmac] = token.split('.');
    const payload = Buffer.from(payloadB64, 'base64url').toString();
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
    if (hmac !== expected) return null;
    const data = JSON.parse(payload);
    if (data.exp < Date.now()) return null;
    return data;
  } catch (e) { return null; }
}

// User store (in-memory, synced to DB or file)
const users = {};

// ─── PostgreSQL (persistent) or file-based fallback ──────
const DATABASE_URL = process.env.DATABASE_URL;
let db = null;

if (DATABASE_URL) {
  db = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }, // Render requires SSL
  });
  console.log('[DB] PostgreSQL connected');
} else {
  console.log('[DB] No DATABASE_URL — using file-based storage (will be wiped on deploy)');
}

// Create tables if using Postgres
async function initDB() {
  if (!db) return;
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        data JSONB NOT NULL
      )
    `);
    await db.query(`
      CREATE TABLE IF NOT EXISTS profiles (
        user_id TEXT PRIMARY KEY,
        data JSONB NOT NULL
      )
    `);
    await db.query(`
      CREATE TABLE IF NOT EXISTS watches (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        data JSONB NOT NULL
      )
    `);
    console.log('[DB] Tables ready');
  } catch (e) {
    console.error('[DB] Table creation failed:', e.message);
  }
}

// ─── File-based fallback paths ───────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROFILES_FILE = path.join(DATA_DIR, 'profiles.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ─── Save / Load functions (DB or file) ──────────────────
async function saveUsers() {
  if (db) {
    try {
      for (const [username, data] of Object.entries(users)) {
        await db.query(
          `INSERT INTO users (username, data) VALUES ($1, $2)
           ON CONFLICT (username) DO UPDATE SET data = $2`,
          [username, JSON.stringify(data)]
        );
      }
    } catch (e) { console.error('[DB] Failed to save users:', e.message); }
  } else {
    try {
      ensureDataDir();
      fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (e) { console.error('[Persist] Failed to save users:', e.message); }
  }
}

async function saveProfiles() {
  if (db) {
    try {
      for (const [userId, data] of Object.entries(userProfiles)) {
        await db.query(
          `INSERT INTO profiles (user_id, data) VALUES ($1, $2)
           ON CONFLICT (user_id) DO UPDATE SET data = $2`,
          [userId, JSON.stringify(data)]
        );
      }
    } catch (e) { console.error('[DB] Failed to save profiles:', e.message); }
  } else {
    try {
      ensureDataDir();
      fs.writeFileSync(PROFILES_FILE, JSON.stringify(userProfiles, null, 2));
    } catch (e) { console.error('[Persist] Failed to save profiles:', e.message); }
  }
}

async function loadPersistedData() {
  if (db) {
    try {
      const userRows = await db.query('SELECT username, data FROM users');
      for (const row of userRows.rows) {
        users[row.username] = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
      }
      console.log(`[DB] Loaded ${userRows.rows.length} user(s)`);
    } catch (e) { console.error('[DB] Failed to load users:', e.message); }
    try {
      const profileRows = await db.query('SELECT user_id, data FROM profiles');
      for (const row of profileRows.rows) {
        userProfiles[row.user_id] = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
      }
      console.log(`[DB] Loaded ${profileRows.rows.length} profile(s)`);
    } catch (e) { console.error('[DB] Failed to load profiles:', e.message); }
  } else {
    try {
      if (fs.existsSync(USERS_FILE)) {
        const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        Object.assign(users, data);
        console.log(`[Persist] Loaded ${Object.keys(data).length} user(s)`);
      }
    } catch (e) { console.error('[Persist] Failed to load users:', e.message); }
    try {
      if (fs.existsSync(PROFILES_FILE)) {
        const data = JSON.parse(fs.readFileSync(PROFILES_FILE, 'utf8'));
        Object.assign(userProfiles, data);
        console.log(`[Persist] Loaded ${Object.keys(data).length} profile(s)`);
      }
    } catch (e) { console.error('[Persist] Failed to load profiles:', e.message); }
  }
}

// Auto-create admin user from env vars (survives deploys)
async function ensureAdminUser() {
  const adminUser = process.env.ADMIN_USER;
  const adminPass = process.env.ADMIN_PASS;
  if (adminUser && adminPass) {
    // Check if already exists (by username field)
    const existingId = Object.keys(users).find(k => users[k].username === adminUser);
    if (!existingId) {
      const id = uuidv4();
      users[id] = {
        id,
        username: adminUser,
        passwordHash: hashPassword(adminPass),
        createdAt: new Date().toISOString(),
        isAdmin: true,
      };
      await saveUsers();
      console.log(`[Auth] Auto-created admin user "${adminUser}" from env vars`);
    } else {
      console.log(`[Auth] Admin user "${adminUser}" already exists`);
    }
  }
}

// Startup init (called after userProfiles is defined below)

// Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const token = authHeader.substring(7);
  const data = verifyToken(token);
  if (!data || !users[data.userId]) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  req.userId = data.userId;
  req.user = users[data.userId];
  next();
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Config ───────────────────────────────────────────────
const CHECK_INTERVAL_MS = parseInt(process.env.CHECK_INTERVAL_MS || '30000'); // 30 seconds
const TWOCAPTCHA_KEY = process.env.TWOCAPTCHA_KEY || '';

// BrightData proxy config (for bypassing airline bot protection)
const BRIGHTDATA_HOST = process.env.BRIGHTDATA_HOST || '';
const BRIGHTDATA_PORT = process.env.BRIGHTDATA_PORT || '22225';
const BRIGHTDATA_USER = process.env.BRIGHTDATA_USER || '';
const BRIGHTDATA_PASS = process.env.BRIGHTDATA_PASS || '';
const hasBrightData = !!(BRIGHTDATA_HOST && BRIGHTDATA_USER && BRIGHTDATA_PASS);

// ─── In-memory stores ─────────────────────────────────────
const watches = {};
let checkInterval = null;
let isChecking = false;
let nextCheckAt = null;

// User profiles
const userProfiles = {};

// Initialize DB + load persisted data + create admin user
(async () => {
  await initDB();
  await loadPersistedData();
  await ensureAdminUser();
})();

// ─── Puppeteer setup ──────────────────────────────────────
let puppeteerExtra, StealthPlugin;
try {
  puppeteerExtra = require('puppeteer-extra');
  StealthPlugin = require('puppeteer-extra-plugin-stealth');
  puppeteerExtra.use(StealthPlugin());
} catch (e) {
  console.error('Failed to load puppeteer-extra:', e.message);
  process.exit(1);
}

let browser = null;

async function getBrowser() {
  if (!browser || !browser.connected) {
    console.log('[Browser] Launching Puppeteer...');
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || undefined;
    const launchOpts = {
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-blink-features=AutomationControlled',
        '--disable-infobars',
        '--window-size=1366,768',
        '--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      ],
    };
    if (executablePath) launchOpts.executablePath = executablePath;
    browser = await puppeteerExtra.launch(launchOpts);
  }
  return browser;
}

// ─── 2Captcha solver ──────────────────────────────────────
async function solveCaptcha(siteKey, pageUrl) {
  if (!TWOCAPTCHA_KEY) throw new Error('No 2captcha API key configured');
  const fetch = (await import('node-fetch')).default;

  // Submit captcha
  const submitUrl = `http://2captcha.com/in.php?key=${TWOCAPTCHA_KEY}&method=userrecaptcha&googlekey=${siteKey}&pageurl=${encodeURIComponent(pageUrl)}&json=1`;
  const submitRes = await fetch(submitUrl);
  const submitData = await submitRes.json();
  if (submitData.status !== 1) throw new Error('2captcha submit failed: ' + submitData.request);

  const captchaId = submitData.request;
  console.log(`[2Captcha] Submitted, ID: ${captchaId}`);

  // Poll for result
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 5000));
    const resultUrl = `http://2captcha.com/res.php?key=${TWOCAPTCHA_KEY}&action=get&id=${captchaId}&json=1`;
    const resultRes = await fetch(resultUrl);
    const resultData = await resultRes.json();
    if (resultData.status === 1) {
      console.log(`[2Captcha] Solved!`);
      return resultData.request;
    }
    if (resultData.request !== 'CAPCHA_NOT_READY') {
      throw new Error('2captcha solve failed: ' + resultData.request);
    }
  }
  throw new Error('2captcha timeout');
}

// ─── Air Haifa checker ────────────────────────────────────
async function checkAirHaifa(url) {
  const br = await getBrowser();
  const page = await br.newPage();
  await page.setViewport({ width: 1366, height: 768 });
  await page.setExtraHTTPHeaders({
    'Accept-Language': 'en-US,en;q=0.9,he;q=0.8',
  });

  let flightData = null;
  let apiError = null;

  page.on('response', async (response) => {
    const resUrl = response.url();
    if (resUrl.includes('flightList.php') && resUrl.includes('flightsPull')) {
      try {
        const text = await response.text();
        flightData = JSON.parse(text);
      } catch (e) {
        apiError = 'Failed to parse flight API response: ' + e.message;
      }
    }
  });

  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 45000 });
    await new Promise(r => setTimeout(r, 6000));

    let domText = '';
    try { domText = await page.evaluate(() => document.body.innerText || ''); } catch (e) {}
    await page.close();

    if (apiError) throw new Error(apiError);

    if (!flightData) {
      if (domText.includes('הטיסה מלאה') || domText.includes('מצטערים')) {
        return { available: false, freeSeats: 0, reason: 'Flight is full / no seats', flights: [] };
      }
      return { available: false, freeSeats: 0, reason: 'No API response', flights: [] };
    }

    const directions = ['outbound', 'inbound'].filter(d => flightData[d] && Array.isArray(flightData[d]));
    let totalFreeSeats = 0;
    let flightDetails = [];

    for (const dir of directions) {
      for (const flight of flightData[dir]) {
        if (flight.classes && Array.isArray(flight.classes)) {
          for (const cls of flight.classes) {
            if (cls.freeseats > 0) {
              totalFreeSeats += cls.freeseats;
              flightDetails.push({
                airline: 'Air Haifa',
                direction: dir,
                flightNum: flight.fltnum,
                from: flight.fromcode,
                to: flight.tocode,
                departure: flight.stdinutc,
                arrival: flight.stainutc,
                className: cls.classname,
                freeSeats: cls.freeseats,
                price: cls.fareamount,
                currency: cls.farecurrency,
                bookingUrl: url,
              });
            }
          }
        }
      }
    }

    return {
      available: totalFreeSeats > 0,
      freeSeats: totalFreeSeats,
      flights: flightDetails,
      reason: totalFreeSeats > 0 ? 'seats_available' : 'sold_out',
    };
  } catch (e) {
    try { await page.close(); } catch (_) {}
    throw e;
  }
}

// ─── BrightData proxy browser (for El Al / protected sites) ──
let proxyBrowser = null;

async function getProxyBrowser() {
  if (!hasBrightData) throw new Error('BrightData proxy not configured - add BRIGHTDATA_HOST, BRIGHTDATA_USER, BRIGHTDATA_PASS to .env');
  if (proxyBrowser && proxyBrowser.connected) return proxyBrowser;

  console.log('[ProxyBrowser] Launching Puppeteer with BrightData proxy...');
  const proxyUrl = `http://${BRIGHTDATA_HOST}:${BRIGHTDATA_PORT}`;
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || undefined;
  const launchOpts = {
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-blink-features=AutomationControlled',
      '--disable-infobars',
      '--window-size=1366,768',
      `--proxy-server=${proxyUrl}`,
      '--ignore-certificate-errors',
    ],
  };
  if (executablePath) launchOpts.executablePath = executablePath;
  proxyBrowser = await puppeteerExtra.launch(launchOpts);
  return proxyBrowser;
}

// ─── El Al checker (BrightData proxy → direct scrape, fallback to Google Flights) ─────
async function checkElAl(origin, destination, date, passengers = 1) {
  const elAlBookingUrl = `https://www.elal.com/en/booking/flight-select/?isOneWay=true&origin=${origin}&destination=${destination}&dep=${date}&adult=${passengers}`;

  // Try BrightData direct El Al scraping first
  if (hasBrightData) {
    try {
      const result = await checkElAlDirect(origin, destination, date, passengers, elAlBookingUrl);
      if (result) return result;
    } catch (e) {
      console.log(`[ElAl] Direct scrape failed (${e.message}), falling back to Google Flights...`);
    }
  } else {
    console.log('[ElAl] No BrightData proxy configured, using Google Flights fallback...');
  }

  // Fallback: Google Flights
  return await checkElAlGoogleFlights(origin, destination, date, passengers, elAlBookingUrl);
}

// ─── Direct El Al scraping via BrightData proxy ──────────
async function checkElAlDirect(origin, destination, date, passengers, bookingUrl) {
  const br = await getProxyBrowser();
  const page = await br.newPage();
  await page.setViewport({ width: 1366, height: 768 });

  // Authenticate with BrightData proxy
  await page.authenticate({
    username: BRIGHTDATA_USER,
    password: BRIGHTDATA_PASS,
  });

  // Set realistic headers
  await page.setExtraHTTPHeaders({
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  });

  let flightApiData = null;

  // Intercept El Al's API responses
  page.on('response', async (response) => {
    const resUrl = response.url();
    try {
      const ct = response.headers()['content-type'] || '';
      if (ct.includes('json') && (
        resUrl.includes('/api/') ||
        resUrl.includes('flight') ||
        resUrl.includes('search') ||
        resUrl.includes('availability') ||
        resUrl.includes('offer') ||
        resUrl.includes('fare')
      )) {
        const text = await response.text();
        if (text.length > 100) { // skip tiny responses
          try {
            const data = JSON.parse(text);
            // Look for flight data in various structures El Al might use
            if (data && (
              data.flights || data.results || data.outbound || data.Flights ||
              data.FlightResults || data.offers || data.Offers ||
              data.journeys || data.Journeys || data.itineraries ||
              (Array.isArray(data) && data.length > 0 && (data[0].price || data[0].fare || data[0].flight))
            )) {
              console.log(`[ElAl Direct] Intercepted API data from: ${resUrl.substring(0, 100)}`);
              flightApiData = data;
            }
          } catch (e) {}
        }
      }
    } catch (e) {}
  });

  const searchUrl = `https://www.elal.com/en/booking/flight-select/?isOneWay=true&origin=${origin}&destination=${destination}&dep=${date}&adult=${passengers}`;

  try {
    console.log(`[ElAl Direct] Navigating via BrightData proxy: ${searchUrl}`);
    await page.goto(searchUrl, { waitUntil: 'networkidle2', timeout: 90000 });

    // Check if we got blocked
    const pageTitle = await page.title();
    if (pageTitle.toLowerCase().includes('access denied') || pageTitle.toLowerCase().includes('blocked')) {
      await page.close();
      throw new Error('Still blocked by El Al even with proxy');
    }

    // Wait for SPA to render flight results
    await new Promise(r => setTimeout(r, 10000));

    // Try waiting for flight-specific elements
    try {
      await page.waitForSelector('[class*="flight"], [class*="Flight"], [class*="offer"], [class*="Offer"], [class*="journey"], [class*="result"], [class*="itinerary"], [data-testid*="flight"]', { timeout: 15000 });
      console.log('[ElAl Direct] Flight elements found on page!');
    } catch (e) {
      console.log('[ElAl Direct] No obvious flight elements found, trying DOM scan...');
    }

    // DOM scraping - broader search patterns
    const pageFlights = await page.evaluate(() => {
      const results = [];

      // Strategy 1: Look for any elements with price + flight-like content
      const allElements = document.querySelectorAll('div, li, article, section, tr');
      for (const el of allElements) {
        const text = el.innerText || '';
        if (text.length < 20 || text.length > 2000) continue; // skip too small/large

        const hasPrice = /\$[\d,]+|₪[\d,]+|\d+\s*(USD|ILS|EUR|NIS)/i.test(text);
        const hasTime = /\d{1,2}:\d{2}/.test(text);
        const hasFlightIndicator = /(LY\s*\d|nonstop|direct|stop|economy|business|class)/i.test(text);

        if (hasPrice && (hasTime || hasFlightIndicator)) {
          const priceMatch = text.match(/\$[\d,]+/);
          const ilsPriceMatch = text.match(/₪([\d,]+)/);
          const timeMatches = text.match(/\d{1,2}:\d{2}/g);
          const flightNumMatch = text.match(/LY\s*\d+/i);
          const stopsMatch = text.match(/(nonstop|direct|\d+\s*stop)/i);

          results.push({
            price: priceMatch ? priceMatch[0] : (ilsPriceMatch ? '₪' + ilsPriceMatch[1] : null),
            times: timeMatches || [],
            flightNum: flightNumMatch ? flightNumMatch[0] : null,
            stops: stopsMatch ? stopsMatch[0] : null,
            text: text.substring(0, 400),
          });
        }
      }

      // Strategy 2: Check for no-results messages
      const bodyText = document.body.innerText;
      if (bodyText.match(/no (flights?|results?|availability)/i) || bodyText.includes('אין טיסות')) {
        return [{ noFlights: true }];
      }

      // Deduplicate by price+time combo
      const unique = [];
      const seen = new Set();
      for (const r of results) {
        const key = (r.price || '') + (r.times[0] || '') + (r.flightNum || '');
        if (!seen.has(key) && key.length > 0) {
          seen.add(key);
          unique.push(r);
        }
      }
      return unique;
    });

    await page.close();

    // Process API data first (most reliable)
    if (flightApiData) {
      const flightArrayKeys = ['flights', 'results', 'Flights', 'FlightResults', 'offers', 'Offers', 'journeys', 'Journeys', 'itineraries'];
      let flights = [];
      for (const key of flightArrayKeys) {
        if (flightApiData[key]) {
          flights = Array.isArray(flightApiData[key]) ? flightApiData[key] : Object.values(flightApiData[key]);
          break;
        }
      }
      if (Array.isArray(flightApiData) && flightApiData.length > 0) flights = flightApiData;

      if (flights.length > 0) {
        const flightDetails = flights.map((f, i) => ({
          airline: 'El Al',
          flightNum: f.flightNumber || f.flightNum || f.number || f.flightNo || `LY${i + 1}`,
          from: origin,
          to: destination,
          departure: f.departureTime || f.departure || f.depTime || date,
          arrival: f.arrivalTime || f.arrival || f.arrTime || '',
          className: f.cabin || f.class || f.cabinClass || 'Economy',
          freeSeats: f.seatsAvailable || f.seats || f.availability || 1,
          price: f.price || f.totalPrice || f.fare || f.amount || null,
          currency: 'USD',
          bookingUrl: bookingUrl,
          source: 'direct',
        }));
        const totalSeats = flightDetails.reduce((s, f) => s + (f.freeSeats || 0), 0);
        console.log(`[ElAl Direct] API: Found ${flightDetails.length} flight(s), ${totalSeats} total seats`);
        return {
          available: true,
          freeSeats: totalSeats,
          flights: flightDetails,
          reason: 'seats_available',
          source: 'elal_direct_api',
        };
      }
    }

    // Process DOM data
    if (pageFlights.length > 0 && !pageFlights[0]?.noFlights) {
      const flightDetails = pageFlights.filter(f => f.price).map((f, i) => ({
        airline: 'El Al',
        flightNum: f.flightNum || `LY${i + 1}`,
        from: origin,
        to: destination,
        departure: f.times[0] || date,
        arrival: f.times[1] || '',
        className: 'Economy',
        freeSeats: 1,
        price: f.price,
        stops: f.stops,
        currency: 'USD',
        bookingUrl: bookingUrl,
        source: 'direct_dom',
      }));
      if (flightDetails.length > 0) {
        console.log(`[ElAl Direct] DOM: Found ${flightDetails.length} flight(s)`);
        return {
          available: true,
          freeSeats: flightDetails.length,
          flights: flightDetails,
          reason: 'seats_available',
          source: 'elal_direct_dom',
        };
      }
    }

    if (pageFlights.length > 0 && pageFlights[0]?.noFlights) {
      return { available: false, freeSeats: 0, flights: [], reason: 'no_flights', source: 'elal_direct' };
    }

    // Couldn't parse anything — don't return, let it fall through to Google Flights
    throw new Error('Could not parse El Al page - DOM structure unrecognized');
  } catch (e) {
    try { await page.close(); } catch (_) {}
    throw e;
  }
}

// ─── Google Flights fallback for El Al ───────────────────
async function checkElAlGoogleFlights(origin, destination, date, passengers, bookingUrl) {
  const br = await getBrowser();
  const page = await br.newPage();
  await page.setViewport({ width: 1366, height: 768 });

  // Use structured Google Flights URL instead of free-text query
  // Format: /travel/flights/search?tfs=...  or simpler: use the query param approach
  const gfQuery = `Flights from ${origin} to ${destination} on ${date} one way ${passengers} passenger`;
  const searchUrl = `https://www.google.com/travel/flights?q=${encodeURIComponent(gfQuery)}&hl=en`;

  try {
    console.log(`[GF] Google Flights fallback: ${searchUrl}`);
    await page.goto(searchUrl, { waitUntil: 'networkidle2', timeout: 60000 });
    await new Promise(r => setTimeout(r, 8000)); // extra wait for SPA rendering

    // Debug: log what we see on the page
    const debugInfo = await page.evaluate(() => {
      const body = document.body;
      if (!body) return { error: 'no body element' };
      const text = body.innerText || '';
      const firstChars = text.substring(0, 300);
      // Check for common Google Flights selectors (they rotate class names)
      const selectorChecks = {
        'li.pIav2d': document.querySelectorAll('li.pIav2d').length,
        'li[data-ved]': document.querySelectorAll('li[data-ved]').length,
        'div[data-ved]': document.querySelectorAll('div[data-ved]').length,
        '[role="listitem"]': document.querySelectorAll('[role="listitem"]').length,
        'ul li': document.querySelectorAll('ul li').length,
        // Look for price elements
        'span with $': [...document.querySelectorAll('span')].filter(s => /^\$[\d,]+$/.test(s.textContent.trim())).length,
        'any $ text': (text.match(/\$[\d,]+/g) || []).length,
      };
      return { firstChars, selectorChecks, title: document.title };
    });
    console.log(`[GF] Debug - Title: "${debugInfo.title}"`);
    console.log(`[GF] Debug - Selectors:`, JSON.stringify(debugInfo.selectorChecks));
    console.log(`[GF] Debug - Page starts with: "${(debugInfo.firstChars || '').substring(0, 150)}"`);

    const pageFlights = await page.evaluate(() => {
      const results = [];
      const seen = new Set();

      // Strategy 1: Try known Google Flights selectors (they rotate class names)
      const knownSelectors = ['li.pIav2d', 'li[data-ved]', '[role="listitem"]'];
      let cards = [];
      for (const sel of knownSelectors) {
        const found = document.querySelectorAll(sel);
        if (found.length > 0 && found.length < 100) {
          // Verify these look like flight cards (have prices)
          const withPrices = [...found].filter(el => /\$[\d,]+/.test(el.innerText || ''));
          if (withPrices.length > 0) {
            cards = withPrices;
            break;
          }
        }
      }

      // Strategy 2: If no cards found, scan ALL elements for flight-like content
      if (cards.length === 0) {
        const allEls = document.querySelectorAll('div, li, article, section');
        for (const el of allEls) {
          const text = el.innerText || '';
          if (text.length < 30 || text.length > 2000) continue;
          const hasPrice = /\$[\d,]+/.test(text);
          const hasAirline = /(El\s*Al|Etihad|Turkish|Lufthansa|United|Delta|American|Swiss|LOT|Austrian|Arkia|Israir|British|Air France|KLM|Emirates|Qatar|Aegean|Ryanair|Wizz)/i.test(text);
          const hasTime = /\d{1,2}:\d{2}\s*[AP]M/i.test(text);
          const hasDuration = /\d+\s*hr/i.test(text);
          if (hasPrice && hasAirline && (hasTime || hasDuration)) {
            // Check this isn't a parent of an already-found card
            let isDuplicate = false;
            for (const existing of cards) {
              if (el.contains(existing) || existing.contains(el)) {
                isDuplicate = true;
                break;
              }
            }
            if (!isDuplicate) cards.push(el);
          }
        }
      }

      // Parse each flight card
      for (const card of cards) {
        const text = card.innerText || '';
        const priceMatch = text.match(/\$[\d,]+/);
        const airlineMatch = text.match(/(El\s*Al|Etihad|Turkish|Lufthansa|United|Delta|American|Swiss|LOT|Austrian|Arkia|Israir|British|Air France|KLM|Emirates|Qatar|Aegean|Ryanair|Wizz)/i);
        const routeMatch = text.match(/([A-Z]{3})[–\-]([A-Z]{3})/);
        const stopsMatch = text.match(/(Nonstop|\d+\s*stop)/i);
        const durationMatch = text.match(/(\d+\s*hr\s*\d*\s*min?)/);
        const timeMatch = text.match(/(\d{1,2}:\d{2}\s*[AP]M)/gi);
        if (priceMatch) {
          const airline = airlineMatch ? airlineMatch[1] : 'Unknown';
          const key = airline + '-' + priceMatch[0] + '-' + (timeMatch ? timeMatch[0] : '');
          if (!seen.has(key)) {
            seen.add(key);
            results.push({
              airline, price: priceMatch[0],
              from: routeMatch ? routeMatch[1] : '', to: routeMatch ? routeMatch[2] : '',
              stops: stopsMatch ? stopsMatch[0] : '', duration: durationMatch ? durationMatch[1] : '',
              departure: timeMatch && timeMatch[0] ? timeMatch[0] : '',
              arrival: timeMatch && timeMatch[1] ? timeMatch[1] : '',
            });
          }
        }
      }

      // Check for explicit "no flights" messages
      const bodyText = (document.body && document.body.innerText) || '';
      if (bodyText.includes('No flights match') || bodyText.includes('Try different dates') || bodyText.includes('No results found')) {
        return [{ noFlights: true }];
      }

      return results;
    });

    await page.close();

    console.log(`[GF] Parsed ${pageFlights.length} flight result(s)${pageFlights[0]?.noFlights ? ' (no_flights message)' : ''}`);

    if (pageFlights.length > 0 && pageFlights[0]?.noFlights) {
      return { available: false, freeSeats: 0, flights: [], reason: 'no_flights', source: 'google_flights' };
    }

    if (pageFlights.length === 0) {
      console.log(`[GF] WARNING: Found 0 flights and no "no flights" message — Google may have changed DOM or blocked the request`);
      return { available: false, freeSeats: 0, flights: [], reason: 'no_flights (parser found nothing — DOM may have changed)', source: 'google_flights' };
    }

    const elAlFlights = pageFlights.filter(f => f.airline && f.airline.toLowerCase().replace(/\s/g, '').includes('elal'));
    const allFlights = pageFlights;

    // Include ALL airline flights, not just El Al — user wants to see all options
    const flightsToShow = elAlFlights.length > 0 ? elAlFlights : allFlights;

    const flightDetails = flightsToShow.map((f, i) => ({
      airline: f.airline || 'Unknown', flightNum: f.airline && f.airline.toLowerCase().includes('el') ? `LY${i + 1}` : `${f.airline} ${i + 1}`,
      from: f.from || origin, to: f.to || destination,
      departure: f.departure || date, arrival: f.arrival || '',
      className: 'Economy', freeSeats: 1,
      price: f.price, currency: 'USD', stops: f.stops, duration: f.duration,
      bookingUrl: bookingUrl, source: 'google_flights',
    }));

    let reason = 'no_flights';
    if (elAlFlights.length > 0) reason = 'seats_available';
    else if (allFlights.length > 0) reason = 'seats_available';

    return {
      available: flightDetails.length > 0,
      freeSeats: flightDetails.length,
      flights: flightDetails,
      reason, source: 'google_flights',
      allAirlines: allFlights.map(f => ({
        airline: f.airline, price: f.price, stops: f.stops,
        departure: f.departure, arrival: f.arrival, duration: f.duration,
      })),
    };
  } catch (e) {
    try { await page.close(); } catch (_) {}
    throw e;
  }
}

// ─── Build Air Haifa URL from route + date ───────────────
function buildAirHaifaUrl(origin, destination, date, passengers = 1) {
  // Air Haifa URL format: https://airhaifa.com/flight-results/TLV-ATH/2026-03-30/NA/{pax}/0/0?breakdown=%7B%7D
  return `https://airhaifa.com/flight-results/${origin}-${destination}/${date}/NA/${passengers}/0/0?breakdown=%7B%7D`;
}

// ─── Generic flight checker router ────────────────────────
async function checkFlight(watch) {
  switch (watch.airline) {
    case 'airhaifa': {
      // If no URL but has route+date, auto-generate the URL
      const url = watch.url || buildAirHaifaUrl(watch.origin, watch.destination, watch.date, watch.passengers || 1);
      watch.url = url; // store for notifications/booking
      return await checkAirHaifa(url);
    }
    case 'elal': {
      return await checkElAl(watch.origin, watch.destination, watch.date, watch.passengers || 1);
    }
    default:
      // Try generic URL scraping
      return await checkAirHaifa(watch.url);
  }
}

// ─── Auto-booking (Air Haifa) ─────────────────────────────
async function attemptAutoBook(watch, flightResult) {
  if (!watch.autoBook) return { booked: false, reason: 'Auto-book toggle is off' };
  if (!watch.profileId) return { booked: false, reason: 'No profile selected — select a profile when adding the monitor' };

  const profile = userProfiles[watch.profileId];
  if (!profile) return { booked: false, reason: 'Profile was deleted (server restarted?) — re-add your profile in My Info tab and create a new monitor' };

  console.log(`[AutoBook] Attempting to book for ${profile.firstName} ${profile.lastName}...`);

  // Route to airline-specific booker
  if (watch.airline === 'elal') {
    return await attemptAutoBookElAl(watch, flightResult, profile);
  }

  // Air Haifa booking
  const br = await getBrowser();
  const page = await br.newPage();
  await page.setViewport({ width: 1366, height: 768 });

  try {
    await page.goto(watch.url, { waitUntil: 'networkidle2', timeout: 45000 });
    await new Promise(r => setTimeout(r, 5000));

    // Try to click on the first available flight
    const clicked = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('button, a, [role="button"]')];
      const bookBtn = btns.find(b => {
        const text = (b.innerText || '').toLowerCase();
        return text.includes('book') || text.includes('select') || text.includes('הזמן') || text.includes('בחר');
      });
      if (bookBtn) { bookBtn.click(); return true; }
      return false;
    });

    if (!clicked) {
      await page.close();
      return { booked: false, reason: 'Could not find booking button' };
    }

    await new Promise(r => setTimeout(r, 3000));

    // Fill in passenger details + payment
    const formFields = {
      firstName: profile.firstName,
      lastName: profile.lastName,
      email: profile.email,
      phone: profile.phone,
      passport: decrypt(profile.passport),
      dob: profile.dob,
      cardNumber: decrypt(profile.cardNumber),
      cardExp: decrypt(profile.cardExp),
      cardCvv: decrypt(profile.cardCvv),
    };

    for (const [field, value] of Object.entries(formFields)) {
      if (!value) continue;
      try {
        await page.evaluate((f, v) => {
          const inputs = document.querySelectorAll('input, select');
          for (const input of inputs) {
            const name = (input.name || input.id || input.placeholder || '').toLowerCase();
            const label = input.closest('label')?.innerText?.toLowerCase() || '';
            const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
            const combined = name + ' ' + label + ' ' + ariaLabel;

            const fieldMappings = {
              firstName: ['first', 'fname', 'given', 'שם פרטי'],
              lastName: ['last', 'lname', 'surname', 'family', 'שם משפחה'],
              email: ['email', 'mail', 'דוא"ל', 'אימייל'],
              phone: ['phone', 'tel', 'mobile', 'טלפון'],
              passport: ['passport', 'id', 'document', 'דרכון', 'תעודת זהות'],
              dob: ['birth', 'dob', 'date of birth', 'תאריך לידה'],
              cardNumber: ['card', 'credit', 'cc', 'כרטיס אשראי', 'מספר כרטיס'],
              cardExp: ['expir', 'exp', 'valid', 'תוקף'],
              cardCvv: ['cvv', 'cvc', 'security', 'csv'],
            };

            const keywords = fieldMappings[f] || [f];
            if (keywords.some(k => combined.includes(k))) {
              input.value = v;
              input.dispatchEvent(new Event('input', { bubbles: true }));
              input.dispatchEvent(new Event('change', { bubbles: true }));
              break;
            }
          }
        }, field, value);
      } catch (e) {
        console.log(`[AutoBook] Could not fill ${field}: ${e.message}`);
      }
    }

    // Check for captcha
    const hasCaptcha = await page.evaluate(() => {
      return !!document.querySelector('.g-recaptcha, [data-sitekey], iframe[src*="recaptcha"]');
    });

    if (hasCaptcha && TWOCAPTCHA_KEY) {
      const siteKey = await page.evaluate(() => {
        const el = document.querySelector('.g-recaptcha, [data-sitekey]');
        return el ? el.getAttribute('data-sitekey') : null;
      });

      if (siteKey) {
        try {
          const token = await solveCaptcha(siteKey, watch.url);
          await page.evaluate((t) => {
            const textarea = document.querySelector('#g-recaptcha-response, [name="g-recaptcha-response"]');
            if (textarea) {
              textarea.value = t;
              textarea.dispatchEvent(new Event('change', { bubbles: true }));
            }
            // Also try callback
            if (typeof window.captchaCallback === 'function') window.captchaCallback(t);
            if (typeof window.onCaptchaSuccess === 'function') window.onCaptchaSuccess(t);
          }, token);
        } catch (e) {
          console.log(`[AutoBook] Captcha solve failed: ${e.message}`);
        }
      }
    }

    // Try to submit
    await new Promise(r => setTimeout(r, 2000));
    const submitted = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('button, input[type="submit"], a')];
      const submitBtn = btns.find(b => {
        const text = (b.innerText || b.value || '').toLowerCase();
        return text.includes('continue') || text.includes('submit') || text.includes('next') ||
               text.includes('המשך') || text.includes('שלח') || text.includes('book');
      });
      if (submitBtn) { submitBtn.click(); return true; }
      return false;
    });

    await new Promise(r => setTimeout(r, 5000));

    // Take a "screenshot" via page content for logging
    const pageText = await page.evaluate(() => document.body.innerText.substring(0, 500));
    await page.close();

    return {
      booked: submitted,
      reason: submitted ? 'Form submitted - check email for confirmation' : 'Could not find submit button',
      pagePreview: pageText,
    };
  } catch (e) {
    try { await page.close(); } catch (_) {}
    return { booked: false, reason: 'Error: ' + e.message };
  }
}

// ─── Stealth helpers for El Al booking ───────────────────
function randomDelay(min = 200, max = 800) {
  return new Promise(r => setTimeout(r, Math.floor(Math.random() * (max - min)) + min));
}

async function humanType(page, selector, text) {
  await page.focus(selector);
  await randomDelay(100, 300);
  for (const char of text) {
    await page.keyboard.type(char, { delay: Math.floor(Math.random() * 120) + 40 });
    if (Math.random() < 0.1) await randomDelay(200, 600); // occasional pause
  }
}

async function humanClick(page, selector) {
  const el = await page.$(selector);
  if (!el) return false;
  const box = await el.boundingBox();
  if (!box) return false;
  // Move to element with slight randomness
  const x = box.x + box.width * (0.3 + Math.random() * 0.4);
  const y = box.y + box.height * (0.3 + Math.random() * 0.4);
  await page.mouse.move(x, y, { steps: Math.floor(Math.random() * 10) + 5 });
  await randomDelay(50, 200);
  await page.mouse.click(x, y);
  return true;
}

// Apply heavy anti-detection overrides to a page
async function applyStealthOverrides(page) {
  await page.evaluateOnNewDocument(() => {
    // Override webdriver flag
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

    // Override plugins to look real
    Object.defineProperty(navigator, 'plugins', {
      get: () => {
        const plugins = [
          { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
          { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
          { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
        ];
        plugins.length = 3;
        return plugins;
      },
    });

    // Override languages
    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en', 'he'] });

    // Chrome runtime
    window.chrome = {
      runtime: { onConnect: { addListener: () => {} }, sendMessage: () => {}, id: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
      loadTimes: () => ({ requestTime: Date.now() / 1000 - Math.random() * 5 }),
      csi: () => ({ startE: Date.now(), onloadT: Date.now() + 300 }),
    };

    // Override permissions query
    const origQuery = window.Permissions?.prototype?.query;
    if (origQuery) {
      window.Permissions.prototype.query = function(parameters) {
        if (parameters.name === 'notifications') {
          return Promise.resolve({ state: Notification.permission });
        }
        return origQuery.call(this, parameters);
      };
    }

    // Fake canvas fingerprint (subtle noise)
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
      if (this.width > 16 && this.height > 16) {
        const ctx = this.getContext('2d');
        if (ctx) {
          const imageData = ctx.getImageData(0, 0, 1, 1);
          imageData.data[0] = imageData.data[0] ^ 1; // tiny noise
          ctx.putImageData(imageData, 0, 0);
        }
      }
      return origToDataURL.call(this, type);
    };

    // WebGL vendor/renderer
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
      if (param === 37445) return 'Intel Inc.';
      if (param === 37446) return 'Intel Iris OpenGL Engine';
      return getParameter.call(this, param);
    };

    // Fake connection info
    if (navigator.connection) {
      Object.defineProperty(navigator.connection, 'rtt', { get: () => 50 + Math.floor(Math.random() * 100) });
    }

    // Override deviceMemory and hardwareConcurrency
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });

    // Remove automation indicators from DOM
    const observer = new MutationObserver(() => {
      document.querySelectorAll('[aria-label*="automation"], [class*="automation"]').forEach(el => el.remove());
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  });
}

// Launch a fresh stealth browser for El Al booking
async function launchStealthBrowser(useProxy = true) {
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || undefined;
  const randomUA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  ];
  const ua = randomUA[Math.floor(Math.random() * randomUA.length)];

  const args = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-blink-features=AutomationControlled',
    '--disable-infobars',
    '--disable-background-timer-throttling',
    '--disable-renderer-backgrounding',
    '--window-size=1366,768',
    `--user-agent=${ua}`,
    '--lang=en-US,en',
  ];

  if (useProxy && hasBrightData) {
    args.push(`--proxy-server=http://${BRIGHTDATA_HOST}:${BRIGHTDATA_PORT}`);
    args.push('--ignore-certificate-errors');
  }

  const launchOpts = {
    headless: 'new',
    args,
    ignoreDefaultArgs: ['--enable-automation'],
  };
  if (executablePath) launchOpts.executablePath = executablePath;

  const stealthBrowser = await puppeteerExtra.launch(launchOpts);
  return stealthBrowser;
}

// ─── El Al stealth auto-booker ──────────────────────────
// Attempts real booking via booking.elal.com Angular SPA with aggressive anti-detection.
// Falls back to booking links if stealth fails.
async function attemptAutoBookElAl(watch, flightResult, profile) {
  const passengers = watch.passengers || 1;
  const cabinPref = (watch.cabinClass || 'economy').toLowerCase();

  // Pick the best (cheapest) flight from results
  let bestFlight = null;
  if (flightResult.flights && flightResult.flights.length > 0) {
    const sorted = [...flightResult.flights].sort((a, b) => {
      const priceA = parseFloat(String(a.price || '0').replace(/[^0-9.]/g, ''));
      const priceB = parseFloat(String(b.price || '0').replace(/[^0-9.]/g, ''));
      return priceA - priceB;
    });
    bestFlight = sorted[0];
  }

  // Always generate fallback booking links
  const elAlSearchUrl = `https://www.elal.com/en/booking/flight-select/?isOneWay=true&origin=${watch.origin}&destination=${watch.destination}&dep=${watch.date}&adult=${passengers}`;
  const googleFlightsUrl = `https://www.google.com/travel/flights?q=Flights+from+${watch.origin}+to+${watch.destination}+on+${watch.date}+one+way+${passengers}+passenger&hl=en`;
  const bookingLinks = { elal: elAlSearchUrl, google: googleFlightsUrl };

  // --- ATTEMPT 1: Stealth booking via booking.elal.com ---
  let stealthBrowser = null;
  try {
    console.log(`[AutoBook ElAl] Launching stealth browser for booking...`);
    stealthBrowser = await launchStealthBrowser(true);
    const page = await stealthBrowser.newPage();

    // Apply heavy anti-detection
    await applyStealthOverrides(page);
    await page.setViewport({ width: 1366, height: 768 });
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9,he;q=0.8',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"macOS"',
    });

    // Authenticate with BrightData if using proxy
    if (hasBrightData) {
      await page.authenticate({ username: BRIGHTDATA_USER, password: BRIGHTDATA_PASS });
    }

    // Navigate to El Al booking search page
    const bookingUrl = `https://booking.elal.com/newbe/booking/availability?isOneWay=true&origin=${watch.origin}&destination=${watch.destination}&ADT=${passengers}&CHD=0&INF=0&dep=${watch.date}&promoCode=&cls=Economy&flex=1`;
    console.log(`[AutoBook ElAl] Navigating to: ${bookingUrl}`);

    await page.goto(bookingUrl, { waitUntil: 'networkidle2', timeout: 60000 });
    await randomDelay(3000, 5000);

    // Check if we got blocked
    const pageTitle = await page.title();
    const bodyPreview = await page.evaluate(() => (document.body && document.body.innerText || '').substring(0, 500));
    console.log(`[AutoBook ElAl] Page title: "${pageTitle}"`);
    console.log(`[AutoBook ElAl] Body preview: "${bodyPreview.substring(0, 200)}"`);

    const isBlocked = pageTitle.toLowerCase().includes('not allowed') ||
                      pageTitle.toLowerCase().includes('access denied') ||
                      pageTitle.toLowerCase().includes('blocked') ||
                      bodyPreview.toLowerCase().includes('request is not allowed') ||
                      bodyPreview.toLowerCase().includes('access denied');

    if (isBlocked) {
      console.log(`[AutoBook ElAl] ⚠️ BLOCKED by WAF — falling back to booking links`);
      await page.close();
      await stealthBrowser.close();

      return {
        booked: false,
        reason: bestFlight
          ? `Found ${bestFlight.airline} ${bestFlight.flightNum} at $${bestFlight.price} — El Al blocked automated booking, use the links below`
          : `Flights available — El Al blocked automated booking, use the links below`,
        bookingLinks,
        selectedFlight: bestFlight,
        isLinkOnly: true,
        stealthAttempted: true,
      };
    }

    // ─── STEP 1: Wait for Angular SPA to load flight results ───
    console.log(`[AutoBook ElAl] Page loaded! Waiting for flight results to render...`);
    await randomDelay(5000, 8000);

    // Simulate human scrolling
    await page.mouse.move(683, 400);
    await page.mouse.wheel({ deltaY: 300 });
    await randomDelay(1000, 2000);

    // Look for flight selection buttons/cards
    const flightCards = await page.evaluate(() => {
      const cards = document.querySelectorAll('[class*="flight"], [class*="Flight"], [class*="offer"], [class*="result"], [class*="journey"], [class*="avail"], button[class*="fare"], [class*="bound"]');
      return Array.from(cards).map((c, i) => ({
        index: i,
        text: (c.innerText || '').substring(0, 200),
        tag: c.tagName,
        hasPrice: /\$|₪|\d+/.test(c.innerText || ''),
        isClickable: c.tagName === 'BUTTON' || c.tagName === 'A' || c.getAttribute('role') === 'button' || c.style.cursor === 'pointer',
      }));
    });

    console.log(`[AutoBook ElAl] Found ${flightCards.length} potential flight cards`);
    flightCards.forEach((c, i) => {
      if (i < 5) console.log(`[AutoBook ElAl]   Card ${i}: [${c.tag}] "${c.text.substring(0, 80)}" price=${c.hasPrice} clickable=${c.isClickable}`);
    });

    // ─── STEP 2: Click cheapest/first flight ───
    let clickedFlight = false;
    if (flightCards.length > 0) {
      // Try clicking the first card with a price
      const priceCard = flightCards.find(c => c.hasPrice) || flightCards[0];
      const allCards = await page.$$('[class*="flight"], [class*="Flight"], [class*="offer"], [class*="result"], [class*="journey"], [class*="avail"], button[class*="fare"], [class*="bound"]');
      if (allCards[priceCard.index]) {
        const box = await allCards[priceCard.index].boundingBox();
        if (box) {
          console.log(`[AutoBook ElAl] Clicking flight card ${priceCard.index}...`);
          await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 8 });
          await randomDelay(200, 500);
          await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
          clickedFlight = true;
          await randomDelay(3000, 5000);
        }
      }
    }

    // Also try clicking any "Select" or "Choose" or "בחר" buttons
    if (!clickedFlight) {
      const selectClicked = await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button, a, [role="button"]')];
        const selectBtn = btns.find(b => {
          const t = (b.innerText || '').toLowerCase();
          return t.includes('select') || t.includes('choose') || t.includes('בחר') || t.includes('continue');
        });
        if (selectBtn) { selectBtn.click(); return true; }
        return false;
      });
      if (selectClicked) {
        clickedFlight = true;
        console.log(`[AutoBook ElAl] Clicked select/choose button`);
        await randomDelay(3000, 5000);
      }
    }

    // ─── STEP 3: Handle fare selection (Economy/Flex/Business) ───
    await randomDelay(2000, 3000);
    const fareClicked = await page.evaluate((pref) => {
      const btns = [...document.querySelectorAll('button, a, [role="button"], [class*="fare"], [class*="Fare"]')];
      // Try to match preferred cabin class
      const fareBtn = btns.find(b => {
        const t = (b.innerText || '').toLowerCase();
        return t.includes(pref) || t.includes('classic') || t.includes('lite') || t.includes('economy');
      });
      if (fareBtn) { fareBtn.click(); return true; }
      // Fallback: click first fare option
      const anyFare = btns.find(b => (b.innerText || '').toLowerCase().match(/(select|choose|from \$|add to cart|continue|בחר)/));
      if (anyFare) { anyFare.click(); return true; }
      return false;
    }, cabinPref);
    if (fareClicked) console.log(`[AutoBook ElAl] Selected fare option`);
    await randomDelay(3000, 5000);

    // ─── STEP 4: Fill passenger details form ───
    // El Al uses Angular form with specific IDs: #form-0-civility, #form-0-firstName, etc.
    const formExists = await page.evaluate(() => {
      return !!(document.querySelector('#form-0-firstName') ||
                document.querySelector('[formcontrolname="firstName"]') ||
                document.querySelector('input[name*="first"]') ||
                document.querySelector('input[placeholder*="First"]'));
    });

    if (formExists) {
      console.log(`[AutoBook ElAl] 🎯 Passenger form detected! Filling details...`);

      // Title/Civility
      try {
        const civilitySelector = '#form-0-civility, [formcontrolname="civility"], select[name*="title"], select[name*="civility"]';
        const hasCivility = await page.$(civilitySelector);
        if (hasCivility) {
          await humanClick(page, civilitySelector);
          await randomDelay(300, 600);
          await page.select(civilitySelector, 'MR').catch(() => {});
          // Also try clicking "Mr" option if it's a dropdown
          await page.evaluate(() => {
            const opts = document.querySelectorAll('option, [role="option"], li');
            const mrOpt = [...opts].find(o => (o.innerText || '').match(/^Mr\.?$/i));
            if (mrOpt) mrOpt.click();
          });
          await randomDelay(500, 800);
        }
      } catch (e) { console.log(`[AutoBook ElAl] Civility: ${e.message}`); }

      // First Name
      try {
        const fnSelector = '#form-0-firstName, [formcontrolname="firstName"], input[name*="first"], input[placeholder*="First"]';
        const hasFn = await page.$(fnSelector);
        if (hasFn) {
          await humanType(page, fnSelector, profile.firstName);
          console.log(`[AutoBook ElAl] ✓ First name filled`);
          await randomDelay(300, 700);
        }
      } catch (e) { console.log(`[AutoBook ElAl] First name: ${e.message}`); }

      // Last Name
      try {
        const lnSelector = '#form-0-lastName, [formcontrolname="lastName"], input[name*="last"], input[placeholder*="Last"]';
        const hasLn = await page.$(lnSelector);
        if (hasLn) {
          await humanType(page, lnSelector, profile.lastName);
          console.log(`[AutoBook ElAl] ✓ Last name filled`);
          await randomDelay(300, 700);
        }
      } catch (e) { console.log(`[AutoBook ElAl] Last name: ${e.message}`); }

      // Date of Birth (month, day, year separate fields)
      if (profile.dob) {
        const dobParts = profile.dob.split(/[-\/]/); // expect YYYY-MM-DD or MM/DD/YYYY
        let dobMonth, dobDay, dobYear;
        if (dobParts[0].length === 4) { // YYYY-MM-DD
          dobYear = dobParts[0]; dobMonth = dobParts[1]; dobDay = dobParts[2];
        } else { // MM/DD/YYYY
          dobMonth = dobParts[0]; dobDay = dobParts[1]; dobYear = dobParts[2];
        }
        try {
          const monthSel = '#form-0-month, [formcontrolname="month"], select[name*="month"]';
          if (await page.$(monthSel)) { await page.select(monthSel, String(parseInt(dobMonth))).catch(() => {}); }
          await randomDelay(300, 500);
          const daySel = '#form-0-day, [formcontrolname="day"], select[name*="day"]';
          if (await page.$(daySel)) { await page.select(daySel, String(parseInt(dobDay))).catch(() => {}); }
          await randomDelay(300, 500);
          const yearSel = '#form-0-year, [formcontrolname="year"], select[name*="year"]';
          if (await page.$(yearSel)) { await page.select(yearSel, dobYear).catch(() => {}); }
          console.log(`[AutoBook ElAl] ✓ DOB filled`);
          await randomDelay(300, 700);
        } catch (e) { console.log(`[AutoBook ElAl] DOB: ${e.message}`); }
      }

      // Email
      try {
        const emailSel = '#form-0-email, [formcontrolname="email"], input[type="email"], input[name*="email"]';
        const hasEmail = await page.$(emailSel);
        if (hasEmail) {
          await humanType(page, emailSel, profile.email || watch.email);
          console.log(`[AutoBook ElAl] ✓ Email filled`);
          await randomDelay(300, 700);
        }
      } catch (e) { console.log(`[AutoBook ElAl] Email: ${e.message}`); }

      // Phone
      try {
        const phoneSel = '#form-0-number, [formcontrolname="number"], input[type="tel"], input[name*="phone"]';
        const hasPhone = await page.$(phoneSel);
        if (hasPhone) {
          await humanType(page, phoneSel, profile.phone);
          console.log(`[AutoBook ElAl] ✓ Phone filled`);
          await randomDelay(300, 700);
        }
      } catch (e) { console.log(`[AutoBook ElAl] Phone: ${e.message}`); }

      // Scroll down to show we've filled the form
      await page.mouse.wheel({ deltaY: 200 });
      await randomDelay(1000, 2000);

      // Click "Continue" / "Next" / "המשך"
      const continueClicked = await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button, a[role="button"], [type="submit"]')];
        const contBtn = btns.find(b => {
          const t = (b.innerText || b.value || '').toLowerCase();
          return t.includes('continue') || t.includes('next') || t.includes('המשך') || t.includes('proceed');
        });
        if (contBtn && !contBtn.disabled) { contBtn.click(); return true; }
        return false;
      });

      if (continueClicked) {
        console.log(`[AutoBook ElAl] ✓ Clicked continue — waiting for next step...`);
        await randomDelay(5000, 8000);

        // Check where we ended up
        const nextPageText = await page.evaluate(() => (document.body && document.body.innerText || '').substring(0, 500));
        console.log(`[AutoBook ElAl] Next page preview: "${nextPageText.substring(0, 200)}"`);

        const reachedPayment = nextPageText.toLowerCase().includes('payment') ||
                                nextPageText.toLowerCase().includes('credit') ||
                                nextPageText.toLowerCase().includes('תשלום') ||
                                nextPageText.toLowerCase().includes('כרטיס');

        await page.close();
        await stealthBrowser.close();

        if (reachedPayment) {
          // We got past the passenger form! But we stop before payment for safety.
          return {
            booked: false,
            reason: `✅ Passenger details filled successfully! Reached payment page — complete payment via the link below`,
            bookingLinks,
            selectedFlight: bestFlight,
            isLinkOnly: true,
            stealthAttempted: true,
            stealthReachedPayment: true,
          };
        } else {
          return {
            booked: false,
            reason: `Passenger form submitted — could not confirm next step. Use the booking links to complete`,
            bookingLinks,
            selectedFlight: bestFlight,
            isLinkOnly: true,
            stealthAttempted: true,
          };
        }
      } else {
        console.log(`[AutoBook ElAl] Could not find continue button`);
      }
    } else {
      console.log(`[AutoBook ElAl] No passenger form found on page`);
      // Log what IS on the page for debugging
      const inputCount = await page.evaluate(() => document.querySelectorAll('input, select, textarea').length);
      const btnCount = await page.evaluate(() => document.querySelectorAll('button').length);
      console.log(`[AutoBook ElAl] Page has ${inputCount} inputs, ${btnCount} buttons`);
    }

    await page.close();
    await stealthBrowser.close();

    // If we got here without being blocked but couldn't complete, still provide links
    return {
      booked: false,
      reason: bestFlight
        ? `Found ${bestFlight.airline} ${bestFlight.flightNum} at $${bestFlight.price} — stealth booking couldn't complete, use links below`
        : `Flights available — stealth booking couldn't complete all steps, use links below`,
      bookingLinks,
      selectedFlight: bestFlight,
      isLinkOnly: true,
      stealthAttempted: true,
    };

  } catch (e) {
    console.error(`[AutoBook ElAl] Stealth attempt error: ${e.message}`);
    if (stealthBrowser) { try { await stealthBrowser.close(); } catch (_) {} }

    // Fallback to links
    return {
      booked: false,
      reason: bestFlight
        ? `Found ${bestFlight.airline} ${bestFlight.flightNum} at $${bestFlight.price} — click the booking link to complete your reservation`
        : `Flights available — click the booking link to book on El Al`,
      bookingLinks,
      selectedFlight: bestFlight,
      isLinkOnly: true,
      stealthAttempted: true,
      stealthError: e.message,
    };
  }
}

// ─── Email notification ───────────────────────────────────
async function sendEmail(toString, watch, result) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.log('[Email] Skipping – no Gmail credentials');
    return;
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
  });

  const flightRows = (result.flights || []).map(f => `
    <tr>
      <td style="padding:8px;border:1px solid #ddd;">${f.airline}</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.flightNum}</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.from} → ${f.to}</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.departure ? String(f.departure).replace('T', ' ').substring(0, 16) : '-'}</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.freeSeats} seat(s)</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.price ? f.price + ' ' + (f.currency || '') : '-'}</td>
    </tr>`).join('');

  let bookingSection = '';
  if (watch.autoBook && result.bookingAttempt) {
    const ba = result.bookingAttempt;
    if (ba.isLinkOnly && ba.bookingLinks) {
      // Show booking links prominently
      bookingSection = `
        <div style="background:#e3f2fd;padding:16px;border-radius:8px;margin:16px 0;">
          <strong>🔗 Book your flight now:</strong>
          <p style="margin:12px 0 4px;">
            <a href="${ba.bookingLinks.google}" style="background:#1a73e8;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block;margin:4px 0;">Book on Google Flights →</a>
          </p>
          <p style="margin:4px 0;">
            <a href="${ba.bookingLinks.elal}" style="background:#003087;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block;margin:4px 0;">Search on El Al →</a>
          </p>
          <p style="font-size:13px;color:#555;margin-top:8px;">${ba.reason}</p>
        </div>`;
    } else {
      bookingSection = `
        <div style="background:#${ba.booked ? 'e8f5e9' : 'fff3e0'};padding:16px;border-radius:8px;margin:16px 0;">
          <strong>${ba.booked ? '✅ Auto-booking attempted!' : '⚠️ Auto-booking note:'}</strong>
          <p>${ba.reason}</p>
        </div>`;
    }
  }

  const airlineLabel = watch.airline === 'elal' ? 'El Al' : watch.airline === 'airhaifa' ? 'Air Haifa' : watch.airline;

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px;border-radius:12px 12px 0 0;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:24px;">✈️ Flight Available!</h1>
        <p style="color:#a0c4ff;margin:8px 0 0;">${airlineLabel} Availability Alert</p>
      </div>
      <div style="background:#f8f9ff;padding:30px;border-radius:0 0 12px 12px;">
        <p style="font-size:16px;color:#333;">Great news! <strong>${result.freeSeats}</strong> seat(s) found on <strong>${airlineLabel}</strong>.</p>
        ${bookingSection}
        ${flightRows ? `
          <table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;">
            <thead>
              <tr style="background:#1a1a2e;color:#fff;">
                <th style="padding:10px;text-align:left;">Airline</th>
                <th style="padding:10px;text-align:left;">Flight</th>
                <th style="padding:10px;text-align:left;">Route</th>
                <th style="padding:10px;text-align:left;">Departure</th>
                <th style="padding:10px;text-align:left;">Seats</th>
                <th style="padding:10px;text-align:left;">Price</th>
              </tr>
            </thead>
            <tbody>${flightRows}</tbody>
          </table>` : ''}
        <div style="text-align:center;margin-top:24px;">
          <a href="${result.bookingAttempt?.bookingLinks?.google || result.flights?.[0]?.bookingUrl || watch.url || `https://www.google.com/travel/flights?q=Flights+from+${watch.origin}+to+${watch.destination}+on+${watch.date}`}" style="background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-size:16px;font-weight:bold;">Book Now →</a>
        </div>
        <p style="font-size:12px;color:#999;margin-top:24px;text-align:center;">Sent by SkyWatch Flight Tracker</p>
      </div>
    </div>`;

  const recipients = toString.split(',').map(e => e.trim()).filter(e => e);
  await transporter.sendMail({
    from: `"✈️ SkyWatch" <${process.env.GMAIL_USER}>`,
    to: recipients.join(', '),
    subject: `✈️ ${airlineLabel} Seats Available! ${result.freeSeats} seat(s) found`,
    html,
  });
  console.log(`[Email] Sent to ${recipients.join(', ')}`);
}

// ─── SMS via vtext.com ────────────────────────────────────
async function sendVtext(vtextNumber, watch, result) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) return;

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
  });

  const airlineLabel = watch.airline === 'elal' ? 'ElAl' : watch.airline === 'airhaifa' ? 'AirHaifa' : watch.airline;
  let routeInfo = `${watch.origin || '?'}-${watch.destination || '?'}`;
  if (watch.airline === 'airhaifa' && watch.url) {
    try {
      const match = watch.url.match(/flight-results\/([A-Z]{3}-[A-Z]{3})\/(\d{4}-\d{2}-\d{2})/);
      if (match) routeInfo = `${match[1]} ${match[2]}`;
    } catch (e) {}
  }

  const priceInfo = result.flights?.[0]?.price ? ` $${result.flights[0].price}` : '';
  const text = `${airlineLabel} ${routeInfo}: ${result.freeSeats} seats!${priceInfo} Book now!`;

  const cleanNumber = vtextNumber.replace(/\D/g, '');
  const vtextEmail = `${cleanNumber}@vtext.com`;

  await transporter.sendMail({
    from: `"SkyWatch" <${process.env.GMAIL_USER}>`,
    to: vtextEmail,
    subject: '',
    text,
  });
  console.log(`[VText] SMS sent to ${cleanNumber}@vtext.com`);
}

// ─── Main check loop ──────────────────────────────────────
async function runChecks() {
  if (isChecking) return;
  const ids = Object.keys(watches);
  if (ids.length === 0) {
    nextCheckAt = new Date(Date.now() + CHECK_INTERVAL_MS);
    return;
  }

  isChecking = true;
  console.log(`\n[Checker] ─── Running checks for ${ids.length} watch(es) ───`);

  for (const id of ids) {
    const watch = watches[id];
    watch.status = 'checking';
    watch.lastChecked = new Date().toISOString();

    try {
      const result = await checkFlight(watch);

      // Apply price filter
      if (watch.maxPrice && result.flights && result.flights.length > 0) {
        result.flights = result.flights.filter(f => {
          if (!f.price) return true; // include if no price info
          const numPrice = parseFloat(String(f.price).replace(/[^0-9.]/g, ''));
          return !isNaN(numPrice) && numPrice <= watch.maxPrice;
        });
        result.freeSeats = result.flights.reduce((sum, f) => sum + (f.freeSeats || 0), 0);
        result.available = result.flights.length > 0;
      }

      watch.available = result.available;
      watch.freeSeats = result.freeSeats;
      watch.flights = result.flights || [];
      watch.status = result.available ? 'available' : 'not_available';
      watch.error = null;
      watch.reason = result.reason;

      watch.history = [
        { time: new Date().toISOString(), available: result.available, freeSeats: result.freeSeats },
        ...(watch.history || []),
      ].slice(0, 30);

      const airlineLabel = watch.airline === 'elal' ? 'El Al' : 'Air Haifa';
      console.log(`[Checker] ${airlineLabel} → ${result.available ? '✅ AVAILABLE (' + result.freeSeats + ' seats)' : '❌ ' + (result.reason || 'Not available')}`);

      // Attempt auto-book if enabled
      if (result.available && watch.autoBook && !watch.bookingAttempted) {
        console.log(`[AutoBook] Auto-book enabled, attempting...`);
        const bookResult = await attemptAutoBook(watch, result);
        result.bookingAttempt = bookResult;
        watch.bookingAttempted = true;
        watch.bookingResult = bookResult;
        console.log(`[AutoBook] Result: ${bookResult.booked ? 'SUCCESS' : bookResult.reason}`);
      }

      // Send notifications (only once per availability window)
      if (result.available && !watch.notified) {
        watch.notified = true;
        watch.notifiedAt = new Date().toISOString();

        const notificationPromises = [];

        if (watch.email) {
          notificationPromises.push(
            sendEmail(watch.email, watch, result).catch(e => console.error('[Email] Error:', e.message))
          );
        }

        if (watch.vtext) {
          notificationPromises.push(
            sendVtext(watch.vtext, watch, result).catch(e => console.error('[VText] Error:', e.message))
          );
        }

        await Promise.allSettled(notificationPromises);
      }

      // Reset notified flag when unavailable (so we re-notify next time)
      if (!result.available && watch.notified) {
        watch.notified = false;
        watch.bookingAttempted = false;
      }
    } catch (e) {
      console.error(`[Checker] Error:`, e.message);
      watch.status = 'error';
      watch.error = e.message;
      watch.history = [
        { time: new Date().toISOString(), error: e.message },
        ...(watch.history || []),
      ].slice(0, 30);
    }
  }

  isChecking = false;
  nextCheckAt = new Date(Date.now() + CHECK_INTERVAL_MS);
  console.log(`[Checker] Done. Next check at ${nextCheckAt.toLocaleTimeString()}\n`);
}

// ─── Start checker ────────────────────────────────────────
function startChecker() {
  if (checkInterval) clearInterval(checkInterval);
  nextCheckAt = new Date(Date.now() + 5000);
  setTimeout(runChecks, 5000);
  checkInterval = setInterval(runChecks, CHECK_INTERVAL_MS);
}

// ═══════════════════════════════════════════════════════════
//  API Routes
// ═══════════════════════════════════════════════════════════

// ─── Auth Routes ─────────────────────────────────────────
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  // Check if username taken
  const existing = Object.values(users).find(u => u.username && u.username.toLowerCase() === username.toLowerCase());
  if (existing) return res.status(400).json({ error: 'Username already taken' });

  const id = uuidv4();
  users[id] = { id, username, passwordHash: hashPassword(password), createdAt: new Date().toISOString() };
  const token = createToken(id);
  console.log(`[Auth] New user registered: ${username}`);
  saveUsers();
  res.json({ success: true, token, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = Object.values(users).find(u => u.username && u.username.toLowerCase() === username.toLowerCase());
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = createToken(user.id);
  console.log(`[Auth] User logged in: ${username}`);
  res.json({ success: true, token, username: user.username });
});

// Status
app.get('/api/status', authMiddleware, (req, res) => {
  res.json({
    watches: Object.values(watches).filter(w => w.userId === req.userId).map(w => ({
      id: w.id,
      airline: w.airline,
      url: w.url,
      origin: w.origin,
      destination: w.destination,
      date: w.date,
      passengers: w.passengers,
      maxPrice: w.maxPrice,
      email: w.email,
      vtext: w.vtext ? w.vtext.replace(/\d(?=\d{4})/g, '*') : null,
      autoBook: w.autoBook,
      profileId: w.profileId,
      status: w.status,
      available: w.available,
      freeSeats: w.freeSeats,
      flights: w.flights || [],
      lastChecked: w.lastChecked,
      notified: w.notified,
      notifiedAt: w.notifiedAt,
      error: w.error,
      reason: w.reason,
      bookingResult: w.bookingResult,
      history: (w.history || []).slice(0, 10),
    })),
    nextCheckAt: nextCheckAt ? nextCheckAt.toISOString() : null,
    isChecking,
    checkIntervalSeconds: CHECK_INTERVAL_MS / 1000,
    profiles: Object.values(userProfiles).filter(p => p.userId === req.userId).map(p => ({
      id: p.id,
      firstName: p.firstName,
      lastName: p.lastName,
      email: p.email,
    })),
  });
});

// Add watch
app.post('/api/watches', authMiddleware, (req, res) => {
  const { airline, url, origin, destination, date, passengers, email, vtext, maxPrice, autoBook, profileId, cabinClass } = req.body;

  if (airline === 'airhaifa' && !url && (!origin || !destination || !date)) return res.status(400).json({ error: 'Either a URL or origin/destination/date is required for Air Haifa' });
  if (airline === 'elal' && (!origin || !destination || !date)) return res.status(400).json({ error: 'Origin, destination, and date are required for El Al' });
  if (!email && !vtext) return res.status(400).json({ error: 'Email or Verizon number is required for notifications' });

  const id = uuidv4();
  watches[id] = {
    id,
    userId: req.userId,
    airline: airline || 'airhaifa',
    url: url || null,
    origin: origin || null,
    destination: destination || null,
    date: date || null,
    passengers: passengers || 1,
    maxPrice: maxPrice ? parseFloat(maxPrice) : null,
    email: email || null,
    vtext: vtext || null,
    autoBook: !!autoBook,
    profileId: profileId || null,
    cabinClass: cabinClass || 'economy',
    status: 'pending',
    available: null,
    freeSeats: null,
    flights: [],
    lastChecked: null,
    notified: false,
    notifiedAt: null,
    error: null,
    reason: null,
    bookingAttempted: false,
    bookingResult: null,
    history: [],
    createdAt: new Date().toISOString(),
  };

  setTimeout(runChecks, 1000);
  res.json({ success: true, id });
});

// Remove watch
app.delete('/api/watches/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  if (!watches[id]) return res.status(404).json({ error: 'Watch not found' });
  if (watches[id].userId !== req.userId) return res.status(403).json({ error: 'Not your watch' });
  delete watches[id];
  res.json({ success: true });
});

// Manual check
app.post('/api/check-now', authMiddleware, async (req, res) => {
  if (isChecking) return res.json({ message: 'Check already in progress' });
  res.json({ message: 'Manual check triggered' });
  runChecks();
});

// ─── User profiles (privacy-safe: in-memory only) ────────
app.post('/api/profiles', authMiddleware, (req, res) => {
  const { firstName, lastName, email, phone, passport, dob, nationality, cardNumber, cardExp, cardCvv } = req.body;
  if (!firstName || !lastName) return res.status(400).json({ error: 'First and last name required' });

  const id = uuidv4();
  userProfiles[id] = {
    id, firstName, lastName, email, phone,
    userId: req.userId,
    passport: encrypt(passport),
    dob, nationality,
    cardNumber: encrypt(cardNumber || null),
    cardExp: encrypt(cardExp || null),
    cardCvv: encrypt(cardCvv || null),
    createdAt: new Date().toISOString(),
  };
  saveProfiles();
  res.json({ success: true, id, name: `${firstName} ${lastName}` });
});

app.get('/api/profiles', authMiddleware, (req, res) => {
  res.json({
    profiles: Object.values(userProfiles).filter(p => p.userId === req.userId).map(p => ({
      id: p.id,
      firstName: p.firstName,
      lastName: p.lastName,
      email: p.email,
    })),
  });
});

app.delete('/api/profiles/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  if (!userProfiles[id]) return res.status(404).json({ error: 'Profile not found' });
  if (userProfiles[id].userId !== req.userId) return res.status(403).json({ error: 'Not your profile' });
  delete userProfiles[id];
  saveProfiles();
  res.json({ success: true });
});

// ─── Test Mode ────────────────────────────────────────────
// Simulates finding a flight to test the full notification + booking pipeline
app.post('/api/test', authMiddleware, async (req, res) => {
  const { email, vtext, autoBook, profileId, testType } = req.body;
  if (!email && !vtext) return res.status(400).json({ error: 'Email or vtext required' });

  console.log(`\n[TEST MODE] ─── Running test pipeline ───`);

  // Create a fake "available" result
  const fakeResult = {
    available: true,
    freeSeats: 2,
    flights: [
      {
        airline: 'Air Haifa',
        flightNum: 'E2-TEST',
        from: 'TLV',
        to: 'ATH',
        departure: '2026-03-30T08:00:00',
        arrival: '2026-03-30T10:30:00',
        className: 'Economy',
        freeSeats: 2,
        price: 99,
        currency: 'USD',
        bookingUrl: 'https://airhaifa.com/flight-results/TLV-ATH/2026-03-30/NA/1/0/0',
      },
      {
        airline: 'El Al',
        flightNum: 'LY-TEST',
        from: 'TLV',
        to: 'JFK',
        departure: '2026-03-31T22:00:00',
        arrival: '2026-04-01T04:30:00',
        className: 'Economy',
        freeSeats: 4,
        price: 549,
        currency: 'USD',
        bookingUrl: 'https://booking.elal.com/booking/flights?origin=TLV&destination=JFK',
      },
    ],
    reason: 'TEST_MODE',
  };

  const fakeWatch = {
    airline: 'airhaifa',
    url: 'https://airhaifa.com/flight-results/TLV-ATH/2026-03-30/NA/1/0/0',
    origin: 'TLV',
    destination: 'ATH',
    date: '2026-03-30',
    autoBook: !!autoBook,
    profileId: profileId || null,
  };

  const results = { emailSent: false, vtextSent: false, bookingAttempt: null };

  // Test email
  if (email) {
    try {
      await sendEmail(email, fakeWatch, fakeResult);
      results.emailSent = true;
      console.log(`[TEST] Email sent to ${email}`);
    } catch (e) {
      results.emailError = e.message;
      console.error(`[TEST] Email failed: ${e.message}`);
    }
  }

  // Test vtext SMS
  if (vtext) {
    try {
      await sendVtext(vtext, fakeWatch, fakeResult);
      results.vtextSent = true;
      console.log(`[TEST] VText sent to ${vtext}`);
    } catch (e) {
      results.vtextError = e.message;
      console.error(`[TEST] VText failed: ${e.message}`);
    }
  }

  // Test auto-booking (only if testType === 'full' to avoid accidental bookings)
  if (autoBook && profileId && testType === 'full') {
    try {
      const bookResult = await attemptAutoBook(fakeWatch, fakeResult);
      results.bookingAttempt = bookResult;
      console.log(`[TEST] Booking attempt: ${bookResult.booked ? 'SUCCESS' : bookResult.reason}`);
    } catch (e) {
      results.bookingAttempt = { booked: false, reason: e.message };
    }
  }

  console.log(`[TEST MODE] Done.\n`);
  res.json({ success: true, results, message: 'Test completed — check your email/SMS!' });
});

// ─── Live scrape test (actually checks a real URL) ────────
app.post('/api/test-scrape', authMiddleware, async (req, res) => {
  const { airline, url, origin, destination, date } = req.body;
  console.log(`\n[TEST SCRAPE] Testing real scrape...`);

  try {
    let result;
    if (airline === 'elal') {
      result = await checkElAl(origin || 'TLV', destination || 'JFK', date || '2026-04-15', 1);
    } else {
      const testUrl = url || buildAirHaifaUrl(origin || 'TLV', destination || 'ATH', date || '2026-04-15', 1);
      result = await checkAirHaifa(testUrl);
    }
    console.log(`[TEST SCRAPE] Result: ${result.available ? 'AVAILABLE' : 'Not available'} (${result.freeSeats} seats)`);
    res.json({ success: true, result });
  } catch (e) {
    console.error(`[TEST SCRAPE] Error: ${e.message}`);
    res.json({ success: false, error: e.message });
  }
});

// ─── Health check for Render ──────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', watches: Object.keys(watches).length, uptime: process.uptime() });
});

// ─── Start server ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log(' ✈️  SkyWatch Flight Tracker');
  console.log(' ─────────────────────────────────────');
  console.log(` Server running at http://0.0.0.0:${PORT}`);
  console.log(` Checking every ${CHECK_INTERVAL_MS / 1000} seconds`);
  console.log(` 2Captcha: ${TWOCAPTCHA_KEY ? 'Configured' : 'Not configured'}`);
  console.log(` BrightData: ${hasBrightData ? 'Configured (direct El Al scraping)' : 'Not configured (Google Flights fallback)'}`);
  console.log(` Gmail: ${process.env.GMAIL_USER ? 'Configured' : 'Not configured'}`);
  console.log('');
  startChecker();
});

process.on('SIGINT', async () => {
  console.log('\n[Shutdown] Closing browsers...');
  if (browser) await browser.close();
  if (proxyBrowser) await proxyBrowser.close();
  process.exit(0);
});
