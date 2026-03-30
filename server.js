require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

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

// User store
const users = {};

// ─── Persistence (JSON file on disk) ─────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROFILES_FILE = path.join(DATA_DIR, 'profiles.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function saveUsers() {
  try {
    ensureDataDir();
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (e) { console.error('[Persist] Failed to save users:', e.message); }
}

function saveProfiles() {
  try {
    ensureDataDir();
    fs.writeFileSync(PROFILES_FILE, JSON.stringify(userProfiles, null, 2));
  } catch (e) { console.error('[Persist] Failed to save profiles:', e.message); }
}

function loadPersistedData() {
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

// Auto-create admin user from env vars (survives deploys even without persistent disk)
function ensureAdminUser() {
  const adminUser = process.env.ADMIN_USER;
  const adminPass = process.env.ADMIN_PASS;
  if (adminUser && adminPass) {
    if (!users[adminUser]) {
      users[adminUser] = {
        passwordHash: hashPassword(adminPass),
        createdAt: new Date().toISOString(),
        isAdmin: true,
      };
      saveUsers();
      console.log(`[Auth] Auto-created admin user "${adminUser}" from env vars`);
    } else {
      console.log(`[Auth] Admin user "${adminUser}" already exists`);
    }
  }
}

// Load on startup (called after userProfiles is defined below)

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

// Load persisted users + profiles from disk
loadPersistedData();
// Auto-create admin user from ADMIN_USER/ADMIN_PASS env vars
ensureAdminUser();

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

  const gfQuery = `Flights from ${origin} to ${destination} on ${date} one way ${passengers} passenger`;
  const searchUrl = `https://www.google.com/travel/flights?q=${encodeURIComponent(gfQuery)}&hl=en`;

  try {
    console.log(`[ElAl] Google Flights fallback: ${searchUrl}`);
    await page.goto(searchUrl, { waitUntil: 'networkidle2', timeout: 60000 });
    await new Promise(r => setTimeout(r, 6000));

    const pageFlights = await page.evaluate(() => {
      const cards = document.querySelectorAll('li.pIav2d');
      const results = [];
      const seen = new Set();
      for (const card of cards) {
        const text = card.innerText || '';
        const priceMatch = text.match(/\$[\d,]+/);
        const airlineMatch = text.match(/(El\s*Al|Etihad|Turkish|Lufthansa|United|Delta|American|Swiss|LOT|Austrian|Arkia|Israir|British|Air France|KLM|Emirates|Qatar|Aegean|Ryanair|Wizz)/i);
        const routeMatch = text.match(/([A-Z]{3})[–\-]([A-Z]{3})/);
        const stopsMatch = text.match(/(Nonstop|\d+\s*stop)/i);
        const durationMatch = text.match(/(\d+\s*hr\s*\d*\s*min?)/);
        const timeMatch = text.match(/(\d{1,2}:\d{2}\s*[AP]M)/g);
        if (priceMatch && airlineMatch) {
          const key = airlineMatch[1] + '-' + priceMatch[0] + '-' + (timeMatch ? timeMatch[0] : '');
          if (!seen.has(key)) {
            seen.add(key);
            results.push({
              airline: airlineMatch[1], price: priceMatch[0],
              from: routeMatch ? routeMatch[1] : '', to: routeMatch ? routeMatch[2] : '',
              stops: stopsMatch ? stopsMatch[0] : '', duration: durationMatch ? durationMatch[1] : '',
              departure: timeMatch && timeMatch[0] ? timeMatch[0] : '',
              arrival: timeMatch && timeMatch[1] ? timeMatch[1] : '',
            });
          }
        }
      }
      const bodyText = document.body.innerText;
      if (bodyText.includes('No flights match') || bodyText.includes('Try different dates')) return [{ noFlights: true }];
      return results;
    });

    await page.close();

    if (pageFlights.length > 0 && pageFlights[0]?.noFlights) {
      return { available: false, freeSeats: 0, flights: [], reason: 'no_flights', source: 'google_flights' };
    }

    const elAlFlights = pageFlights.filter(f => f.airline && f.airline.toLowerCase().replace(/\s/g, '') === 'elal');
    const allFlights = pageFlights;

    const flightDetails = elAlFlights.map((f, i) => ({
      airline: 'El Al', flightNum: `LY${i + 1}`,
      from: f.from || origin, to: f.to || destination,
      departure: f.departure || date, arrival: f.arrival || '',
      className: 'Economy', freeSeats: 1,
      price: f.price, currency: 'USD', stops: f.stops, duration: f.duration,
      bookingUrl: bookingUrl, source: 'google_flights',
    }));

    let reason = 'no_flights';
    if (flightDetails.length > 0) reason = 'seats_available';
    else if (allFlights.length > 0) reason = `No El Al flights found, but ${allFlights.length} other airline(s) on route`;

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

// ─── El Al auto-booking via BrightData proxy ────────────
async function attemptAutoBookElAl(watch, flightResult, profile) {
  if (!hasBrightData) {
    return { booked: false, reason: 'BrightData proxy required for El Al auto-booking' };
  }

  const cabinPref = (watch.cabinClass || 'economy').toLowerCase();
  const maxPrice = watch.maxPrice ? parseFloat(watch.maxPrice) : null;
  const passengers = watch.passengers || 1;

  console.log(`[AutoBook ElAl] Starting — ${watch.origin}→${watch.destination} on ${watch.date}, ${cabinPref}, max $${maxPrice || 'any'}`);

  // Airport code → city name mapping for El Al search form autocomplete
  const airportCityMap = {
    'TLV': 'Tel Aviv', 'JFK': 'New York', 'EWR': 'Newark', 'LAX': 'Los Angeles',
    'ORD': 'Chicago', 'MIA': 'Miami', 'BOS': 'Boston', 'SFO': 'San Francisco',
    'LHR': 'London', 'CDG': 'Paris', 'FCO': 'Rome', 'ATH': 'Athens',
    'BKK': 'Bangkok', 'IST': 'Istanbul', 'BCN': 'Barcelona', 'AMS': 'Amsterdam',
    'FRA': 'Frankfurt', 'MUC': 'Munich', 'ZRH': 'Zurich', 'MAD': 'Madrid',
    'BER': 'Berlin', 'VIE': 'Vienna', 'PRG': 'Prague', 'BUD': 'Budapest',
    'JNB': 'Johannesburg', 'ADD': 'Addis Ababa', 'NBO': 'Nairobi',
    'BOM': 'Mumbai', 'DEL': 'Delhi', 'HKG': 'Hong Kong', 'PEK': 'Beijing',
    'ICN': 'Seoul', 'NRT': 'Tokyo',
  };

  const originCity = airportCityMap[watch.origin] || watch.origin;
  const destCity = airportCityMap[watch.destination] || watch.destination;

  const br = await getProxyBrowser();
  const page = await br.newPage();
  await page.setViewport({ width: 1366, height: 768 });

  await page.authenticate({
    username: BRIGHTDATA_USER,
    password: BRIGHTDATA_PASS,
  });

  await page.setExtraHTTPHeaders({
    'Accept-Language': 'en-US,en;q=0.9',
  });

  // Helper: wait for page to settle (SPA transitions)
  async function waitSettle(ms = 8000) {
    try {
      await Promise.race([
        page.waitForNavigation({ waitUntil: 'networkidle2', timeout: ms }),
        new Promise(r => setTimeout(r, ms)),
      ]);
    } catch (e) { /* ok — SPA might not trigger navigation */ }
    await new Promise(r => setTimeout(r, 2000));
  }

  // Helper: set Angular input value properly (triggers Angular change detection)
  async function setAngularInput(selector, value) {
    await page.evaluate((sel, val) => {
      const el = document.querySelector(sel);
      if (!el) return false;
      el.focus();
      el.value = '';
      // Trigger Angular's input event
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      nativeInputValueSetter.call(el, val);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      el.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
      el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
      return true;
    }, selector, value);
  }

  // Helper: log page state for debugging
  async function logState(label) {
    try {
      const s = await page.evaluate(() => ({
        url: window.location.href,
        title: document.title,
        bodyLen: document.body.innerText.length,
        inputs: document.querySelectorAll('input, select, textarea').length,
        buttons: [...document.querySelectorAll('button, [role="button"]')]
          .map(b => (b.innerText || '').trim().substring(0, 50)).filter(t => t.length > 0).slice(0, 10),
      }));
      console.log(`[AutoBook ElAl] ${label} — URL: ${s.url}, inputs: ${s.inputs}, buttons: ${JSON.stringify(s.buttons)}`);
      return s;
    } catch (e) {
      console.log(`[AutoBook ElAl] ${label} — context lost: ${e.message}`);
      return null;
    }
  }

  try {
    // ─── STEP 1: Navigate to El Al homepage ─────────────────
    console.log('[AutoBook ElAl] Step 1: Loading El Al homepage...');
    await page.goto('https://www.elal.com/eng/usa', { waitUntil: 'networkidle2', timeout: 90000 });
    await new Promise(r => setTimeout(r, 5000));

    // Check if blocked
    const title = await page.title();
    const bodyLen = await page.evaluate(() => document.body.innerText.length);
    console.log(`[AutoBook ElAl] Homepage loaded — title: "${title}", body: ${bodyLen} chars`);

    if (title.toLowerCase().includes('access denied') || bodyLen < 200) {
      await page.close();
      return { booked: false, reason: 'El Al blocked access even with proxy' };
    }

    // Dismiss cookie banner if present
    try {
      await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button')];
        const acceptBtn = btns.find(b => /accept|allow|agree|got it/i.test(b.innerText || ''));
        if (acceptBtn) acceptBtn.click();
      });
      await new Promise(r => setTimeout(r, 1000));
    } catch (e) { /* ok */ }

    // ─── STEP 2: Set to "One Way" trip ──────────────────────
    console.log('[AutoBook ElAl] Step 2: Setting One Way trip...');
    try {
      await page.evaluate(() => {
        // Look for One Way radio/button/tab
        const allEls = document.querySelectorAll('button, label, div, span, a, [role="tab"], [role="radio"]');
        for (const el of allEls) {
          const text = (el.innerText || el.textContent || '').trim().toLowerCase();
          if (text === 'one way' || text === 'one-way' || text === 'oneway') {
            el.click();
            return true;
          }
        }
        return false;
      });
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) {
      console.log(`[AutoBook ElAl] Could not set One Way: ${e.message}`);
    }

    // ─── STEP 3: Fill origin airport ────────────────────────
    console.log(`[AutoBook ElAl] Step 3: Filling origin — "${originCity}"...`);
    try {
      // Click origin field and type city name
      const originFilled = await page.evaluate(() => {
        // Find origin input — look for "from", "origin", "departure" fields
        const inputs = document.querySelectorAll('input[type="text"], input:not([type])');
        for (const inp of inputs) {
          const ph = (inp.placeholder || '').toLowerCase();
          const name = (inp.name || inp.id || '').toLowerCase();
          const label = (inp.closest('label')?.innerText || '').toLowerCase();
          const aria = (inp.getAttribute('aria-label') || '').toLowerCase();
          const combined = ph + ' ' + name + ' ' + label + ' ' + aria;
          if (/(from|origin|depart|where.*from|מאיפה|מוצא|יציאה)/i.test(combined)) {
            inp.click();
            inp.focus();
            return inp.id || inp.name || 'found';
          }
        }
        return null;
      });
      console.log(`[AutoBook ElAl] Origin field: ${originFilled || 'not found'}`);

      if (originFilled) {
        // Type the city name to trigger autocomplete
        await page.keyboard.type(originCity, { delay: 100 });
        await new Promise(r => setTimeout(r, 2000));

        // Click first autocomplete result
        await page.evaluate((city) => {
          const items = document.querySelectorAll('[role="option"], [role="listbox"] li, .autocomplete-item, .search-result, .dropdown-item, li[class*="option"], div[class*="option"], .suggestion, mat-option');
          for (const item of items) {
            const text = (item.innerText || item.textContent || '').toLowerCase();
            if (text.includes(city.toLowerCase())) {
              item.click();
              return true;
            }
          }
          // Fallback: click first visible option
          if (items.length > 0) {
            items[0].click();
            return true;
          }
          return false;
        }, originCity);
        await new Promise(r => setTimeout(r, 1500));
      }
    } catch (e) {
      console.log(`[AutoBook ElAl] Origin fill error: ${e.message}`);
    }

    // ─── STEP 4: Fill destination airport ───────────────────
    console.log(`[AutoBook ElAl] Step 4: Filling destination — "${destCity}"...`);
    try {
      const destFilled = await page.evaluate(() => {
        const inputs = document.querySelectorAll('input[type="text"], input:not([type])');
        for (const inp of inputs) {
          const ph = (inp.placeholder || '').toLowerCase();
          const name = (inp.name || inp.id || '').toLowerCase();
          const label = (inp.closest('label')?.innerText || '').toLowerCase();
          const aria = (inp.getAttribute('aria-label') || '').toLowerCase();
          const combined = ph + ' ' + name + ' ' + label + ' ' + aria;
          if (/(to|dest|arrival|where.*to|לאן|יעד|הגעה)/i.test(combined)) {
            inp.click();
            inp.focus();
            return inp.id || inp.name || 'found';
          }
        }
        return null;
      });
      console.log(`[AutoBook ElAl] Destination field: ${destFilled || 'not found'}`);

      if (destFilled) {
        await page.keyboard.type(destCity, { delay: 100 });
        await new Promise(r => setTimeout(r, 2000));

        await page.evaluate((city) => {
          const items = document.querySelectorAll('[role="option"], [role="listbox"] li, .autocomplete-item, .search-result, .dropdown-item, li[class*="option"], div[class*="option"], .suggestion, mat-option');
          for (const item of items) {
            const text = (item.innerText || item.textContent || '').toLowerCase();
            if (text.includes(city.toLowerCase())) {
              item.click();
              return true;
            }
          }
          if (items.length > 0) {
            items[0].click();
            return true;
          }
          return false;
        }, destCity);
        await new Promise(r => setTimeout(r, 1500));
      }
    } catch (e) {
      console.log(`[AutoBook ElAl] Destination fill error: ${e.message}`);
    }

    // ─── STEP 5: Set departure date ─────────────────────────
    console.log(`[AutoBook ElAl] Step 5: Setting date — ${watch.date}...`);
    try {
      // Click date picker
      await page.evaluate(() => {
        const dateInputs = document.querySelectorAll('input[type="text"], input[type="date"], [class*="date"], [class*="calendar"], button[class*="date"]');
        for (const el of dateInputs) {
          const text = (el.placeholder || el.innerText || el.getAttribute('aria-label') || '').toLowerCase();
          const name = (el.name || el.id || el.className || '').toLowerCase();
          if (/(date|depart|when|תאריך|יציאה)/i.test(text + ' ' + name)) {
            el.click();
            return true;
          }
        }
        return false;
      });
      await new Promise(r => setTimeout(r, 2000));

      // Parse the target date
      const [year, month, day] = watch.date.split('-').map(Number);
      const targetDate = new Date(year, month - 1, day);
      const targetMonth = targetDate.toLocaleString('en-US', { month: 'long' });
      const targetYear = targetDate.getFullYear();

      // Navigate calendar to the right month (click next up to 12 times)
      for (let i = 0; i < 12; i++) {
        const calendarMonth = await page.evaluate(() => {
          const headers = document.querySelectorAll('[class*="calendar"] [class*="header"], [class*="calendar"] [class*="title"], [class*="month"], .datepicker-header, .calendar-title');
          for (const h of headers) {
            const text = (h.innerText || h.textContent || '').trim();
            if (text.length > 3 && text.length < 40) return text;
          }
          return '';
        });
        console.log(`[AutoBook ElAl] Calendar shows: "${calendarMonth}"`);

        if (calendarMonth.includes(targetMonth) && calendarMonth.includes(String(targetYear))) {
          break; // We're on the right month
        }

        // Click next month arrow
        await page.evaluate(() => {
          const nextBtns = document.querySelectorAll('button[class*="next"], [class*="calendar"] button[aria-label*="next"], [class*="calendar"] button[aria-label*="Next"], [class*="right-arrow"], .calendar-next, button[class*="forward"]');
          if (nextBtns.length > 0) nextBtns[0].click();
          else {
            // Fallback: find arrow-looking buttons
            const allBtns = document.querySelectorAll('[class*="calendar"] button, .datepicker button');
            for (const b of allBtns) {
              const text = (b.innerText || b.getAttribute('aria-label') || '').toLowerCase();
              if (text.includes('next') || text.includes('>') || text.includes('→') || text.includes('forward')) {
                b.click();
                break;
              }
            }
          }
        });
        await new Promise(r => setTimeout(r, 500));
      }

      // Click the target day
      await page.evaluate((d) => {
        const dayCells = document.querySelectorAll('[class*="calendar"] td, [class*="calendar"] button, [class*="calendar"] div[class*="day"], .datepicker td, .day-cell');
        for (const cell of dayCells) {
          const text = (cell.innerText || cell.textContent || '').trim();
          const isDisabled = cell.classList.contains('disabled') || cell.getAttribute('aria-disabled') === 'true';
          if (!isDisabled && text === String(d)) {
            cell.click();
            return true;
          }
        }
        return false;
      }, day);
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) {
      console.log(`[AutoBook ElAl] Date setting error: ${e.message}`);
    }

    // ─── STEP 6: Click Search ───────────────────────────────
    console.log('[AutoBook ElAl] Step 6: Clicking Search...');
    try {
      await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button, input[type="submit"], a[role="button"]')];
        const searchBtn = btns.find(b => {
          const text = (b.innerText || b.value || '').toLowerCase().trim();
          return text.includes('search') || text.includes('find') || text.includes('חפש') || text.includes('חיפוש');
        });
        if (searchBtn) { searchBtn.click(); return true; }
        // Fallback: look for a prominent submit button
        const submitBtn = btns.find(b => b.type === 'submit' || b.classList.contains('search-btn'));
        if (submitBtn) { submitBtn.click(); return true; }
        return false;
      });
    } catch (e) {
      console.log(`[AutoBook ElAl] Search click error: ${e.message}`);
    }

    // Wait for navigation to booking.elal.com
    console.log('[AutoBook ElAl] Waiting for flight results on booking.elal.com...');
    await waitSettle(30000);
    await new Promise(r => setTimeout(r, 10000)); // Extra wait for El Al SPA to load results

    let state = await logState('After search');

    // Check if we landed on booking.elal.com
    let currentUrl = '';
    try { currentUrl = await page.evaluate(() => window.location.href); } catch (e) {}
    console.log(`[AutoBook ElAl] Current URL after search: ${currentUrl}`);

    if (!currentUrl.includes('booking.elal.com')) {
      // Maybe the search didn't redirect. Try checking if we're still on the homepage
      console.log('[AutoBook ElAl] Not on booking.elal.com — checking if search form had errors...');
      const pageSnippet = await page.evaluate(() => document.body.innerText.substring(0, 1000)).catch(() => '');
      await page.close();
      return { booked: false, reason: 'El Al search did not navigate to booking page. Might need manual intervention.', pagePreview: pageSnippet.substring(0, 500) };
    }

    // ─── STEP 7: Select flight (ECONOMY column) ─────────────
    console.log('[AutoBook ElAl] Step 7: Selecting flight...');
    await new Promise(r => setTimeout(r, 5000)); // Wait for Angular to render flights

    const selectResult = await page.evaluate((pref, mPrice) => {
      // On booking.elal.com, flights are displayed with ECONOMY/PREMIUM/BUSINESS columns
      // Each column has a price. We need to click the right column.
      const priceElements = document.querySelectorAll('[class*="price"], [class*="fare"], [class*="cabin"], button, div');
      const candidates = [];

      for (const el of priceElements) {
        const text = (el.innerText || '').trim();
        if (text.length < 2 || text.length > 2000) continue;

        const hasPrice = /\$[\d,]+/.test(text);
        if (!hasPrice) continue;

        const priceMatch = text.match(/\$[\d,]+/);
        const priceNum = priceMatch ? parseFloat(priceMatch[0].replace(/[^0-9.]/g, '')) : null;

        const isEconomy = /economy/i.test(text);
        const isPremium = /premium/i.test(text);
        const isBusiness = /business/i.test(text);

        // Skip if it contains too many prices (probably a parent container)
        const priceCount = (text.match(/\$[\d,]+/g) || []).length;
        if (priceCount > 3) continue;

        candidates.push({
          el, text: text.substring(0, 200), price: priceNum,
          priceStr: priceMatch ? priceMatch[0] : null,
          isEconomy, isPremium, isBusiness, priceCount
        });
      }

      if (candidates.length === 0) {
        return { clicked: false, reason: 'No flight prices found', debug: document.body.innerText.substring(0, 1500) };
      }

      // Filter by cabin preference
      let filtered = candidates;
      if (pref === 'economy') {
        const econOnly = candidates.filter(c => c.isEconomy && !c.isBusiness && !c.isPremium && c.priceCount <= 2);
        if (econOnly.length > 0) filtered = econOnly;
      } else if (pref === 'business') {
        const bizOnly = candidates.filter(c => c.isBusiness);
        if (bizOnly.length > 0) filtered = bizOnly;
      }

      // Sort by price
      filtered.sort((a, b) => (a.price || 99999) - (b.price || 99999));

      // Apply max price
      if (mPrice) {
        filtered = filtered.filter(c => !c.price || c.price <= mPrice);
      }

      if (filtered.length === 0) return { clicked: false, reason: 'No flights match price/class criteria' };

      const target = filtered[0];
      target.el.click();

      return {
        clicked: true, selectedPrice: target.priceStr,
        selectedClass: target.isEconomy ? 'Economy' : target.isBusiness ? 'Business' : target.isPremium ? 'Premium' : 'Unknown',
        reason: `Selected ${target.priceStr} ${target.isEconomy ? 'Economy' : target.isBusiness ? 'Business' : ''}`,
      };
    }, cabinPref, maxPrice);

    console.log(`[AutoBook ElAl] Flight selection: ${JSON.stringify(selectResult)}`);

    if (!selectResult.clicked) {
      console.log(`[AutoBook ElAl] FAILED - ${selectResult.reason}: ${(selectResult.debug || '').substring(0, 500)}`);
      await page.close();
      return { booked: false, reason: selectResult.reason, pagePreview: (selectResult.debug || '').substring(0, 500) };
    }

    // ─── STEP 8: Select fare (CLASSIC) ──────────────────────
    console.log('[AutoBook ElAl] Step 8: Selecting CLASSIC fare...');
    await new Promise(r => setTimeout(r, 5000)); // Wait for fare sub-options to appear

    try {
      await page.evaluate((pref) => {
        // After clicking ECONOMY, sub-options appear: CLASSIC ($X) and FLEX ($Y)
        // We want CLASSIC (cheapest) for economy, or the first option for business
        const allEls = document.querySelectorAll('button, div, [role="button"]');
        for (const el of allEls) {
          const text = (el.innerText || '').trim().toLowerCase();
          if (text.length < 3 || text.length > 500) continue;
          // Look for CLASSIC with a price
          if (/classic/i.test(text) && /\$[\d,]+/.test(text)) {
            el.click();
            return true;
          }
        }
        // Fallback: click any fare option with a price
        for (const el of allEls) {
          const text = (el.innerText || '').trim().toLowerCase();
          if (/(classic|lite|flex|standard)/i.test(text) && /\$[\d,]+/.test(text)) {
            el.click();
            return true;
          }
        }
        return false;
      }, cabinPref);
    } catch (e) {
      console.log(`[AutoBook ElAl] Fare selection error: ${e.message}`);
    }

    await new Promise(r => setTimeout(r, 3000));

    // ─── STEP 9: Click "Passenger Details >" ────────────────
    console.log('[AutoBook ElAl] Step 9: Clicking Passenger Details...');
    try {
      // Scroll down to find the button
      await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      await new Promise(r => setTimeout(r, 1000));

      await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button, a, [role="button"]')];
        const paxBtn = btns.find(b => {
          const text = (b.innerText || '').toLowerCase().trim();
          return text.includes('passenger') || text.includes('continue') || text.includes('next') || text.includes('נוסעים') || text.includes('המשך');
        });
        if (paxBtn) { paxBtn.click(); return true; }
        return false;
      });
    } catch (e) {
      console.log(`[AutoBook ElAl] Passenger Details click error: ${e.message}`);
    }

    // Wait for passenger form to load
    console.log('[AutoBook ElAl] Waiting for passenger form...');
    await waitSettle(15000);
    await new Promise(r => setTimeout(r, 5000));

    state = await logState('Passenger form');

    // Verify we're on the passengers page
    try { currentUrl = await page.evaluate(() => window.location.href); } catch (e) { currentUrl = ''; }
    console.log(`[AutoBook ElAl] Passenger page URL: ${currentUrl}`);

    const onPassengerPage = currentUrl.includes('/passengers') || currentUrl.includes('/passenger');
    if (!onPassengerPage) {
      // Try one more time — look for intermediate steps
      console.log('[AutoBook ElAl] Not on passenger page yet, trying to click through...');
      for (let i = 0; i < 3; i++) {
        try {
          await page.evaluate(() => {
            const btns = [...document.querySelectorAll('button, a, [role="button"]')];
            const nextBtn = btns.find(b => {
              const text = (b.innerText || '').toLowerCase().trim();
              return text.includes('continue') || text.includes('next') || text.includes('passenger') || text.includes('confirm') || text.includes('select');
            });
            if (nextBtn) nextBtn.click();
          });
          await waitSettle(8000);
          currentUrl = await page.evaluate(() => window.location.href).catch(() => '');
          if (currentUrl.includes('/passengers') || currentUrl.includes('/passenger')) break;
        } catch (e) { break; }
      }
    }

    // ─── STEP 10: Fill passenger form ───────────────────────
    console.log('[AutoBook ElAl] Step 10: Filling passenger form...');

    const formFields = {
      firstName: profile.firstName,
      lastName: profile.lastName,
      email: profile.email,
      phone: profile.phone,
      dob: profile.dob, // Expected format: YYYY-MM-DD or MM/DD/YYYY
    };

    let filledCount = 0;

    // Fill Title (civility) — custom Angular dropdown
    try {
      // Click to open the dropdown
      await page.click('#form-0-civility');
      await new Promise(r => setTimeout(r, 1000));
      // Select "Mr" or "Mrs" based on gender if available
      const titleClicked = await page.evaluate((gender) => {
        const options = document.querySelectorAll('[role="option"], li[class*="option"], .dropdown-item, mat-option, [class*="select-option"]');
        const targetTitle = gender === 'F' ? 'mrs' : 'mr';
        for (const opt of options) {
          const text = (opt.innerText || opt.textContent || '').trim().toLowerCase();
          if (text === targetTitle || text === targetTitle + '.') {
            opt.click();
            return true;
          }
        }
        // Fallback: click first option (usually "Mr")
        if (options.length > 0) { options[0].click(); return true; }
        return false;
      }, profile.gender || 'M');
      if (titleClicked) filledCount++;
      await new Promise(r => setTimeout(r, 500));
    } catch (e) {
      console.log(`[AutoBook ElAl] Title fill error: ${e.message}`);
    }

    // Fill First Name
    try {
      await setAngularInput('#form-0-firstName', formFields.firstName || '');
      if (formFields.firstName) filledCount++;
    } catch (e) { console.log(`[AutoBook ElAl] First name error: ${e.message}`); }

    // Fill Last Name
    try {
      await setAngularInput('#form-0-lastName', formFields.lastName || '');
      if (formFields.lastName) filledCount++;
    } catch (e) { console.log(`[AutoBook ElAl] Last name error: ${e.message}`); }

    // Fill Date of Birth (mm, dd, yyyy)
    try {
      if (formFields.dob) {
        let dobParts;
        if (formFields.dob.includes('-')) {
          // YYYY-MM-DD format
          const [y, m, d] = formFields.dob.split('-');
          dobParts = { month: m, day: d, year: y };
        } else if (formFields.dob.includes('/')) {
          // MM/DD/YYYY format
          const [m, d, y] = formFields.dob.split('/');
          dobParts = { month: m, day: d, year: y };
        }

        if (dobParts) {
          await setAngularInput('#form-0-month', dobParts.month);
          await setAngularInput('#form-0-day', dobParts.day);
          await setAngularInput('#form-0-year', dobParts.year);
          filledCount++;
        }
      }
    } catch (e) { console.log(`[AutoBook ElAl] DOB error: ${e.message}`); }

    // Set Gender
    try {
      const gender = (profile.gender || 'M').toUpperCase();
      await page.evaluate((g) => {
        // Find Male/Female radio-style buttons
        const labels = document.querySelectorAll('label, [class*="radio"], [class*="gender"]');
        const target = g === 'F' ? 'female' : 'male';
        for (const label of labels) {
          const text = (label.innerText || label.textContent || '').trim().toLowerCase();
          if (text === target) {
            label.click();
            const radio = label.querySelector('input[type="radio"]') || label;
            radio.click();
            return true;
          }
        }
        return false;
      }, gender);
      filledCount++;
    } catch (e) { console.log(`[AutoBook ElAl] Gender error: ${e.message}`); }

    // Fill Email
    try {
      await setAngularInput('#form-0-email', formFields.email || '');
      if (formFields.email) filledCount++;
    } catch (e) { console.log(`[AutoBook ElAl] Email error: ${e.message}`); }

    // Fill Phone
    try {
      await setAngularInput('#form-0-number', formFields.phone || '');
      if (formFields.phone) filledCount++;
    } catch (e) { console.log(`[AutoBook ElAl] Phone error: ${e.message}`); }

    // Check terms checkbox
    try {
      await page.evaluate(() => {
        const checkboxes = document.querySelectorAll('input[type="checkbox"]');
        for (const cb of checkboxes) {
          const parent = cb.closest('label, div, span');
          const text = (parent?.innerText || '').toLowerCase();
          if (text.includes('confirm') || text.includes('accept') || text.includes('agree') || text.includes('terms') || text.includes('fare conditions')) {
            if (!cb.checked) cb.click();
            return true;
          }
        }
        // Fallback: find the terms checkbox wrapper and click it
        const wrappers = document.querySelectorAll('[class*="checkbox"], [class*="terms"], [class*="accept"]');
        for (const w of wrappers) {
          const text = (w.innerText || '').toLowerCase();
          if (text.includes('confirm') || text.includes('accept') || text.includes('fare')) {
            w.click();
            return true;
          }
        }
        return false;
      });
      filledCount++;
    } catch (e) { console.log(`[AutoBook ElAl] Terms checkbox error: ${e.message}`); }

    console.log(`[AutoBook ElAl] Filled ${filledCount} form fields`);

    // ─── STEP 11: Click "Confirm and Continue" ──────────────
    await new Promise(r => setTimeout(r, 2000));
    let submitted = false;
    try {
      submitted = await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button')];
        const confirmBtn = btns.find(b => {
          const text = (b.innerText || '').toLowerCase().trim();
          return text.includes('confirm') && text.includes('continue');
        });
        if (confirmBtn && !confirmBtn.disabled) {
          confirmBtn.click();
          return true;
        }
        // Fallback: any continue/next button
        const nextBtn = btns.find(b => {
          const text = (b.innerText || '').toLowerCase().trim();
          return (text.includes('continue') || text.includes('next') || text.includes('confirm')) && !b.disabled;
        });
        if (nextBtn) { nextBtn.click(); return true; }
        return false;
      });
    } catch (e) {
      console.log(`[AutoBook ElAl] Submit error: ${e.message}`);
    }

    console.log(`[AutoBook ElAl] Submitted: ${submitted}`);

    // Wait and capture final state
    if (submitted) {
      await waitSettle(10000);
    }

    let pageText = '';
    try {
      pageText = await page.evaluate(() => document.body.innerText.substring(0, 500));
    } catch (e) {
      pageText = '(page navigated — could not capture text)';
    }

    await page.close();

    return {
      booked: submitted || filledCount >= 3,
      reason: filledCount >= 3
        ? `El Al booking attempted — ${selectResult.selectedPrice || '?'} ${selectResult.selectedClass || ''} — filled ${filledCount} fields — ${submitted ? 'submitted to extras/payment' : 'submit button not found'} — check email`
        : `Could not complete El Al booking form (only filled ${filledCount} fields)`,
      selectedFlight: selectResult,
      filledFields: filledCount,
      pagePreview: pageText,
    };
  } catch (e) {
    try { await page.close(); } catch (_) {}
    if (e.message && e.message.includes('Execution context was destroyed')) {
      return {
        booked: true,
        reason: `El Al page navigated after interaction (likely booking in progress) — check email for confirmation`,
      };
    }
    return { booked: false, reason: 'El Al booking error: ' + e.message };
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

  const bookingSection = watch.autoBook && result.bookingAttempt
    ? `<div style="background:#${result.bookingAttempt.booked ? 'e8f5e9' : 'fff3e0'};padding:16px;border-radius:8px;margin:16px 0;">
        <strong>${result.bookingAttempt.booked ? '✅ Auto-booking attempted!' : '⚠️ Auto-booking note:'}</strong>
        <p>${result.bookingAttempt.reason}</p>
       </div>`
    : '';

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
          <a href="${result.flights?.[0]?.bookingUrl || watch.url || '#'}" style="background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-size:16px;font-weight:bold;">Book Now →</a>
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
  const existing = Object.values(users).find(u => u.username.toLowerCase() === username.toLowerCase());
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

  const user = Object.values(users).find(u => u.username.toLowerCase() === username.toLowerCase());
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
