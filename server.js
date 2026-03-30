require('dotenv').config();
const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

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

// User profiles (stored in memory for privacy - cleared on restart)
const userProfiles = {};

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
      passport: profile.passport,
      dob: profile.dob,
      cardNumber: profile.cardNumber,
      cardExp: profile.cardExp,
      cardCvv: profile.cardCvv,
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

  // Pick the best flight from results based on preference
  let targetFlight = null;
  if (flightResult.flights && flightResult.flights.length > 0) {
    const sorted = [...flightResult.flights].sort((a, b) => {
      const priceA = parseFloat(String(a.price || '0').replace(/[^0-9.]/g, ''));
      const priceB = parseFloat(String(b.price || '0').replace(/[^0-9.]/g, ''));
      return priceA - priceB; // cheapest first
    });

    if (cabinPref === 'economy') {
      // Pick cheapest flight (economy is usually cheapest)
      targetFlight = sorted[0];
    } else if (cabinPref === 'business') {
      // Pick a business class flight (usually more expensive)
      targetFlight = sorted.find(f => {
        const cls = (f.className || '').toLowerCase();
        return cls.includes('business') || cls.includes('מחלקת עסקים');
      }) || sorted[sorted.length - 1]; // fallback to most expensive
    } else {
      targetFlight = sorted[0]; // any = cheapest
    }
  }

  const targetPrice = targetFlight ? String(targetFlight.price || '').replace(/[^0-9.]/g, '') : null;
  console.log(`[AutoBook ElAl] Target: ${cabinPref} class, price ${targetFlight?.price || 'unknown'}`);

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

  const bookingUrl = `https://www.elal.com/en/booking/flight-select/?isOneWay=true&origin=${watch.origin}&destination=${watch.destination}&dep=${watch.date}&adult=${watch.passengers || 1}`;

  try {
    console.log(`[AutoBook ElAl] Navigating to: ${bookingUrl}`);
    await page.goto(bookingUrl, { waitUntil: 'networkidle2', timeout: 90000 });

    // Check if blocked
    const title = await page.title();
    if (title.toLowerCase().includes('access denied')) {
      await page.close();
      return { booked: false, reason: 'El Al blocked access even with proxy' };
    }

    await new Promise(r => setTimeout(r, 10000));

    // Debug: log page title + body snippet so we can see what loaded
    const pageDebug = await page.evaluate(() => {
      return {
        title: document.title,
        url: window.location.href,
        bodyLength: document.body.innerText.length,
        bodySnippet: document.body.innerText.substring(0, 1500),
        hasAccessDenied: document.body.innerText.toLowerCase().includes('access denied'),
        allButtons: [...document.querySelectorAll('button, a[role="button"], [role="button"]')]
          .map(b => (b.innerText || '').substring(0, 80)).filter(t => t.length > 1).slice(0, 20),
      };
    });
    console.log(`[AutoBook ElAl] Page title: "${pageDebug.title}"`);
    console.log(`[AutoBook ElAl] URL: ${pageDebug.url}`);
    console.log(`[AutoBook ElAl] Body length: ${pageDebug.bodyLength} chars`);
    console.log(`[AutoBook ElAl] Buttons found: ${JSON.stringify(pageDebug.allButtons)}`);
    console.log(`[AutoBook ElAl] Body snippet: ${pageDebug.bodySnippet.substring(0, 500)}`);

    if (pageDebug.hasAccessDenied || pageDebug.bodyLength < 200) {
      await page.close();
      return { booked: false, reason: 'El Al page did not load properly (blocked or empty)', pagePreview: pageDebug.bodySnippet.substring(0, 300) };
    }

    // Step 1: Find and click the right flight based on cabin class and price
    const selectResult = await page.evaluate((pref, tPrice, mPrice) => {
      const allElements = document.querySelectorAll('div, li, article, section, button, a, [role="button"], span, td, tr');
      const candidates = [];

      for (const el of allElements) {
        const text = el.innerText || '';
        if (text.length < 5 || text.length > 5000) continue;

        // Broader matching - look for prices in USD, ILS, or just numbers that look like prices
        const hasPrice = /\$[\d,]+|₪[\d,]+|USD\s*[\d,]+|ILS\s*[\d,]+/i.test(text);
        const hasSelect = /(select|book|choose|add|בחר|הזמן|הוסף)/i.test(text);
        const hasFlightInfo = /(LY\s*\d|nonstop|direct|stop|economy|business|class|תיירים|עסקים|flight)/i.test(text);
        const isEconomy = /(economy|תיירים|coach|lite|classic|flex)/i.test(text);
        const isBusiness = /(business|עסקים|premium)/i.test(text);

        if (hasPrice || hasSelect || hasFlightInfo) {
          const priceMatch = text.match(/\$[\d,]+/) || text.match(/₪[\d,]+/);
          const priceNum = priceMatch ? parseFloat(priceMatch[0].replace(/[^0-9.]/g, '')) : null;

          candidates.push({
            el,
            text: text.substring(0, 300),
            price: priceNum,
            priceStr: priceMatch ? priceMatch[0] : null,
            isEconomy,
            isBusiness,
            hasSelect,
            hasPrice,
            hasFlightInfo,
            tagName: el.tagName,
          });
        }
      }

      if (candidates.length === 0) {
        // Return debug info about what IS on the page
        const allText = document.body.innerText.substring(0, 2000);
        return { clicked: false, reason: 'No flight options found on page', debug: allText };
      }

      // Filter by cabin preference
      let filtered = candidates;
      if (pref === 'economy') {
        const econOnly = candidates.filter(c => c.isEconomy && !c.isBusiness);
        if (econOnly.length > 0) filtered = econOnly;
        // Sort by price ascending
        filtered.sort((a, b) => (a.price || 99999) - (b.price || 99999));
      } else if (pref === 'business') {
        const bizOnly = candidates.filter(c => c.isBusiness);
        if (bizOnly.length > 0) filtered = bizOnly;
        filtered.sort((a, b) => (a.price || 99999) - (b.price || 99999));
      } else {
        filtered.sort((a, b) => (a.price || 99999) - (b.price || 99999));
      }

      // Apply max price filter
      if (mPrice) {
        filtered = filtered.filter(c => !c.price || c.price <= mPrice);
      }

      if (filtered.length === 0) return { clicked: false, reason: 'No flights match price/class criteria' };

      const target = filtered[0];

      // Try to click select/book button within or near this element
      const selectBtn = target.el.querySelector('button, a, [role="button"]') ||
        target.el.closest('[role="button"]') || target.el;

      // Also look for explicit select buttons
      const btns = target.el.querySelectorAll('button, a, [role="button"]');
      let clicked = false;
      for (const btn of btns) {
        const btnText = (btn.innerText || '').toLowerCase();
        if (btnText.includes('select') || btnText.includes('book') || btnText.includes('בחר') || btnText.includes('הזמן')) {
          btn.click();
          clicked = true;
          break;
        }
      }

      if (!clicked) {
        // Click the element itself
        selectBtn.click();
        clicked = true;
      }

      return {
        clicked,
        selectedPrice: target.priceStr,
        selectedClass: target.isEconomy ? 'Economy' : target.isBusiness ? 'Business' : 'Unknown',
        reason: `Selected ${target.priceStr || 'unknown price'} ${target.isEconomy ? 'Economy' : target.isBusiness ? 'Business' : ''} flight`,
      };
    }, cabinPref, targetPrice, maxPrice);

    console.log(`[AutoBook ElAl] Flight selection: ${JSON.stringify(selectResult)}`);

    if (!selectResult.clicked) {
      console.log(`[AutoBook ElAl] FAILED - debug page content: ${(selectResult.debug || '').substring(0, 800)}`);
      await page.close();
      return { booked: false, reason: selectResult.reason, pagePreview: (selectResult.debug || '').substring(0, 500) };
    }

    await new Promise(r => setTimeout(r, 5000));

    // Step 2: Fill passenger details
    const formFields = {
      firstName: profile.firstName,
      lastName: profile.lastName,
      email: profile.email,
      phone: profile.phone,
      passport: profile.passport,
      dob: profile.dob,
      cardNumber: profile.cardNumber,
      cardExp: profile.cardExp,
      cardCvv: profile.cardCvv,
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
              phone: ['phone', 'tel', 'mobile', 'טלפון', 'נייד'],
              passport: ['passport', 'id', 'document', 'דרכון', 'תעודת זהות'],
              dob: ['birth', 'dob', 'date of birth', 'תאריך לידה'],
              cardNumber: ['card', 'credit', 'cc', 'כרטיס אשראי', 'מספר כרטיס'],
              cardExp: ['expir', 'exp', 'valid', 'תוקף'],
              cardCvv: ['cvv', 'cvc', 'security', 'csv'],
            };

            const keywords = fieldMappings[f] || [f];
            if (keywords.some(k => combined.includes(k))) {
              input.focus();
              input.value = v;
              input.dispatchEvent(new Event('input', { bubbles: true }));
              input.dispatchEvent(new Event('change', { bubbles: true }));
              input.dispatchEvent(new Event('blur', { bubbles: true }));
              break;
            }
          }
        }, field, value);
      } catch (e) {
        console.log(`[AutoBook ElAl] Could not fill ${field}: ${e.message}`);
      }
    }

    // Step 3: Handle captcha if present
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
          console.log('[AutoBook ElAl] Solving captcha...');
          const token = await solveCaptcha(siteKey, bookingUrl);
          await page.evaluate((t) => {
            const ta = document.querySelector('#g-recaptcha-response, [name="g-recaptcha-response"]');
            if (ta) { ta.value = t; ta.dispatchEvent(new Event('change', { bubbles: true })); }
            if (typeof window.captchaCallback === 'function') window.captchaCallback(t);
            if (typeof window.onCaptchaSuccess === 'function') window.onCaptchaSuccess(t);
          }, token);
        } catch (e) {
          console.log(`[AutoBook ElAl] Captcha solve failed: ${e.message}`);
        }
      }
    }

    // Step 4: Find and click continue/submit/next
    await new Promise(r => setTimeout(r, 2000));
    const submitted = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('button, input[type="submit"], a')];
      const submitBtn = btns.find(b => {
        const text = (b.innerText || b.value || '').toLowerCase();
        return text.includes('continue') || text.includes('submit') || text.includes('next') ||
               text.includes('proceed') || text.includes('confirm') ||
               text.includes('המשך') || text.includes('שלח') || text.includes('אישור');
      });
      if (submitBtn) { submitBtn.click(); return true; }
      return false;
    });

    await new Promise(r => setTimeout(r, 5000));

    const pageText = await page.evaluate(() => document.body.innerText.substring(0, 500));
    await page.close();

    return {
      booked: submitted,
      reason: submitted
        ? `El Al booking submitted — ${selectResult.selectedPrice || '?'} ${selectResult.selectedClass || ''} — check email for confirmation`
        : 'Could not find submit button on El Al',
      selectedFlight: selectResult,
      pagePreview: pageText,
    };
  } catch (e) {
    try { await page.close(); } catch (_) {}
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

// Status
app.get('/api/status', (req, res) => {
  res.json({
    watches: Object.values(watches).map(w => ({
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
    profiles: Object.keys(userProfiles).map(id => ({
      id,
      firstName: userProfiles[id].firstName,
      lastName: userProfiles[id].lastName,
      email: userProfiles[id].email,
    })),
  });
});

// Add watch
app.post('/api/watches', (req, res) => {
  const { airline, url, origin, destination, date, passengers, email, vtext, maxPrice, autoBook, profileId, cabinClass } = req.body;

  if (airline === 'airhaifa' && !url && (!origin || !destination || !date)) return res.status(400).json({ error: 'Either a URL or origin/destination/date is required for Air Haifa' });
  if (airline === 'elal' && (!origin || !destination || !date)) return res.status(400).json({ error: 'Origin, destination, and date are required for El Al' });
  if (!email && !vtext) return res.status(400).json({ error: 'Email or Verizon number is required for notifications' });

  const id = uuidv4();
  watches[id] = {
    id,
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
app.delete('/api/watches/:id', (req, res) => {
  const { id } = req.params;
  if (!watches[id]) return res.status(404).json({ error: 'Watch not found' });
  delete watches[id];
  res.json({ success: true });
});

// Manual check
app.post('/api/check-now', async (req, res) => {
  if (isChecking) return res.json({ message: 'Check already in progress' });
  res.json({ message: 'Manual check triggered' });
  runChecks();
});

// ─── User profiles (privacy-safe: in-memory only) ────────
app.post('/api/profiles', (req, res) => {
  const { firstName, lastName, email, phone, passport, dob, nationality, cardNumber, cardExp, cardCvv } = req.body;
  if (!firstName || !lastName) return res.status(400).json({ error: 'First and last name required' });

  const id = uuidv4();
  userProfiles[id] = {
    id, firstName, lastName, email, phone, passport, dob, nationality,
    cardNumber: cardNumber || null,
    cardExp: cardExp || null,
    cardCvv: cardCvv || null,
    createdAt: new Date().toISOString(),
  };
  res.json({ success: true, id, name: `${firstName} ${lastName}` });
});

app.get('/api/profiles', (req, res) => {
  res.json({
    profiles: Object.values(userProfiles).map(p => ({
      id: p.id,
      firstName: p.firstName,
      lastName: p.lastName,
      email: p.email,
    })),
  });
});

app.delete('/api/profiles/:id', (req, res) => {
  const { id } = req.params;
  if (!userProfiles[id]) return res.status(404).json({ error: 'Profile not found' });
  delete userProfiles[id];
  res.json({ success: true });
});

// ─── Test Mode ────────────────────────────────────────────
// Simulates finding a flight to test the full notification + booking pipeline
app.post('/api/test', async (req, res) => {
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
app.post('/api/test-scrape', async (req, res) => {
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
