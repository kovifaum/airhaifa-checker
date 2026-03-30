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

// ─── El Al checker ────────────────────────────────────────
async function checkElAl(origin, destination, date, passengers = 1) {
  const br = await getBrowser();
  const page = await br.newPage();
  await page.setViewport({ width: 1366, height: 768 });

  let flightApiData = null;

  // Intercept El Al's API responses
  page.on('response', async (response) => {
    const resUrl = response.url();
    // El Al uses various API endpoints - try to catch flight search results
    if (resUrl.includes('/api/') && (resUrl.includes('flight') || resUrl.includes('search') || resUrl.includes('availability'))) {
      try {
        const ct = response.headers()['content-type'] || '';
        if (ct.includes('json')) {
          const text = await response.text();
          const data = JSON.parse(text);
          if (data && (data.flights || data.results || data.outbound || data.Flights || data.FlightResults)) {
            flightApiData = data;
          }
        }
      } catch (e) {}
    }
  });

  const searchUrl = `https://booking.elal.com/booking/flights?market=US&lang=en&isOneWay=true&origin=${origin}&destination=${destination}&dep=${date}&adult=${passengers}`;

  try {
    console.log(`[ElAl] Navigating to: ${searchUrl}`);
    await page.goto(searchUrl, { waitUntil: 'networkidle2', timeout: 60000 });
    await new Promise(r => setTimeout(r, 8000));

    // Try to extract data from the page DOM if API interception didn't work
    let pageFlights = [];
    try {
      pageFlights = await page.evaluate(() => {
        const results = [];
        // Try to find flight cards on the page
        const flightElements = document.querySelectorAll('[class*="flight"], [class*="Flight"], [data-flight], .search-result, .flight-card, .flight-row');
        flightElements.forEach(el => {
          const text = el.innerText || '';
          // Extract price if visible
          const priceMatch = text.match(/\$[\d,]+|\d+\s*(USD|ILS|EUR)/i);
          const timeMatch = text.match(/\d{1,2}:\d{2}/g);
          if (priceMatch || timeMatch) {
            results.push({
              text: text.substring(0, 300),
              price: priceMatch ? priceMatch[0] : null,
              times: timeMatch || [],
            });
          }
        });

        // Also check for "no flights" messages
        const bodyText = document.body.innerText;
        if (bodyText.includes('No flights') || bodyText.includes('no results') || bodyText.includes('unavailable')) {
          return [{ noFlights: true }];
        }

        return results;
      });
    } catch (e) {}

    await page.close();

    // Process API data if we got it
    if (flightApiData) {
      const flights = flightApiData.flights || flightApiData.results || flightApiData.Flights || flightApiData.FlightResults || [];
      const flightDetails = [];
      let totalSeats = 0;

      const flightArray = Array.isArray(flights) ? flights : Object.values(flights);
      for (const f of flightArray) {
        const seats = f.seatsAvailable || f.seats || f.availability || 1;
        totalSeats += seats;
        flightDetails.push({
          airline: 'El Al',
          flightNum: f.flightNumber || f.flightNum || f.number || 'LY???',
          from: origin,
          to: destination,
          departure: f.departureTime || f.departure || date,
          arrival: f.arrivalTime || f.arrival || '',
          className: f.cabin || f.class || 'Economy',
          freeSeats: seats,
          price: f.price || f.totalPrice || f.fare || null,
          currency: 'USD',
          bookingUrl: searchUrl,
        });
      }

      return {
        available: flightDetails.length > 0,
        freeSeats: totalSeats,
        flights: flightDetails,
        reason: flightDetails.length > 0 ? 'seats_available' : 'no_flights',
      };
    }

    // Fallback: process DOM-scraped data
    if (pageFlights.length > 0 && !pageFlights[0]?.noFlights) {
      const flightDetails = pageFlights.filter(f => f.price).map((f, i) => ({
        airline: 'El Al',
        flightNum: `LY${i + 1}`,
        from: origin,
        to: destination,
        departure: f.times[0] || date,
        arrival: f.times[1] || '',
        className: 'Economy',
        freeSeats: 1,
        price: f.price,
        currency: 'USD',
        bookingUrl: searchUrl,
        rawText: f.text,
      }));

      return {
        available: flightDetails.length > 0,
        freeSeats: flightDetails.length,
        flights: flightDetails,
        reason: flightDetails.length > 0 ? 'seats_available' : 'no_flights',
      };
    }

    return {
      available: false,
      freeSeats: 0,
      flights: [],
      reason: 'Could not determine availability - page may need manual review',
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
  if (!watch.autoBook || !watch.profileId) return { booked: false, reason: 'Auto-book not enabled' };

  const profile = userProfiles[watch.profileId];
  if (!profile) return { booked: false, reason: 'No user profile found' };

  console.log(`[AutoBook] Attempting to book for ${profile.firstName} ${profile.lastName}...`);

  if (watch.airline !== 'airhaifa') {
    return { booked: false, reason: 'Auto-book currently only supports Air Haifa' };
  }

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
  const { airline, url, origin, destination, date, passengers, email, vtext, maxPrice, autoBook, profileId } = req.body;

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
  console.log(` Gmail: ${process.env.GMAIL_USER ? 'Configured' : 'Not configured'}`);
  console.log('');
  startChecker();
});

process.on('SIGINT', async () => {
  console.log('\n[Shutdown] Closing browser...');
  if (browser) await browser.close();
  process.exit(0);
});
