require('dotenv').config();
const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── In-memory store ────────────────────────────────────────────────────────
const watches = {}; // { id: { id, url, email, phone, label, status, freeSeats, lastChecked, notified, history } }
let checkInterval = null;
let isChecking = false;
const CHECK_INTERVAL_MS = 60000; // 60 seconds
let nextCheckAt = null;

// ─── Puppeteer setup ────────────────────────────────────────────────────────
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
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || puppeteerExtra.executablePath();
    browser = await puppeteerExtra.launch({
      headless: true,
      executablePath,
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
    });
  }
  return browser;
}

// ─── Availability check ─────────────────────────────────────────────────────
async function checkFlightAvailability(url) {
  const br = await getBrowser();
  const page = await br.newPage();

  // Set realistic viewport and extra headers
  await page.setViewport({ width: 1366, height: 768 });
  await page.setExtraHTTPHeaders({
    'Accept-Language': 'en-US,en;q=0.9,he;q=0.8',
    'Accept': 'text/html,application/xhtml+xml,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  });

  // Intercept the flightList API response
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
    // Give JS extra time to fire XHR
    await new Promise(r => setTimeout(r, 6000));

    await page.close();

    if (apiError) throw new Error(apiError);

    let domText = '';
    try {
      // If we don't have flightData or it's empty, grab the DOM text to check for explicit "sold out" messages
      domText = await page.evaluate(() => document.body.innerText || '');
    } catch (e) {}

    if (!flightData) {
      // Check for explicit Hebrew text indicating no flights
      if (domText.includes('הטיסה מלאה')) {
        return { available: false, freeSeats: 0, reason: 'הטיסה מלאה (Flight is full)', raw: null };
      }
      if (domText.includes('מצטערים, אין מקומות בתאריכים שחיפשת')) {
        return { available: false, freeSeats: 0, reason: 'אין מקומות (No seats on this date)', raw: null };
      }
      return { available: false, freeSeats: 0, reason: 'no_api_response_and_no_explicit_message', raw: null };
    }

    // Check outbound (and inbound if present)
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
              });
            }
          }
        }
      }
    }

    // If the API returned data but totalFreeSeats is 0, it might still have the Hebrew text on the page
    if (totalFreeSeats === 0) {
      if (domText.includes('הטיסה מלאה')) {
        return { available: false, freeSeats: 0, reason: 'הטיסה מלאה (Flight is full)', raw: flightData };
      }
      if (domText.includes('מצטערים, אין מקומות בתאריכים שחיפשת')) {
        return { available: false, freeSeats: 0, reason: 'אין מקומות (No seats on this date)', raw: flightData };
      }
    }

    return {
      available: totalFreeSeats > 0,
      freeSeats: totalFreeSeats,
      flights: flightDetails,
      reason: totalFreeSeats > 0 ? 'seats_available' : 'sold_out',
      raw: flightData,
    };

  } catch (e) {
    try { await page.close(); } catch (_) {}
    throw e;
  }
}

// ─── Notifications ──────────────────────────────────────────────────────────
async function sendEmail(toString, watch, result) {
  if (process.env.ENABLE_NOTIFICATIONS !== 'true') {
    console.log('[Email] Notifications disabled (ENABLE_NOTIFICATIONS is not true)');
    return;
  }
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.log('[Email] Skipping – no Gmail credentials configured');
    return;
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
  });

  const flightRows = (result.flights || []).map(f => `
    <tr>
      <td style="padding:8px;border:1px solid #ddd;">${f.flightNum}</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.from} → ${f.to}</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.departure ? f.departure.replace('T', ' ').substring(0, 16) : '-'}</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.freeSeats} seat(s)</td>
      <td style="padding:8px;border:1px solid #ddd;">${f.price ? f.price + ' ' + f.currency : '-'}</td>
    </tr>`).join('');

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px;border-radius:12px 12px 0 0;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:24px;">✈️ Flight Available!</h1>
        <p style="color:#a0c4ff;margin:8px 0 0;">Air Haifa Availability Alert</p>
      </div>
      <div style="background:#f8f9ff;padding:30px;border-radius:0 0 12px 12px;">
        <p style="font-size:16px;color:#333;">Great news! Seats are now available for your watched flight:</p>
        <div style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:16px;margin:16px 0;">
          <p style="margin:0;font-size:14px;color:#666;">Watched URL:</p>
          <a href="${watch.url}" style="color:#2563eb;word-break:break-all;">${watch.url}</a>
        </div>
        ${flightRows ? `
        <table style="width:100%;border-collapse:collapse;margin:16px 0;">
          <thead>
            <tr style="background:#1a1a2e;color:#fff;">
              <th style="padding:10px;text-align:left;">Flight</th>
              <th style="padding:10px;text-align:left;">Route</th>
              <th style="padding:10px;text-align:left;">Departure</th>
              <th style="padding:10px;text-align:left;">Seats</th>
              <th style="padding:10px;text-align:left;">Price</th>
            </tr>
          </thead>
          <tbody>${flightRows}</tbody>
        </table>` : '<p>Seats are now available! Click the link above to book.</p>'}
        <div style="text-align:center;margin-top:24px;">
          <a href="${watch.url}" style="background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-size:16px;font-weight:bold;">Book Now →</a>
        </div>
        <p style="font-size:12px;color:#999;margin-top:24px;text-align:center;">This alert was sent by Air Haifa Flight Checker. The availability may change quickly — book soon!</p>
      </div>
    </div>`;

  // toString could be a comma-separated string of multiple emails
  const recipients = toString.split(',').map(e => e.trim()).filter(e => e);
  
  await transporter.sendMail({
    from: `"✈️ Air Haifa Checker" <${process.env.GMAIL_USER}>`,
    to: recipients.join(', '),
    subject: `✈️ Seats Available! Air Haifa Flight Alert`,
    html,
  });

  console.log(`[Email] Sent to ${recipients.join(', ')}`);
}

async function sendShortText(toString, watch, result) {
  if (process.env.ENABLE_NOTIFICATIONS !== 'true') {
    console.log('[Email-to-SMS] Notifications disabled (ENABLE_NOTIFICATIONS is not true)');
    return;
  }
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) return;

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
  });

  // Extract Route and Date from URL
  let routeInfo = 'AirHaifa';
  try {
    const match = watch.url.match(/flight-results\/([A-Z]{3}-[A-Z]{3})\/(\d{4}-\d{2}-\d{2})/);
    if (match) routeInfo = `${match[1]} on ${match[2]}`;
  } catch (e) {}

  const text = `${routeInfo}: ${result.freeSeats} seats available!`;
  const recipients = toString.split(',').map(e => e.trim()).filter(e => e);

  await transporter.sendMail({
    from: `"✈️ Air Haifa Checker" <${process.env.GMAIL_USER}>`,
    to: recipients.join(', '),
    subject: `Air Haifa Alert`,
    text,
  });

  console.log(`[Email-to-SMS] Sent short text to ${recipients.join(', ')}`);
}

async function sendSMS(to, watch, result) {
  if (process.env.ENABLE_NOTIFICATIONS !== 'true') {
    console.log('[SMS] Notifications disabled (ENABLE_NOTIFICATIONS is not true)');
    return;
  }
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_FROM_NUMBER) {
    console.log('[SMS] Skipping – no Twilio credentials configured');
    return;
  }

  try {
    const twilio = require('twilio');
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    const seatsInfo = result.freeSeats ? `${result.freeSeats} seat(s) available! ` : '';
    await client.messages.create({
      body: `✈️ Air Haifa Alert! ${seatsInfo}Flight is now available. Book here: ${watch.url}`,
      from: process.env.TWILIO_FROM_NUMBER,
      to,
    });
    console.log(`[SMS] Sent to ${to}`);
  } catch (e) {
    console.error('[SMS] Failed:', e.message);
  }
}

// ─── Main check loop ─────────────────────────────────────────────────────────
async function runChecks() {
  if (isChecking) return;
  const ids = Object.keys(watches);
  if (ids.length === 0) {
    nextCheckAt = new Date(Date.now() + CHECK_INTERVAL_MS);
    return;
  }

  isChecking = true;
  console.log(`[Checker] Running checks for ${ids.length} watch(es)...`);

  for (const id of ids) {
    const watch = watches[id];
    watch.status = 'checking';
    watch.lastChecked = new Date().toISOString();

    try {
      const result = await checkFlightAvailability(watch.url);
      watch.available = result.available;
      watch.freeSeats = result.freeSeats;
      watch.flights = result.flights || [];
      watch.status = result.available ? 'available' : 'not_available';
      watch.error = null;

      const histEntry = {
        time: new Date().toISOString(),
        available: result.available,
        freeSeats: result.freeSeats,
      };
      watch.history = [histEntry, ...(watch.history || [])].slice(0, 20);

      console.log(`[Checker] ${watch.url} → ${result.available ? '✅ AVAILABLE (' + result.freeSeats + ' seats)' : '❌ Not available'}`);

      // Send notification only once (reset notified if flight was unavailable then becomes available)
      if (result.available && !watch.notified) {
        watch.notified = true;
        watch.notifiedAt = new Date().toISOString();
        
        const notificationPromises = [];
        
        let allEmails = [];
        if (watch.email) allEmails.push(watch.email);
        const combinedEmails = allEmails.join(', ');

        let allVtexts = [];
        if (watch.vtext) allVtexts.push(`${watch.vtext.replace(/\D/g, '')}@vtext.com`);
        const combinedVtexts = allVtexts.join(', ');

        if (combinedEmails) notificationPromises.push(sendEmail(combinedEmails, watch, result));
        if (combinedVtexts) notificationPromises.push(sendShortText(combinedVtexts, watch, result));
        if (watch.phone) notificationPromises.push(sendSMS(watch.phone, watch, result));
        
        await Promise.allSettled(notificationPromises);
      }

      // Reset notified flag when it goes back to unavailable (so we alert again if it opens up later)
      if (!result.available && watch.notified) {
        watch.notified = false;
      }

    } catch (e) {
      console.error(`[Checker] Error checking ${watch.url}:`, e.message);
      watch.status = 'error';
      watch.error = e.message;
      watch.history = [{ time: new Date().toISOString(), error: e.message }, ...(watch.history || [])].slice(0, 20);
    }
  }

  isChecking = false;
  nextCheckAt = new Date(Date.now() + CHECK_INTERVAL_MS);
  console.log(`[Checker] Done. Next check at ${nextCheckAt.toLocaleTimeString()}`);
}

// Start the interval
function startChecker() {
  if (checkInterval) clearInterval(checkInterval);
  nextCheckAt = new Date(Date.now() + 5000); // First check in 5 seconds
  setTimeout(runChecks, 5000); // Run first check quickly
  checkInterval = setInterval(runChecks, CHECK_INTERVAL_MS);
}

// ─── API Routes ──────────────────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  res.json({
    watches: Object.values(watches).map(w => ({
      id: w.id,
      url: w.url,
      label: w.label,
      email: w.email,
      phone: w.phone ? w.phone.replace(/\d(?=\d{4})/g, '*') : null,
      vtext: w.vtext ? w.vtext.replace(/\d(?=\d{4})/g, '*') : null,
      status: w.status,
      available: w.available,
      freeSeats: w.freeSeats,
      flights: w.flights || [],
      lastChecked: w.lastChecked,
      notified: w.notified,
      notifiedAt: w.notifiedAt,
      error: w.error,
      history: (w.history || []).slice(0, 5),
    })),
    nextCheckAt: nextCheckAt ? nextCheckAt.toISOString() : null,
    isChecking,
    checkIntervalSeconds: CHECK_INTERVAL_MS / 1000,
  });
});

app.post('/api/watches', (req, res) => {
  const { url, email, phone, vtext, label } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  if (!email && !phone && !vtext) return res.status(400).json({ error: 'Either email, Verizon number, or Twilio phone is required' });

  // Validate that it looks like an Air Haifa URL
  if (!url.includes('airhaifa.com')) {
    return res.status(400).json({ error: 'URL must be an airhaifa.com URL' });
  }

  // Check for duplicate URL
  const existing = Object.values(watches).find(w => w.url === url && w.email === email && w.phone === phone && w.vtext === vtext);
  if (existing) return res.status(409).json({ error: 'This URL + contact combination is already being watched' });

  const id = uuidv4();
  watches[id] = {
    id,
    url,
    email: email || null,
    phone: phone || null,
    vtext: vtext || null,
    label: label || url,
    status: 'pending',
    available: null,
    freeSeats: null,
    flights: [],
    lastChecked: null,
    notified: false,
    notifiedAt: null,
    error: null,
    history: [],
    createdAt: new Date().toISOString(),
  };

  // Trigger immediate check
  setTimeout(runChecks, 1000);

  res.json({ success: true, id, message: 'Watch added! First check will run in ~1 second.' });
});

app.delete('/api/watches/:id', (req, res) => {
  const { id } = req.params;
  if (!watches[id]) return res.status(404).json({ error: 'Watch not found' });
  delete watches[id];
  res.json({ success: true });
});

app.post('/api/check-now', async (req, res) => {
  if (isChecking) return res.json({ message: 'Check already in progress' });
  res.json({ message: 'Manual check triggered' });
  runChecks();
});

// ─── Start server ────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ✈️  Air Haifa Flight Checker');
  console.log('  ─────────────────────────────────────');
  console.log(`  Server running at http://0.0.0.0:${PORT}`);
  console.log(`  Checks every ${CHECK_INTERVAL_MS / 1000} seconds`);
  console.log('');
  if (!process.env.GMAIL_USER) console.log('  ⚠️  No Gmail credentials – email disabled');
  if (!process.env.TWILIO_ACCOUNT_SID) console.log('  ⚠️  No Twilio credentials – SMS disabled');
  console.log('');
  startChecker();
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n[Shutdown] Closing browser...');
  if (browser) await browser.close();
  process.exit(0);
});
