const express = require('express');
const session = require('express-session');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const { adminOps, userOps, spOps, logOps } = require('./lib/db');
const samlLib = require('./lib/saml');
const totpLib = require('./lib/totp');

// Load .env manually (no dotenv dependency)
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf-8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const [key, ...rest] = trimmed.split('=');
      process.env[key.trim()] = rest.join('=').trim();
    }
  });
}

const HOSTNAME = process.env.HOSTNAME || 'localhost';
const PORT = parseInt(process.env.PORT || '8080');
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-please';
const LOGIN_CAPTCHA_THRESHOLD = parseInt(process.env.LOGIN_CAPTCHA_THRESHOLD || '3', 10);
const LOGIN_LOCK_THRESHOLD = parseInt(process.env.LOGIN_LOCK_THRESHOLD || '10', 10);
const LOGIN_LOCK_MS = parseInt(process.env.LOGIN_LOCK_MS || String(15 * 60 * 1000), 10);
const LOGIN_ATTEMPT_TTL_MS = parseInt(process.env.LOGIN_ATTEMPT_TTL_MS || String(24 * 60 * 60 * 1000), 10);
const CAPTCHA_TTL_MS = parseInt(process.env.CAPTCHA_TTL_MS || String(5 * 60 * 1000), 10);
const TOTP_ISSUER = process.env.TOTP_ISSUER || 'Mini-IdP';
const TOTP_WINDOW = parseInt(process.env.TOTP_WINDOW || '1', 10);
const TOTP_SETUP_TTL_MS = parseInt(process.env.TOTP_SETUP_TTL_MS || String(10 * 60 * 1000), 10);

const app = express();
const loginAttemptStore = new Map();

app.use(morgan('short'));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.json({ limit: '5mb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 8 * 60 * 60 * 1000 }
}));
app.use('/public', express.static(path.join(__dirname, 'public')));

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function buildLoginAttemptKey(scope, req, identifier) {
  const normalizedIdentifier = String(identifier || 'unknown').trim().toLowerCase() || 'unknown';
  return `${scope}:${getClientIp(req)}:${normalizedIdentifier}`;
}

function readAttemptRecord(key) {
  const now = Date.now();
  const record = loginAttemptStore.get(key);
  if (!record) return { failedCount: 0, lockUntil: 0, updatedAt: now };

  if (record.lockUntil > 0 && record.lockUntil <= now) {
    const unlockedState = { failedCount: LOGIN_CAPTCHA_THRESHOLD, lockUntil: 0, updatedAt: now };
    loginAttemptStore.set(key, unlockedState);
    return unlockedState;
  }

  if (now - record.updatedAt > LOGIN_ATTEMPT_TTL_MS && record.lockUntil <= now) {
    loginAttemptStore.delete(key);
    return { failedCount: 0, lockUntil: 0, updatedAt: now };
  }
  return record;
}

function registerFailedAttempt(key) {
  const now = Date.now();
  const prev = readAttemptRecord(key);
  const failedCount = (prev.failedCount || 0) + 1;
  const lockUntil = failedCount >= LOGIN_LOCK_THRESHOLD ? now + LOGIN_LOCK_MS : prev.lockUntil || 0;
  const next = { failedCount, lockUntil, updatedAt: now };
  loginAttemptStore.set(key, next);
  return next;
}

function clearAttemptRecord(key) {
  loginAttemptStore.delete(key);
}

function isCaptchaRequired(key) {
  return readAttemptRecord(key).failedCount >= LOGIN_CAPTCHA_THRESHOLD;
}

function getLockRemainingMs(key) {
  const ms = readAttemptRecord(key).lockUntil - Date.now();
  return ms > 0 ? ms : 0;
}

function cleanupAttemptStore() {
  const now = Date.now();
  for (const [key, value] of loginAttemptStore.entries()) {
    if (now - value.updatedAt > LOGIN_ATTEMPT_TTL_MS && value.lockUntil <= now) {
      loginAttemptStore.delete(key);
    }
  }
}

setInterval(cleanupAttemptStore, 30 * 60 * 1000).unref();

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateCaptcha() {
  const a = randomInt(2, 12);
  const b = randomInt(2, 12);
  if (Math.random() > 0.5) {
    return { question: `${a} + ${b} = ?`, answer: String(a + b) };
  }
  const high = Math.max(a, b);
  const low = Math.min(a, b);
  return { question: `${high} - ${low} = ?`, answer: String(high - low) };
}

function getCaptchaBucket(req) {
  if (!req.session.captcha) req.session.captcha = {};
  return req.session.captcha;
}

function issueCaptchaChallenge(req, scope) {
  const bucket = getCaptchaBucket(req);
  const captcha = generateCaptcha();
  bucket[scope] = {
    question: captcha.question,
    answer: captcha.answer,
    expiresAt: Date.now() + CAPTCHA_TTL_MS
  };
  return bucket[scope];
}

function getCaptchaChallenge(req, scope) {
  const bucket = getCaptchaBucket(req);
  const existing = bucket[scope];
  if (!existing || existing.expiresAt < Date.now()) {
    return issueCaptchaChallenge(req, scope);
  }
  return existing;
}

function clearCaptchaChallenge(req, scope) {
  if (req.session.captcha) delete req.session.captcha[scope];
}

function verifyCaptchaAnswer(req, scope, answer) {
  const bucket = getCaptchaBucket(req);
  const challenge = bucket[scope];
  if (!challenge || challenge.expiresAt < Date.now()) {
    issueCaptchaChallenge(req, scope);
    return false;
  }

  const valid = String(answer || '').trim() === String(challenge.answer);
  if (valid) {
    delete bucket[scope];
    return true;
  }

  issueCaptchaChallenge(req, scope);
  return false;
}

function redirectWithAuthError(res, pathName, { error, captcha, retryMs } = {}) {
  const params = new URLSearchParams();
  if (error) params.set('error', error);
  if (captcha) params.set('captcha', '1');
  if (retryMs && retryMs > 0) params.set('retry', String(Math.ceil(retryMs / 1000)));
  const query = params.toString();
  res.redirect(query ? `${pathName}?${query}` : pathName);
}

function isAdminTotpEnabled(admin) {
  return !!admin && Number(admin.totp_enabled) === 1 && !!admin.totp_secret;
}

function verifyAdminTotp(admin, token) {
  if (!isAdminTotpEnabled(admin)) return true;
  return totpLib.verifyTotp(admin.totp_secret, token, { window: TOTP_WINDOW });
}

function getAdminTotpAccount(admin) {
  return `${admin.username}@${HOSTNAME}`;
}

function getPendingAdminTotpSetup(req) {
  const setup = req.session.admin2faSetup;
  if (!setup) return null;

  if (Date.now() - setup.createdAt > TOTP_SETUP_TTL_MS) {
    delete req.session.admin2faSetup;
    return null;
  }

  return setup;
}

// ============================================================
// Middleware
// ============================================================
function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  if (req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.redirect('/admin/login');
}

app.get('/auth/captcha', (req, res) => {
  const scope = String(req.query.scope || '');
  if (!['sso', 'admin'].includes(scope)) {
    return res.status(400).json({ error: 'Invalid captcha scope' });
  }

  const challenge = getCaptchaChallenge(req, scope);
  res.set('Cache-Control', 'no-store');
  res.json({
    question: challenge.question,
    expiresInSeconds: Math.max(0, Math.ceil((challenge.expiresAt - Date.now()) / 1000))
  });
});

// ============================================================
// SAML Endpoints
// ============================================================

// Metadata
app.get('/saml/metadata', (req, res) => {
  res.set('Content-Type', 'application/xml');
  res.send(samlLib.generateMetadata(HOSTNAME));
});

// Certificate download
app.get('/saml/certificate', (req, res) => {
  res.set('Content-Type', 'application/x-pem-file');
  res.set('Content-Disposition', 'attachment; filename="idp-certificate.pem"');
  res.send(samlLib.getCertificate());
});

// SSO endpoint (receives AuthnRequest from SP)
app.get('/saml/sso', (req, res) => {
  const samlRequest = req.query.SAMLRequest;
  const relayState = req.query.RelayState || '';

  let parsed = { id: null, issuer: null };
  if (samlRequest) {
    parsed = samlLib.parseAuthnRequest(samlRequest);
  }

  // Store in session for after login
  req.session.saml = {
    requestId: parsed.id,
    issuer: parsed.issuer,
    relayState: relayState
  };

  // If user already has a session, generate response directly
  if (req.session.ssoUser) {
    return handleSSOResponse(req, res);
  }

  // Show login page
  res.redirect('/sso/login');
});

// SSO POST binding
app.post('/saml/sso', (req, res) => {
  const samlRequest = req.body.SAMLRequest;
  const relayState = req.body.RelayState || '';

  let parsed = { id: null, issuer: null };
  if (samlRequest) {
    parsed = samlLib.parseAuthnRequest(samlRequest);
  }

  req.session.saml = {
    requestId: parsed.id,
    issuer: parsed.issuer,
    relayState: relayState
  };

  if (req.session.ssoUser) {
    return handleSSOResponse(req, res);
  }

  res.redirect('/sso/login');
});

// SSO Login page
app.get('/sso/login', (req, res) => {
  if (!req.session.saml) {
    return res.status(400).send('No SAML request in session. Please initiate login from your service provider.');
  }
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// SSO Login submit
app.post('/sso/login', (req, res) => {
  const email = String(req.body.email || '').trim();
  const password = String(req.body.password || '');
  const captchaAnswer = req.body.captcha_answer;
  const attemptKey = buildLoginAttemptKey('sso', req, email);
  const lockRemainingMs = getLockRemainingMs(attemptKey);

  if (lockRemainingMs > 0) {
    return redirectWithAuthError(res, '/sso/login', {
      error: 'locked',
      captcha: true,
      retryMs: lockRemainingMs
    });
  }

  if (isCaptchaRequired(attemptKey) && !verifyCaptchaAnswer(req, 'sso', captchaAnswer)) {
    const state = registerFailedAttempt(attemptKey);
    const retryMs = Math.max(0, state.lockUntil - Date.now());
    return redirectWithAuthError(res, '/sso/login', {
      error: retryMs > 0 ? 'locked' : 'captcha',
      captcha: true,
      retryMs
    });
  }

  const user = userOps.verify(email, password);
  if (!user) {
    logOps.add(email || 'unknown', req.session.saml?.issuer || 'unknown', false, getClientIp(req));
    const state = registerFailedAttempt(attemptKey);
    const retryMs = Math.max(0, state.lockUntil - Date.now());
    return redirectWithAuthError(res, '/sso/login', {
      error: retryMs > 0 ? 'locked' : 'invalid',
      captcha: state.failedCount >= LOGIN_CAPTCHA_THRESHOLD,
      retryMs
    });
  }

  clearAttemptRecord(attemptKey);
  clearCaptchaChallenge(req, 'sso');

  req.session.ssoUser = {
    email: user.email,
    first_name: user.first_name,
    last_name: user.last_name,
    immutable_id: user.immutable_id
  };

  handleSSOResponse(req, res);
});

function handleSSOResponse(req, res) {
  const samlData = req.session.saml;
  const user = req.session.ssoUser;

  if (!samlData || !user) {
    return res.status(400).send('Missing SAML context or user session');
  }

  // Find the SP config by issuer, or try all enabled SPs
  let spConfig = null;
  if (samlData.issuer) {
    spConfig = spOps.getByEntityId(samlData.issuer);
  }

  if (!spConfig) {
    // Try to match by checking all SPs - maybe Google sends issuer differently
    const allSps = spOps.list().filter(sp => sp.enabled);
    if (allSps.length === 1) {
      spConfig = allSps[0];
    } else if (allSps.length > 1) {
      // For Google, issuer might be "google.com" or empty
      spConfig = allSps.find(sp => sp.type === 'google') || allSps[0];
    }
  }

  if (!spConfig) {
    return res.status(400).send('No matching Service Provider configured. Please add one in the admin panel.');
  }

  try {
    const signedXml = samlLib.buildSamlResponse({
      user,
      spConfig,
      hostname: HOSTNAME,
      inResponseTo: samlData.requestId
    });

    const base64Response = Buffer.from(signedXml).toString('base64');

    logOps.add(user.email, spConfig.name, true, req.ip);

    // Clear SAML session data
    delete req.session.saml;

    // Auto-submit form
    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Redirecting...</title></head>
<body>
  <form id="saml-form" method="POST" action="${spConfig.acs_url}">
    <input type="hidden" name="SAMLResponse" value="${base64Response}"/>
    <input type="hidden" name="RelayState" value="${samlData.relayState || ''}"/>
    <noscript><button type="submit">Continue</button></noscript>
  </form>
  <script>document.getElementById('saml-form').submit();</script>
</body></html>`);
  } catch (err) {
    console.error('SAML Response error:', err);
    logOps.add(user.email, spConfig?.name || 'unknown', false, req.ip);
    res.status(500).send('Failed to generate SAML response: ' + err.message);
  }
}

// SLO (Single Logout)
app.get('/saml/slo', (req, res) => {
  req.session.destroy(() => {
    res.send('Logged out successfully. You can close this window.');
  });
});

// ============================================================
// Admin Auth
// ============================================================
app.get('/admin/login', (req, res) => {
  if (req.session.admin) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'views', 'admin-login.html'));
});

app.post('/admin/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const otpCode = String(req.body.otp_code || '').trim();
  const captchaAnswer = req.body.captcha_answer;
  const attemptKey = buildLoginAttemptKey('admin', req, username);
  const lockRemainingMs = getLockRemainingMs(attemptKey);

  if (lockRemainingMs > 0) {
    return redirectWithAuthError(res, '/admin/login', {
      error: 'locked',
      captcha: true,
      retryMs: lockRemainingMs
    });
  }

  if (isCaptchaRequired(attemptKey) && !verifyCaptchaAnswer(req, 'admin', captchaAnswer)) {
    const state = registerFailedAttempt(attemptKey);
    const retryMs = Math.max(0, state.lockUntil - Date.now());
    return redirectWithAuthError(res, '/admin/login', {
      error: retryMs > 0 ? 'locked' : 'captcha',
      captcha: true,
      retryMs
    });
  }

  const admin = adminOps.verify(username, password);
  if (!admin) {
    const state = registerFailedAttempt(attemptKey);
    const retryMs = Math.max(0, state.lockUntil - Date.now());
    return redirectWithAuthError(res, '/admin/login', {
      error: retryMs > 0 ? 'locked' : 'invalid',
      captcha: state.failedCount >= LOGIN_CAPTCHA_THRESHOLD,
      retryMs
    });
  }

  if (isAdminTotpEnabled(admin) && !verifyAdminTotp(admin, otpCode)) {
    const state = registerFailedAttempt(attemptKey);
    const retryMs = Math.max(0, state.lockUntil - Date.now());
    return redirectWithAuthError(res, '/admin/login', {
      error: retryMs > 0 ? 'locked' : (otpCode ? 'totp_invalid' : 'totp_required'),
      captcha: state.failedCount >= LOGIN_CAPTCHA_THRESHOLD,
      retryMs
    });
  }

  clearAttemptRecord(attemptKey);
  clearCaptchaChallenge(req, 'admin');
  req.session.admin = { id: admin.id, username: admin.username };
  res.redirect('/admin');
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

// Admin Panel
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// ============================================================
// Admin API
// ============================================================

// Dashboard stats
app.get('/api/stats', requireAdmin, (req, res) => {
  res.json({
    users: userOps.count(),
    sps: spOps.count(),
    loginsToday: logOps.countToday(),
    successToday: logOps.countTodaySuccess(),
    hostname: HOSTNAME
  });
});

// Users CRUD
app.get('/api/users', requireAdmin, (req, res) => {
  res.json(userOps.list());
});

app.post('/api/users', requireAdmin, (req, res) => {
  try {
    const result = userOps.create(req.body);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  try {
    userOps.update(req.params.id, req.body);
    if (req.body.password) {
      userOps.updatePassword(req.params.id, req.body.password);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  userOps.delete(req.params.id);
  res.json({ success: true });
});

// Service Providers CRUD
app.get('/api/sps', requireAdmin, (req, res) => {
  res.json(spOps.list());
});

app.post('/api/sps', requireAdmin, (req, res) => {
  try {
    const result = spOps.create(req.body);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/sps/:id', requireAdmin, (req, res) => {
  try {
    spOps.update(req.params.id, req.body);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/sps/:id', requireAdmin, (req, res) => {
  spOps.delete(req.params.id);
  res.json({ success: true });
});

// Quick-add templates
app.post('/api/sps/template/:type', requireAdmin, (req, res) => {
  const { domain } = req.body;
  const templates = {
    google: {
      name: 'Google Workspace',
      type: 'google',
      entity_id: 'google.com',
      acs_url: `https://www.google.com/a/${domain}/acs`,
      name_id_format: 'email'
    },
    microsoft: {
      name: 'Microsoft 365',
      type: 'microsoft',
      entity_id: 'urn:federation:MicrosoftOnline',
      acs_url: 'https://login.microsoftonline.com/login.srf',
      name_id_format: 'email'
    }
  };

  const template = templates[req.params.type];
  if (!template) return res.status(400).json({ error: 'Unknown template' });

  try {
    const result = spOps.create(template);
    res.json({ success: true, id: result.lastInsertRowid, config: template });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Login logs
app.get('/api/logs', requireAdmin, (req, res) => {
  res.json(logOps.recent(100));
});

// Certificate info
app.get('/api/cert-info', requireAdmin, (req, res) => {
  try {
    const cert = samlLib.getCertificateBase64();
    res.json({
      exists: true,
      base64: cert,
      metadataUrl: `https://${HOSTNAME}/saml/metadata`,
      ssoUrl: `https://${HOSTNAME}/saml/sso`,
      sloUrl: `https://${HOSTNAME}/saml/slo`,
      certDownloadUrl: `https://${HOSTNAME}/saml/certificate`
    });
  } catch (e) {
    res.json({ exists: false });
  }
});

// Admin password change
app.post('/api/admin/password', requireAdmin, (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');

  if (!currentPassword) {
    return res.status(400).json({ error: 'Current password is required' });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  if (currentPassword === newPassword) {
    return res.status(400).json({ error: 'New password must be different from current password' });
  }

  const admin = adminOps.verify(req.session.admin.username, currentPassword);
  if (!admin) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }

  adminOps.changePassword(req.session.admin.id, newPassword);
  res.json({ success: true });
});

// Admin 2FA status
app.get('/api/admin/2fa', requireAdmin, (req, res) => {
  const admin = adminOps.getSecurity(req.session.admin.id);
  if (!admin) return res.status(404).json({ error: 'Admin not found' });

  res.json({
    enabled: isAdminTotpEnabled(admin),
    issuer: TOTP_ISSUER,
    account: getAdminTotpAccount(admin),
    hasPendingSetup: !!getPendingAdminTotpSetup(req)
  });
});

// Start 2FA setup (generate secret, keep pending in session)
app.post('/api/admin/2fa/setup', requireAdmin, (req, res) => {
  const admin = adminOps.getSecurity(req.session.admin.id);
  if (!admin) return res.status(404).json({ error: 'Admin not found' });
  if (isAdminTotpEnabled(admin)) return res.status(400).json({ error: '2FA already enabled' });

  const secret = totpLib.generateSecret();
  const account = getAdminTotpAccount(admin);
  const otpauthUrl = totpLib.buildOtpAuthUrl({
    issuer: TOTP_ISSUER,
    accountName: account,
    secret
  });

  req.session.admin2faSetup = {
    secret,
    account,
    createdAt: Date.now()
  };

  res.json({
    success: true,
    secret,
    account,
    issuer: TOTP_ISSUER,
    otpauthUrl
  });
});

// Confirm setup and enable 2FA
app.post('/api/admin/2fa/enable', requireAdmin, (req, res) => {
  const token = String(req.body.token || '').trim();
  const setup = getPendingAdminTotpSetup(req);

  if (!setup) {
    return res.status(400).json({ error: 'No active 2FA setup. Please start again.' });
  }

  if (!totpLib.verifyTotp(setup.secret, token, { window: TOTP_WINDOW })) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  adminOps.enableTotp(req.session.admin.id, setup.secret);
  delete req.session.admin2faSetup;
  res.json({ success: true });
});

// Disable 2FA (requires a valid current code)
app.post('/api/admin/2fa/disable', requireAdmin, (req, res) => {
  const token = String(req.body.token || '').trim();
  const admin = adminOps.getSecurity(req.session.admin.id);
  if (!admin) return res.status(404).json({ error: 'Admin not found' });
  if (!isAdminTotpEnabled(admin)) return res.status(400).json({ error: '2FA is not enabled' });

  if (!totpLib.verifyTotp(admin.totp_secret, token, { window: TOTP_WINDOW })) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  adminOps.disableTotp(req.session.admin.id);
  delete req.session.admin2faSetup;
  res.json({ success: true });
});

// ============================================================
// Root landing page
// ============================================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'home.html'));
});

// ============================================================
// Start
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════╗
║           Mini-IdP Started                   ║
╠══════════════════════════════════════════════╣
║  Admin Panel:  https://${HOSTNAME}/admin
║  SAML SSO:     https://${HOSTNAME}/saml/sso
║  Metadata:     https://${HOSTNAME}/saml/metadata
║  Port:         ${PORT}
╚══════════════════════════════════════════════╝
  `);
});
