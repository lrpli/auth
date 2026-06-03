const express = require('express');
const session = require('express-session');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const { adminOps, userOps, spOps, logOps } = require('./lib/db');
const samlLib = require('./lib/saml');

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

const app = express();

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
  const { email, password } = req.body;

  const user = userOps.verify(email, password);
  if (!user) {
    logOps.add(email, req.session.saml?.issuer || 'unknown', false, req.ip);
    return res.redirect('/sso/login?error=invalid');
  }

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
  const { username, password } = req.body;
  const admin = adminOps.verify(username, password);
  if (!admin) {
    return res.redirect('/admin/login?error=1');
  }
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
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  adminOps.changePassword(req.session.admin.id, newPassword);
  res.json({ success: true });
});

// ============================================================
// Root redirect
// ============================================================
app.get('/', (req, res) => {
  res.redirect('/admin');
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
