#!/usr/bin/env node
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const CERT_DIR = path.join(__dirname, 'certs');
const ENV_FILE = path.join(__dirname, '.env');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(r => rl.question(q, r));

async function main() {
  console.log('\n🔧  Mini-IdP Setup\n');

  // 1. Hostname
  const hostname = await ask('Enter your domain (e.g. idp.acrio.org): ');
  if (!hostname) { console.log('Domain is required.'); process.exit(1); }

  // 2. Admin credentials
  const adminUser = (await ask('Admin username [admin]: ')) || 'admin';
  const adminPass = await ask('Admin password: ');
  if (!adminPass) { console.log('Password is required.'); process.exit(1); }

  // 3. Session secret
  const crypto = require('crypto');
  const sessionSecret = crypto.randomBytes(32).toString('hex');

  // 4. Generate certificates
  console.log('\n📜  Generating signing certificates...');
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

  const keyPath = path.join(CERT_DIR, 'idp-private-key.pem');
  const certPath = path.join(CERT_DIR, 'idp-certificate.pem');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    const overwrite = await ask('Certificates already exist. Overwrite? [y/N]: ');
    if (overwrite.toLowerCase() !== 'y') {
      console.log('Keeping existing certificates.');
    } else {
      generateCerts(hostname, keyPath, certPath);
    }
  } else {
    generateCerts(hostname, keyPath, certPath);
  }

  // 5. Write .env
  const envContent = `# Mini-IdP Configuration
HOSTNAME=${hostname}
PORT=8080
ADMIN_USERNAME=${adminUser}
ADMIN_PASSWORD=${adminPass}
SESSION_SECRET=${sessionSecret}

# Login protection
LOGIN_CAPTCHA_THRESHOLD=3
LOGIN_LOCK_THRESHOLD=10
LOGIN_LOCK_MS=900000
LOGIN_ATTEMPT_TTL_MS=86400000
CAPTCHA_TTL_MS=300000

# Admin 2FA (TOTP)
TOTP_ISSUER=Mini-IdP
TOTP_WINDOW=1
TOTP_SETUP_TTL_MS=600000
`;
  fs.writeFileSync(ENV_FILE, envContent);
  console.log('✅  Config saved to .env');

  // 6. Create admin user in DB
  const { adminOps } = require('./lib/db');
  if (adminOps.count() === 0) {
    adminOps.create(adminUser, adminPass);
    console.log(`✅  Admin user "${adminUser}" created`);
  } else {
    console.log('ℹ️   Admin user already exists, skipping');
  }

  console.log(`
✅  Setup complete!

Start the server:
  node server.js

Then visit:
  https://${hostname}/admin    - Management panel
  https://${hostname}/saml/metadata  - SAML metadata (give this to Google/Microsoft)

Certificate file (upload to Google/Microsoft):
  ${certPath}
`);

  rl.close();
}

function generateCerts(hostname, keyPath, certPath) {
  try {
    execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -subj "/CN=${hostname}"`, { stdio: 'pipe' });
    console.log('✅  Certificates generated');
  } catch (e) {
    console.error('Failed to generate certificates:', e.message);
    process.exit(1);
  }
}

main().catch(console.error);
