const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(value) {
  const cleaned = String(value || '')
    .toUpperCase()
    .replace(/[^A-Z2-7]/g, '');

  let bits = 0;
  let current = 0;
  const bytes = [];

  for (const char of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;

    current = (current << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

function hotp(secret, counter, digits = 6) {
  const key = base32Decode(secret);
  if (!key.length) return null;

  const counterBuffer = Buffer.alloc(8);
  let value = counter;
  for (let i = 7; i >= 0; i -= 1) {
    counterBuffer[i] = value & 255;
    value = Math.floor(value / 256);
  }

  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 15;

  const code =
    ((hmac[offset] & 127) << 24) |
    ((hmac[offset + 1] & 255) << 16) |
    ((hmac[offset + 2] & 255) << 8) |
    (hmac[offset + 3] & 255);

  return String(code % (10 ** digits)).padStart(digits, '0');
}

function normalizeToken(token) {
  return String(token || '').replace(/\s+/g, '');
}

function totp(secret, { timestamp = Date.now(), step = 30, digits = 6 } = {}) {
  const counter = Math.floor(Math.floor(timestamp / 1000) / step);
  return hotp(secret, counter, digits);
}

function verifyTotp(secret, token, { window = 1, step = 30, digits = 6, timestamp = Date.now() } = {}) {
  const normalizedToken = normalizeToken(token);
  if (!/^\d+$/.test(normalizedToken) || normalizedToken.length !== digits) return false;

  const currentCounter = Math.floor(Math.floor(timestamp / 1000) / step);
  for (let i = -window; i <= window; i += 1) {
    const expected = hotp(secret, currentCounter + i, digits);
    if (expected && expected === normalizedToken) {
      return true;
    }
  }

  return false;
}

function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

function buildOtpAuthUrl({ issuer, accountName, secret }) {
  const safeIssuer = String(issuer || 'Mini-IdP');
  const safeAccountName = String(accountName || 'admin');
  const label = `${safeIssuer}:${safeAccountName}`;
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(safeIssuer)}&algorithm=SHA1&digits=6&period=30`;
}

module.exports = {
  generateSecret,
  totp,
  verifyTotp,
  buildOtpAuthUrl
};
