'use strict';

// Mirrors umami-software/umami's src/lib/crypto.ts encrypt()/hash()/secret()
// exactly (same algorithm, same byte layout), so tokens minted here decrypt
// and verify cleanly inside Umami itself.

const crypto = require('node:crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;
const TAG_POSITION = SALT_LENGTH + IV_LENGTH;
const ENC_POSITION = TAG_POSITION + TAG_LENGTH;

function getKey(secret, salt) {
  return crypto.pbkdf2Sync(secret, salt, 10000, 32, 'sha512');
}

function encrypt(value, secret) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = getKey(secret, salt);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

function hash(...args) {
  return crypto.createHash('sha512').update(args.join('')).digest('hex');
}

function secretFromAppSecret(appSecret) {
  return hash(appSecret);
}

module.exports = { encrypt, hash, secretFromAppSecret };
