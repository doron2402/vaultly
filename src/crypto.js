import crypto from 'node:crypto';

const MAGIC = Buffer.from('VLTY');
const VERSION = 1;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const SCRYPT_OPTS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, KEY_LEN, SCRYPT_OPTS);
}

// File layout: MAGIC(4) | version(1) | salt(16) | iv(12) | tag(16) | ciphertext
/**
 * Encrypt a secret under a fresh, password-derived key.
 * Accepts raw bytes so binary documents (SSH keys, PDFs, images) round-trip
 * byte-for-byte; a string is encoded as UTF-8.
 * @param {string|Buffer} plaintext - secret to seal
 * @param {string} password - master password
 * @returns {Buffer} MAGIC(4)|version(1)|salt(16)|iv(12)|tag(16)|ciphertext
 */
export function encrypt(plaintext, password) {
  // Normalize to bytes up front — never lossily UTF-8-decode binary input.
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, Buffer.from([VERSION]), salt, iv, tag, ciphertext]);
}

/**
 * Decrypt a vaultly blob. Returns RAW BYTES; callers that know an entry is text
 * (e.g. the verifier) decode with `.toString('utf8')`. Throws on a wrong
 * password or any tampering (GCM auth failure).
 * @param {Buffer} blob
 * @param {string} password
 * @returns {Buffer} decrypted plaintext bytes
 */
export function decrypt(blob, password) {
  if (blob.length < MAGIC.length + 1 + SALT_LEN + IV_LEN + TAG_LEN || !blob.subarray(0, 4).equals(MAGIC)) {
    throw new Error('not a vaultly file (bad header)');
  }
  let offset = MAGIC.length + 1;
  const salt = blob.subarray(offset, offset += SALT_LEN);
  const iv = blob.subarray(offset, offset += IV_LEN);
  const tag = blob.subarray(offset, offset += TAG_LEN);
  const ciphertext = blob.subarray(offset);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('wrong master password (or the file is corrupted)');
  }
}

const DEFAULT_CHARSET =
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?';
const ALNUM_CHARSET =
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

export function generatePassword(length = 20, { symbols = true } = {}) {
  if (!Number.isInteger(length) || length < 1 || length > 4096) {
    throw new Error('password length must be an integer between 1 and 4096');
  }
  const charset = symbols ? DEFAULT_CHARSET : ALNUM_CHARSET;
  let out = '';
  for (let i = 0; i < length; i++) {
    out += charset[crypto.randomInt(charset.length)];
  }
  return out;
}
