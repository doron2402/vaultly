import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { encrypt, decrypt } from './crypto.js';

const EXT = '.pass';
const VERIFIER_PLAINTEXT = 'passly-verifier-v1';

export function passlyHome() {
  return process.env.PASSLY_HOME || path.join(os.homedir(), '.passly');
}

function storeDir() {
  return path.join(passlyHome(), 'store');
}

function configPath() {
  return path.join(passlyHome(), 'config.json');
}

export function isInitialized() {
  return fs.existsSync(configPath());
}

export function init(password) {
  if (isInitialized()) {
    throw new Error(`already initialized (${passlyHome()}). Delete that directory to start over.`);
  }
  fs.mkdirSync(storeDir(), { recursive: true, mode: 0o700 });
  const config = {
    version: 1,
    createdAt: new Date().toISOString(),
    verifier: encrypt(VERIFIER_PLAINTEXT, password).toString('base64'),
  };
  fs.writeFileSync(configPath(), JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

export function verifyPassword(password) {
  const config = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
  try {
    return decrypt(Buffer.from(config.verifier, 'base64'), password) === VERIFIER_PLAINTEXT;
  } catch {
    return false;
  }
}

// Re-encrypt every entry and the verifier with a new master password.
// Two phases: decrypt everything and stage the re-encrypted files as .tmp
// (aborting cleanly if any entry fails), then swap the staged files in.
export function changePassword(oldPassword, newPassword) {
  const entries = listEntries();
  const staged = [];
  try {
    for (const entry of entries) {
      const file = entryFile(entry);
      const plaintext = decrypt(fs.readFileSync(file), oldPassword);
      fs.writeFileSync(file + '.tmp', encrypt(plaintext, newPassword), { mode: 0o600 });
      staged.push(file);
    }
  } catch (err) {
    for (const file of staged) fs.rmSync(file + '.tmp', { force: true });
    throw new Error(`aborted, nothing changed: ${err.message}`);
  }
  for (const file of staged) fs.renameSync(file + '.tmp', file);
  const config = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
  config.verifier = encrypt(VERIFIER_PLAINTEXT, newPassword).toString('base64');
  config.passwordChangedAt = new Date().toISOString();
  fs.writeFileSync(configPath(), JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  return entries.length;
}

// Normalize a user-supplied entry path and reject anything that escapes the store.
export function normalizeEntry(entry) {
  const cleaned = entry.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!cleaned) throw new Error('entry name cannot be empty');
  const parts = cleaned.split('/').filter(Boolean);
  if (parts.some((p) => p === '.' || p === '..' || p.startsWith('.'))) {
    throw new Error(`invalid entry name: ${entry}`);
  }
  if (!parts.every((p) => /^[\w@.+-]+$/.test(p))) {
    throw new Error(`invalid entry name: ${entry} (use letters, digits, @ . _ + - and / for nesting)`);
  }
  return parts.join('/');
}

function entryFile(entry) {
  return path.join(storeDir(), ...entry.split('/')) + EXT;
}

export function exists(entry) {
  return fs.existsSync(entryFile(entry));
}

export function save(entry, plaintext, password) {
  const file = entryFile(entry);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, encrypt(plaintext, password), { mode: 0o600 });
}

export function load(entry, password) {
  return decrypt(fs.readFileSync(entryFile(entry)), password);
}

export function remove(entry) {
  fs.rmSync(entryFile(entry));
  // Clean up now-empty parent directories up to the store root.
  let dir = path.dirname(entryFile(entry));
  const root = storeDir();
  while (dir !== root && fs.readdirSync(dir).length === 0) {
    fs.rmdirSync(dir);
    dir = path.dirname(dir);
  }
}

export function listEntries(prefix = '') {
  const root = storeDir();
  if (!fs.existsSync(root)) return [];
  const entries = [];
  const walk = (dir, rel) => {
    for (const name of fs.readdirSync(dir).sort()) {
      const full = path.join(dir, name);
      if (fs.statSync(full).isDirectory()) {
        walk(full, rel ? `${rel}/${name}` : name);
      } else if (name.endsWith(EXT)) {
        const entry = (rel ? `${rel}/` : '') + name.slice(0, -EXT.length);
        entries.push(entry);
      }
    }
  };
  walk(root, '');
  return prefix ? entries.filter((e) => e === prefix || e.startsWith(prefix + '/')) : entries;
}

// True when `entry` is a folder in the tree (has entries beneath it).
export function isGroup(entry) {
  return listEntries(entry).some((e) => e !== entry);
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return dp[a.length][b.length];
}

export function suggest(query, limit = 5) {
  const q = query.toLowerCase();
  const scored = listEntries().map((entry) => {
    const e = entry.toLowerCase();
    const base = e.split('/').pop();
    let score;
    if (e.startsWith(q) || base.startsWith(q)) score = 0;
    else if (e.includes(q)) score = 1;
    else score = 2 + Math.min(levenshtein(q, e), levenshtein(q, base)) / Math.max(q.length, 1);
    return { entry, score };
  });
  return scored
    .filter(({ score }) => score < 2 + 0.6) // drop entries that aren't remotely close
    .sort((a, b) => a.score - b.score)
    .slice(0, limit)
    .map(({ entry }) => entry);
}
