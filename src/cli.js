import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import * as store from './store.js';
import * as sync from './sync.js';
import { generatePassword } from './crypto.js';
import { getMasterPassword, promptHidden } from './prompt.js';
import { childEnv } from './env.js';

const HELP = `passly — encrypted password & document store

Usage:
  passly init                          Set your master password (run once)
  passly generate <name> [-n <chars>] [--no-symbols] [-c]
                                       Generate, store and print a password
  passly <name>                        Fetch a secret (same as: passly get <name>)
  passly get <name> [-c]               Fetch a secret; -c copies instead of printing
  passly insert <name>                 Store a secret you type in (hidden prompt)
  passly insert <name> -f <file>       Encrypt and store a document/file
  passly list [prefix]                 List stored entries as a tree
  passly rm <name>                     Delete an entry
  passly passwd                        Change the master password (re-encrypts everything)
  passly sync setup <remote-url>       Link the vault to a GitHub repo (one time)
  passly sync                          Commit, pull and push the encrypted vault
  passly sync status                   Show sync state
  passly help                          Show this help

Names nest with '/', e.g. passly aws/doron, passly work/github.
Options:
  -n <chars>      Password length (default 20)
  --no-symbols    Alphanumeric passwords only
  -c, --copy      Copy the secret to the clipboard instead of printing
  -f <file>       Read the secret's content from a file

Secrets live as individually encrypted files (AES-256-GCM, scrypt) under
${store.passlyHome()}. Set PASSLY_PASSWORD to skip the prompt in scripts.`;

function parseFlags(args) {
  const flags = { symbols: true, copy: false, length: 20, file: null };
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-n' || a === '--length') flags.length = Number(args[++i]);
    else if (a === '--no-symbols') flags.symbols = false;
    else if (a === '-c' || a === '--copy') flags.copy = true;
    else if (a === '-f' || a === '--file') flags.file = args[++i];
    else if (a === '-h' || a === '--help') flags.help = true;
    else if (a.startsWith('-')) throw new Error(`unknown option: ${a} (try: passly help)`);
    else positional.push(a);
  }
  return { flags, positional };
}

function requireInit() {
  if (!store.isInitialized()) {
    throw new Error("no vault found. Run 'passly init' first to set your master password.");
  }
}

async function unlock() {
  requireInit();
  const password = await getMasterPassword();
  if (!store.verifyPassword(password)) throw new Error('wrong master password');
  return password;
}

function copyToClipboard(text) {
  const cmd = process.platform === 'darwin' ? 'pbcopy'
    : process.platform === 'win32' ? 'clip' : 'xclip';
  const args = cmd === 'xclip' ? ['-selection', 'clipboard'] : [];
  // `text` may be a Buffer (binary entry) or string; both are valid stdin.
  // childEnv() keeps the master password out of the helper's environment (M-1).
  const res = spawnSync(cmd, args, { input: text, env: childEnv() });
  if (res.status !== 0) throw new Error(`could not copy to clipboard (${cmd} failed)`);
}

/**
 * Emit a secret, either to the clipboard or stdout.
 * @param {string|Buffer} secret - raw bytes (from load) or generated string
 * @param {{copy: boolean, label: string}} opts
 */
function output(secret, { copy, label }) {
  if (copy) {
    copyToClipboard(secret);
    console.log(`Copied ${label} to clipboard.`);
  } else {
    // Write raw bytes so binary documents come back byte-for-byte. Add a
    // trailing newline only for a human at a TTY; piped/redirected consumers
    // (e.g. `passly get token | curl ...`) get the exact secret (fixes L-2).
    process.stdout.write(secret);
    if (process.stdout.isTTY) process.stdout.write('\n');
  }
}

function printTree(entries, prefix) {
  if (entries.length === 0) {
    console.log(prefix ? `no entries under '${prefix}'` : 'store is empty');
    return;
  }
  console.log(prefix || 'passly store');
  // Build nested structure from flat entry paths.
  const root = {};
  for (const entry of entries) {
    const rel = prefix ? entry.slice(prefix.length).replace(/^\//, '') : entry;
    if (!rel) { console.log('(this entry itself holds a secret)'); continue; }
    let node = root;
    for (const part of rel.split('/')) node = node[part] ??= {};
  }
  const draw = (node, indent) => {
    const keys = Object.keys(node);
    keys.forEach((key, i) => {
      const last = i === keys.length - 1;
      console.log(`${indent}${last ? '└── ' : '├── '}${key}`);
      draw(node[key], indent + (last ? '    ' : '│   '));
    });
  };
  draw(root, '');
}

function suggestFor(name) {
  if (store.isGroup(name)) {
    const children = store.listEntries(name);
    return `'${name}' is a folder. Entries inside:\n  ${children.join('\n  ')}`;
  }
  const suggestions = store.suggest(name);
  if (suggestions.length === 0) {
    return `nothing stored at '${name}'. Run 'passly list' to see what you have.`;
  }
  return `nothing stored at '${name}'. Did you mean:\n  ${suggestions.join('\n  ')}`;
}

async function cmdInit() {
  if (store.isInitialized()) {
    throw new Error(`vault already exists at ${store.passlyHome()}`);
  }
  console.log('Setting up passly. Pick a master password — it encrypts everything you store.');
  const password = await getMasterPassword({ confirm: true, promptText: 'New master password: ' });
  store.init(password);
  console.log(`Done. Vault created at ${store.passlyHome()}`);
  console.log("Try: passly generate aws/doron -n 24");
}

async function cmdGenerate(positional, flags) {
  // Canonical form is `generate <name>`. The legacy `generate password <name>`
  // is still accepted (backward compatible) by dropping a leading "password".
  if (positional[0] === 'password') positional.shift();
  const name = store.normalizeEntry(positional[0] ?? (() => { throw new Error('usage: passly generate <name> [-n <chars>]'); })());
  const password = await unlock();
  const secret = generatePassword(flags.length, { symbols: flags.symbols });
  if (store.exists(name)) {
    const answer = await promptHidden(`'${name}' already exists. Overwrite? (y/N) `);
    if (answer.toLowerCase() !== 'y') { console.log('aborted'); return; }
  }
  store.save(name, secret, password);
  sync.autoCommit(`generate ${name}`);
  output(secret, { copy: flags.copy, label: name });
  if (!flags.copy) console.error(`Stored at ${name} (${flags.length} chars).`);
}

async function cmdGet(name, flags) {
  requireInit();
  const entry = store.normalizeEntry(name);
  if (!store.exists(entry)) throw new Error(suggestFor(entry));
  const password = await unlock();
  output(store.load(entry, password), { copy: flags.copy, label: entry });
}

async function cmdInsert(name, flags) {
  const entry = store.normalizeEntry(name);
  const password = await unlock();
  let secret;
  if (flags.file) {
    // Read as raw bytes so documents (keys, PDFs, images) are stored intact (H-1).
    secret = fs.readFileSync(flags.file);
  } else {
    secret = await promptHidden(`Secret for ${entry}: `);
    if (!secret) throw new Error('secret cannot be empty');
    if (process.env.PASSLY_PASSWORD === undefined && process.stdin.isTTY) {
      const again = await promptHidden('Confirm secret: ');
      if (again !== secret) throw new Error('secrets do not match');
    }
  }
  if (store.exists(entry)) {
    const answer = await promptHidden(`'${entry}' already exists. Overwrite? (y/N) `);
    if (answer.toLowerCase() !== 'y') { console.log('aborted'); return; }
  }
  store.save(entry, secret, password);
  sync.autoCommit(`insert ${entry}`);
  console.log(`Stored ${entry}.`);
}

async function cmdPasswd() {
  requireInit();
  const oldPassword = process.env.PASSLY_PASSWORD !== undefined
    ? process.env.PASSLY_PASSWORD
    : await promptHidden('Current master password: ');
  if (!store.verifyPassword(oldPassword)) throw new Error('wrong master password');
  let newPassword;
  if (process.env.PASSLY_NEW_PASSWORD !== undefined) {
    newPassword = process.env.PASSLY_NEW_PASSWORD;
  } else {
    newPassword = await promptHidden('New master password: ');
    const again = await promptHidden('Confirm new master password: ');
    if (newPassword !== again) throw new Error('passwords do not match');
  }
  if (!newPassword) throw new Error('password cannot be empty');
  if (newPassword === oldPassword) throw new Error('new password is the same as the current one');
  const count = store.changePassword(oldPassword, newPassword);
  sync.autoCommit('change master password');
  console.log(`Master password changed. Re-encrypted ${count} ${count === 1 ? 'entry' : 'entries'}.`);
}

async function cmdRemove(name) {
  requireInit();
  const entry = store.normalizeEntry(name);
  if (!store.exists(entry)) throw new Error(suggestFor(entry));
  await unlock(); // deleting requires knowing the master password
  store.remove(entry);
  sync.autoCommit(`remove ${entry}`);
  console.log(`Removed ${entry}.`);
}

export async function run(argv) {
  const { flags, positional } = parseFlags(argv);
  const [command, ...rest] = positional;

  if (flags.help || !command || command === 'help') {
    console.log(HELP);
    return;
  }

  switch (command) {
    case 'init':
      return cmdInit();
    case 'generate':
    case 'gen':
      return cmdGenerate(rest, flags);
    case 'get':
    case 'show':
      if (!rest[0]) throw new Error('usage: passly get <name>');
      return cmdGet(rest[0], flags);
    case 'insert':
    case 'add':
    case 'set':
      if (!rest[0]) throw new Error('usage: passly insert <name> [-f <file>]');
      return cmdInsert(rest[0], flags);
    case 'list':
    case 'ls': {
      requireInit();
      const prefix = rest[0] ? store.normalizeEntry(rest[0]) : '';
      return printTree(store.listEntries(prefix), prefix);
    }
    case 'passwd':
    case 'change-password':
      return cmdPasswd();
    case 'sync': {
      requireInit();
      if (rest[0] === 'setup') {
        const url = sync.setup(rest[1]);
        console.log(`Vault linked to ${url} and pushed.`);
      } else if (rest[0] === 'status') {
        console.log(sync.status());
      } else if (rest[0]) {
        throw new Error(`unknown sync subcommand: ${rest[0]} (use: setup <url> | status | nothing)`);
      } else {
        const { committed } = sync.sync();
        console.log(committed ? 'Synced: local changes pushed, remote changes pulled.' : 'Synced: already up to date locally, pulled remote changes.');
      }
      return;
    }
    case 'rm':
    case 'remove':
    case 'delete':
      if (!rest[0]) throw new Error('usage: passly rm <name>');
      return cmdRemove(rest[0]);
    case 'version':
    case '--version':
      console.log('passly 1.0.0');
      return;
    default:
      // Bare path shorthand: `passly aws/doron` fetches that entry.
      return cmdGet(command, flags);
  }
}
