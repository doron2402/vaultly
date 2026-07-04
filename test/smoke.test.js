import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert';

const bin = new URL('../bin/passly.js', import.meta.url).pathname;
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'passly-test-'));
const env = { ...process.env, PASSLY_HOME: home, PASSLY_PASSWORD: 'test-master-pw' };

const passly = (...args) =>
  execFileSync(process.execPath, [bin, ...args], { env, encoding: 'utf8' }).trim();

const passlyFails = (...args) => {
  try {
    execFileSync(process.execPath, [bin, ...args], { env, encoding: 'utf8', stdio: 'pipe' });
    return null;
  } catch (err) {
    return err.stderr.toString();
  }
};

try {
  // init
  passly('init');
  assert.ok(fs.existsSync(path.join(home, 'config.json')), 'config created');

  // generate stores and prints a password of the requested length
  const generated = passly('generate', 'password', 'aws/doron', '-n', '32');
  assert.strictEqual(generated.split('\n')[0].length, 32, '32-char password');

  // fetch via explicit get and via bare-path shorthand
  assert.strictEqual(passly('get', 'aws/doron'), generated, 'get returns stored password');
  assert.strictEqual(passly('aws/doron'), generated, 'bare path shorthand works');

  // stored file is encrypted on disk (no plaintext leak)
  const raw = fs.readFileSync(path.join(home, 'store', 'aws', 'doron.pass'));
  assert.ok(!raw.includes(generated), 'password not stored in plaintext');
  assert.strictEqual(raw.subarray(0, 4).toString(), 'PSLY', 'encrypted file header');

  // wrong master password is rejected
  const wrongEnv = { ...env, PASSLY_PASSWORD: 'wrong' };
  let failed = false;
  try {
    execFileSync(process.execPath, [bin, 'get', 'aws/doron'], { env: wrongEnv, stdio: 'pipe' });
  } catch { failed = true; }
  assert.ok(failed, 'wrong master password rejected');

  // insert from file (document support)
  const doc = path.join(home, 'note.txt');
  fs.writeFileSync(doc, 'ssh-rsa AAAA... my key\nline two\n');
  passly('insert', 'aws/ssh-key', '-f', doc);
  assert.ok(passly('get', 'aws/ssh-key').includes('line two'), 'document round-trips');

  // nested listing
  const tree = passly('list', 'aws');
  assert.ok(tree.includes('doron') && tree.includes('ssh-key'), 'list shows nested entries');

  // suggestions on typo and on folder hit
  const typo = passlyFails('get', 'aws/dorn');
  assert.ok(typo.includes('aws/doron'), 'typo suggests aws/doron');
  const folder = passlyFails('get', 'aws');
  assert.ok(folder.includes('is a folder') && folder.includes('aws/doron'), 'folder lists children');

  // no-symbols generation
  const plain = passly('generate', 'password', 'simple', '-n', '16', '--no-symbols');
  assert.ok(/^[A-Za-z0-9]{16}$/.test(plain.split('\n')[0]), 'no-symbols is alphanumeric');

  // rm deletes and cleans empty dirs
  passly('rm', 'simple');
  const gone = passlyFails('get', 'simple');
  assert.ok(gone.includes('nothing stored'), 'removed entry is gone');

  // passwd re-encrypts everything under the new master password
  execFileSync(process.execPath, [bin, 'passwd'], {
    env: { ...env, PASSLY_NEW_PASSWORD: 'new-master-pw' }, stdio: 'pipe',
  });
  const newEnv = { ...env, PASSLY_PASSWORD: 'new-master-pw' };
  const afterChange = execFileSync(process.execPath, [bin, 'get', 'aws/doron'], {
    env: newEnv, encoding: 'utf8',
  }).trim();
  assert.strictEqual(afterChange, generated, 'entry readable with new master password');
  let oldRejected = false;
  try {
    execFileSync(process.execPath, [bin, 'get', 'aws/doron'], { env, stdio: 'pipe' });
  } catch { oldRejected = true; }
  assert.ok(oldRejected, 'old master password rejected after change');
  env.PASSLY_PASSWORD = 'new-master-pw';

  // sync: link to a bare repo (stand-in for GitHub), push, verify remote content
  const gitEnv = {
    ...env,
    GIT_AUTHOR_NAME: 'test', GIT_AUTHOR_EMAIL: 'test@test',
    GIT_COMMITTER_NAME: 'test', GIT_COMMITTER_EMAIL: 'test@test',
  };
  const syncDir = fs.mkdtempSync(path.join(os.tmpdir(), 'passly-sync-'));
  const remote = path.join(syncDir, 'remote.git');
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', remote]);
  execFileSync(process.execPath, [bin, 'sync', 'setup', remote], { env: gitEnv, stdio: 'pipe' });
  execFileSync(process.execPath, [bin, 'generate', 'password', 'synced/entry'], { env: gitEnv, stdio: 'pipe' });
  execFileSync(process.execPath, [bin, 'sync'], { env: gitEnv, stdio: 'pipe' });
  const clone = path.join(syncDir, 'clone');
  execFileSync('git', ['clone', '-q', remote, clone], { env: gitEnv });
  assert.ok(
    fs.existsSync(path.join(clone, 'store', 'synced', 'entry.pass')),
    'synced entry present in remote clone',
  );
  const cloned = fs.readFileSync(path.join(clone, 'store', 'synced', 'entry.pass'));
  assert.strictEqual(cloned.subarray(0, 4).toString(), 'PSLY', 'remote copy is encrypted');
  const syncStatus = execFileSync(process.execPath, [bin, 'sync', 'status'], {
    env: gitEnv, encoding: 'utf8',
  });
  assert.ok(syncStatus.includes(remote), 'sync status shows remote url');

  // path traversal rejected
  const evil = passlyFails('get', '../../etc/passwd');
  assert.ok(evil.includes('invalid entry name'), 'path traversal rejected');

  console.log('all smoke tests passed');
} finally {
  fs.rmSync(home, { recursive: true, force: true });
  for (const dir of fs.readdirSync(os.tmpdir())) {
    if (dir.startsWith('passly-sync-')) {
      fs.rmSync(path.join(os.tmpdir(), dir), { recursive: true, force: true });
    }
  }
}
