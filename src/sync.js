import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { passlyHome } from './store.js';
import { childEnv } from './env.js';

function git(args) {
  // Scrub master-password env vars so git never sees them (SECURITY_AUDIT.md M-1).
  const res = spawnSync('git', ['-C', passlyHome(), ...args], { encoding: 'utf8', env: childEnv() });
  if (res.error) throw new Error('git is not installed — install it to use passly sync');
  return res;
}

function gitOrThrow(args) {
  const res = git(args);
  if (res.status !== 0) {
    throw new Error(`git ${args[0]} failed: ${(res.stderr || res.stdout).trim()}`);
  }
  return res.stdout.trim();
}

export function hasRepo() {
  return fs.existsSync(path.join(passlyHome(), '.git'));
}

function hasChanges() {
  return gitOrThrow(['status', '--porcelain']) !== '';
}

function commitAll(message) {
  gitOrThrow(['add', '-A']);
  if (!hasChanges()) return false;
  gitOrThrow(['commit', '-q', '-m', message]);
  return true;
}

// Best-effort local commit after a vault mutation. Never breaks the
// operation itself — sync surfaces real git problems.
export function autoCommit(message) {
  if (!hasRepo()) return;
  try {
    commitAll(message);
  } catch {
    // ignore — next `passly sync` will pick the changes up or report the issue
  }
}

export function setup(remoteUrl) {
  if (!remoteUrl) {
    throw new Error('usage: passly sync setup <remote-url>\nexample: passly sync setup git@github.com:you/passly-vault.git');
  }
  if (!hasRepo()) {
    gitOrThrow(['init', '-q']);
    gitOrThrow(['branch', '-M', 'main']);
  }
  const hasOrigin = git(['remote', 'get-url', 'origin']).status === 0;
  gitOrThrow(hasOrigin ? ['remote', 'set-url', 'origin', remoteUrl] : ['remote', 'add', 'origin', remoteUrl]);
  commitAll('passly: initial vault');
  gitOrThrow(['push', '-q', '-u', 'origin', 'main']);
  return remoteUrl;
}

export function sync() {
  if (!hasRepo()) {
    throw new Error("vault is not linked to a remote yet. Run 'passly sync setup <remote-url>' first.");
  }
  const committed = commitAll(`passly sync ${new Date().toISOString()}`);
  if (git(['remote', 'get-url', 'origin']).status !== 0) {
    throw new Error("no 'origin' remote configured. Run 'passly sync setup <remote-url>'.");
  }
  const pull = git(['pull', '-q', '--rebase', 'origin', 'main']);
  if (pull.status !== 0) {
    const detail = (pull.stderr || pull.stdout).trim();
    if (/CONFLICT|could not apply/i.test(detail)) {
      git(['rebase', '--abort']);
      throw new Error(
        `sync conflict: the same entry changed here and on the remote.\nResolve it manually in ${passlyHome()} (it is a normal git repo), then run 'passly sync' again.`,
      );
    }
    throw new Error(`git pull failed: ${detail}`);
  }
  gitOrThrow(['push', '-q', 'origin', 'main']);
  return { committed };
}

export function status() {
  if (!hasRepo()) return 'not set up — run: passly sync setup <remote-url>';
  const remote = git(['remote', 'get-url', 'origin']);
  const lines = [`vault:  ${passlyHome()}`];
  lines.push(`remote: ${remote.status === 0 ? remote.stdout.trim() : '(none)'}`);
  gitOrThrow(['add', '-A']);
  lines.push(hasChanges() ? 'local changes: yes (will be committed on next sync)' : 'local changes: none');
  return lines.join('\n');
}
