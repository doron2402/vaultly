# Passly — Security Audit & Pentest Report

**Target:** `passly` v1.0.0 (zero-dependency CLI password/document vault)
**Date:** 2026-07-04
**Method:** Full source review (crypto.js, store.js, sync.js, prompt.js, cli.js, bin) +
dynamic attacks against a live vault instance (Node v22).
**Scope note:** No live/deployed host was attacked. "Pentest" here = static audit + dynamic
exploitation of a local instance I stood up myself.

---

## Bottom line

I could not break the cryptography, escape the vault directory, or bypass the master
password. The defenses that matter held up under direct attack. The most serious issue is
**not** a security break — it's **data loss**: passly silently corrupts any non-UTF-8 file
you store with `insert -f`, despite advertising "private documents." Fix that first.

The security posture then rests on two things worth hardening: a KDF cost that is on the
light side, and the fact that the master-password verifier is designed to be pushed to a git
remote — so the remote *must* stay private and the master password *must* be strong.

Confidence tags: **[Certain]** = reproduced/verified. **[Likely]** = strong inference.
**[Guessing]** = filling gaps.

---

## What I tried to break, and what held (the good news)

| Attack | Result |
|---|---|
| Path traversal (`../`, `..%2f`, `/etc/shadow`, `.ssh/id_rsa`, `a/./b`) | **Blocked** [Certain]. `normalizeEntry` strips leading slashes, rejects `..`/`.`/dotfiles, and whitelists `[\w@.+-]` per path segment. `/etc/shadow_x` became `store/etc/shadow_x.pass` *inside* the vault. Nothing escaped. |
| GCM ciphertext tampering (flip a byte) | **Detected** [Certain]. Auth tag mismatch → "file is corrupted", no plaintext leaked. |
| Wrong master password | **Rejected** [Certain] via encrypt-then-verify verifier. |
| GCM nonce reuse | **Not exploitable** [Certain]. Fresh random salt *and* IV per write, and the key is re-derived from the per-file salt — so the AES key changes with the salt. No cross-file nonce-under-same-key. |
| Argument injection via `sync setup -<flag>` | **Blocked** [Certain]. `parseFlags` rejects unknown dash-prefixed args before they reach git. |
| `git ext::` transport RCE via malicious remote URL | **Blocked in this environment** [Certain]. Modern git refuses `ext` transport by default (`protocol.ext.allow` unset). See L-3 — the safety currently comes from git, not passly. |
| Biased password generation | **Sound** [Certain]. Uses `crypto.randomInt` (rejection sampling, unbiased). |
| File permissions | **Correct** [Certain]. Vault dir `700`, store `700`, config + entries `600`. |

---

## Findings

### H-1 — `insert -f` corrupts binary/non-UTF-8 files (data loss) [Certain]
**Severity: High (integrity).** `src/cli.js` reads the file as a string and `crypto.js`
encrypts as UTF-8:

```js
secret = fs.readFileSync(flags.file, 'utf8');      // cli.js:160
cipher.update(plaintext, 'utf8')                   // crypto.js:21
```

Any byte that isn't valid UTF-8 is replaced with U+FFFD (`ef bf bd`) on the way in — the
original bytes are **gone before encryption**. Reproduced: a 19-byte PNG-like blob round-tripped
to 26 different bytes (md5 mismatch). A tool that markets "passwords **and private documents**"
will destroy PDFs, images, keys, archives.

**Fix:** treat entries as bytes end to end. Read with `fs.readFileSync(flags.file)` (Buffer),
`cipher.update(buffer)` (no encoding), and on `get` write raw bytes to stdout
(`process.stdout.write(buf)`), not `console.log`. If you want to keep a text-first UX, store a
type flag in the header and branch on it.

### H-2 — KDF cost is light and the verifier is built to live in git [Likely]
**Severity: Medium–High (depends on master-password entropy).**
`scrypt N=2^15, r=8, p=1` measured at **~47 ms/derivation** on this machine — fast for a
vault master key. Current OWASP guidance for scrypt is around `N=2^17` (please confirm against
the current Password Storage Cheat Sheet; I'm ~[Likely] on the exact number). This matters more
than usual here because **both** the ciphertext **and** `config.json` (the verifier, an offline
password-check oracle) are committed by `git add -A` and pushed to the remote (no `.gitignore`).
So if the remote leaks, an attacker gets a cheap offline brute-force target gated only by
scrypt cost + your master-password strength.

**Fix:** raise `N` to `2^17` (and raise `maxmem` — at `N=2^17,r=8` scrypt needs ~128 MB, above
the current 64 MB cap, so it will *throw* until you bump it). Store KDF params in the file
header/config so you can migrate cost later without breaking old files. Add a `.gitignore` only
if you decide the verifier shouldn't sync — but note it must sync for multi-machine verify, so
the real mitigation is (a) strong KDF, (b) a loud warning that the remote must be **private**,
(c) enforce a minimum master-password strength at `init`.

### M-1 — Master password leaks into every child-process environment [Certain]
**Severity: Medium.** `PASSLY_PASSWORD` / `PASSLY_NEW_PASSWORD` are read from `process.env`, and
every `spawnSync` (git, `pbcopy`/`clip`/`xclip`) inherits the full env by default. So the master
password is visible in the environment of git and the clipboard helper — readable via
`/proc/<pid>/environ`, and exfiltratable by a shimmed/compromised `git` or `xclip`.

**Fix:** pass a scrubbed env to every `spawnSync`:
`{ ...opts, env: { ...process.env, PASSLY_PASSWORD: undefined, PASSLY_NEW_PASSWORD: undefined } }`
(or an explicit minimal env). Children never need those vars.

### M-2 — `changePassword` re-encryption is not crash-atomic [Likely]
**Severity: Medium (reliability/data loss).** `store.js:50` stages every entry as `.tmp`, then
renames them in a loop and updates the verifier last. A crash/`kill` *during the rename loop*
leaves some entries re-keyed to the new password and some to the old, while the verifier still
matches the old one — those new-key entries become undecryptable with the verified password.

**Fix:** make it recoverable, not just staged: write a small journal/marker before the swap,
rename verifier/config as part of the same commit step, and on startup detect leftover `.tmp` +
journal to finish or roll back. At minimum, document that `passwd` must not be interrupted.

### L-1 — `-c` clipboard copy never auto-clears [Certain]
Secrets sit in the system clipboard indefinitely, readable by any app and by clipboard-history
managers. **Fix:** clear after a timeout (e.g. 30–45 s) and/or warn. Also only `xclip` is
supported on Linux — Wayland/`wl-copy` and `xsel` users silently fail.

### L-2 — `get` appends a trailing newline to stdout [Certain]
`output()` uses `console.log`, so `passly get token | consumer` receives `secret\n`. For API
tokens/keys consumed exactly, the extra byte can break auth. (Clipboard path is fine — it copies
the raw secret.) **Fix:** `process.stdout.write(secret)`; add newline only when attached to a TTY.

### L-3 — Remote URL is not validated (relies on git + arg-parser to stay safe) [Certain]
`sync setup <url>` passes the URL straight to `git remote add`. Today two independent guards
save you (git blocks `ext::`; `parseFlags` blocks `-`-prefixed URLs), but passly itself performs
no validation — a future refactor of either guard, or a user with `protocol.ext.allow=always`,
reopens a self-inflicted RCE. **Fix (defense in depth):** whitelist `https://`, `git@`,
`ssh://`, `git://` and reject `ext::`/`fd::`/transport-helper schemes.

### L-4 — Env-var password usage is inherently leaky [Certain]
Documented convenience, but `PASSLY_PASSWORD` lands in shell history and `/proc`. Keep it, but
document the risk and prefer stdin piping in scripts.

### I-1 — In-memory secrets can't be zeroed [Certain, informational]
Passwords/plaintext are JS strings — immutable, GC-retained, potentially swapped to disk. This is
a Node limitation, not a passly bug; note it in the threat model. Using Buffers for plaintext
(see H-1) at least lets you `buf.fill(0)` after use.

---

## Recommended fix order
1. **H-1** binary integrity — it's silently destroying user data now.
2. **M-1** scrub child env — small, high-value.
3. **H-2** raise scrypt cost + `maxmem`, enforce master-password minimum, warn "remote must be private."
4. **M-2** crash-safe `passwd`.
5. **L-1 / L-2 / L-3** clipboard clear, stdout newline, remote-URL whitelist.

## Threat model this is (and isn't) good for
Solid for: a single-user, git-synced **private** vault of **text** secrets, protected by a
**strong** master password. Weak for: storing binary documents (H-1), a leaked/public remote
with a weak master password (H-2), or multi-user/shared-machine use where env-var and clipboard
exposure (M-1, L-1) matter.
