# Security

`interceptor` writes signed, hash-chained evidence for consequential
calls. Its trust model matters more than its code does, so read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before reporting or fixing.

## Reporting a vulnerability

Do **not** open a public GitHub issue for a vulnerability that could let an
attacker forge, edit, or disclose evidence.

Report it privately instead:

- If you have write access to the repository, use GitHub's private security
  advisory flow.
- Otherwise, email the maintainers via the contact address listed on the
  project page, and include "interceptor" in the subject line.

Please include:

- the affected version(s);
- the threat-model assumption you believe is violated (or why it is not);
- a minimal reproduction, ideally with a patched journal you can verify
  against;
- whether the issue is a forgery, an integrity break, a disclosure, or a
  denial of service.

We will acknowledge within 48 hours, and prefer a coordinated fix and release
before public disclosure.

## What is and is not in scope

In scope:

- a path by which evidence can be produced, reordered, or edited without the
  signing key, or verified as authentic when it is not;
- a route for named secrets past the fused redaction/canonicalization
  traversal into the journal, a summary, a prompt, or an error message;
- a fail-open path (an approval or observer failure that silently proceeds);
- an authentication or permission weakness in key handling.

Explicitly out of scope, because the threat model states them as limits:

- detecting deletion of the journal **tail** — the documented gap that needs an
  external witness;
- a compromised process or a stolen signing key (both are trust assumptions);
- recoverability of *non-redacted* low-entropy values from `input_hash`.

## Key handling

- The private key is created mode `0600` and the guard refuses to sign with a
  key that is readable by other users (POSIX).
- Rotation (`key-rotate`) keeps the outgoing public key in the `trusted_keys/`
  directory inside the evidence home, so evidence signed before the rotation
  stays verifiable. The trusted set is local operator state, not a signature:
  it protects integrity across key changes, it does not authenticate a key.
  Pin the public key out-of-band (e.g. `--public-key`) for real authentication.
- Never paste a private key or a journal into an issue.
- A journal that failed `interceptor verify` is evidence of tampering or
  corruption; do not discard it, keep it for analysis.

## Supported versions

Only the latest release is patched. Pin exact versions in anything that signs
or verifies evidence; a compromise of the signing path is total and
retroactive.