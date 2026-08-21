# Contributing to ek-ek

Türkçe: [CONTRIBUTING.tr.md](CONTRIBUTING.tr.md)

## Before you write code

**Every pull request needs a signed Contributor License Agreement**
([CLA.md](CLA.md)). No contribution is merged without it, and this is enforced
by an automated check rather than by memory.

The reason is specific: ek-ek is released under AGPL-3.0-or-later and is also
offered under separate commercial terms. Merging one contribution that does not
carry the necessary rights would end the commercial license permanently, for
everyone. Deleting the code afterwards does not undo it.

Signing takes one comment on your first pull request. The check tells you the
exact text to post. You are never asked again.

## Getting the project running

```bash
make dev-env     # create .env and the docker-data directories
make dev-up      # start the three node cluster
make dev-verify  # prove the preconditions the product depends on
```

`make help` lists every target.

## Before you open a pull request

```bash
make ci          # formatting, clippy, licenses, secrets, layering, unit tests
make dev-test    # integration tests against the docker cluster
```

Both must pass. `make ci` is the only target CI invokes for the quality gates,
so if it passes locally it passes there.

## What the code has to look like

- Code, code comments and log messages are written in English.
- Rust: no `.unwrap()` or `.expect()` outside tests. Return `Result` and use `?`.
  The workspace lints enforce this.
- SQL is parameterized. Never build a query by string concatenation.
- The web UI never calls `alert()`, `confirm()` or `prompt()`. Dialogs use
  SweetAlert2. Browser-side state goes in a cookie, never in `localStorage` or
  `sessionStorage`. A script in `make ci` checks all of this.
- Every Rust source file carries the two-line header from
  [LICENSE-HEADER.txt](LICENSE-HEADER.txt).
- Crate dependency direction is fixed and checked. `ek-ek-config` depends on no
  workspace crate; `ek-ek-dataplane` and `ek-ek-vrrp` never depend on each
  other; `ek-ek-itest` depends on no workspace crate at all.

## Commits

One logical change per commit. Write the message so it stands on its own: the
planning documents it might otherwise reference are not in this repository.

Never commit a secret. `.env`, private keys and certificates stay out. A pattern
based scan runs in `make ci`, but it is a safety net, not a guarantee.

## Reporting a security problem

Do not open a public issue. Use GitHub Private Vulnerability Reporting on this
repository, or write to `security@keremgok.tr`.

The full policy, with supported versions, a response time and a PGP key, lands
in `SECURITY.md` later. Until then these two channels are the ones that work.

## Reporting a bug or proposing a feature

Open an issue first for anything larger than a fix. Say what you observed, what
you expected, and what the environment was: distribution, kernel, how ek-ek was
installed, and how many nodes are in the cluster.
