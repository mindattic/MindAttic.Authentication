---
codex: 1
project: MindAttic.Authentication
code: AUTH
layer: rfc
status: planned
updated: 2026-06-07
---

# RFC 0001 — Operator provisioning CLI for CSPRNG secrets

## Problem
[AUTH-LAW-2](../BIBLE.md#AUTH-LAW-2) requires that the running app never write production secrets, yet a fresh deployment needs a CSPRNG pepper, a Data-Protection KEK, and a reset-token key to exist in Vault before first request. Today these must be hand-generated, which is error-prone and tempts insecure shortcuts. We need a *separate* operator tool that generates and seeds them.

## Options compared
1. **In-app rotation UI that writes secrets.** Rejected — violates [AUTH-LAW-2](../BIBLE.md#AUTH-LAW-2) (app would write prod secrets) and widens the prod write surface.
2. **Pure documentation / manual `openssl`.** Works but is unauditable and easy to get wrong (wrong length, wrong bucket, wrong key id).
3. **A separate `dotnet run --provision` operator tool (in `tools/`).** Generates CSPRNG values; in **dev** writes to the Vault file `CredentialStore`/`TokenStore`; in **prod** prints operator/IaC instructions to seed env / Azure Key Vault out-of-band. Chosen.

## Decision
Build option 3 as a standalone console tool under `tools/`, depending on `MindAttic.Vault` and the library's `Secrets` contract. It emits `pepper.vN`, the DP KEK, the reset-token key, the CAPTCHA secret, and a one-time bootstrap token, each ≥32 bytes CSPRNG, redacting values from any log.

## What NOT to do
- Do **not** let the tool ship inside the NuGet package or be reachable from the web host.
- Do **not** write prod secrets from the tool — prod path only *prints* instructions.
- Do **not** invent default secret values (no fallback-to-empty); absent prod secrets must keep failing closed.

## Phased plan (with risk)
1. Console scaffold + CSPRNG generation (low risk).
2. Dev file-store seeding via Vault `CredentialStore`/`TokenStore` (low risk).
3. Prod "print instructions only" path + Key Vault guidance (medium risk — must never silently write).
4. Wire one-time bootstrap token consumption with `AuthBootstrapper` (medium risk — race-safe seeding).

## Graduates into
[BIBLE §4.1 / §6](../BIBLE.md#AUTH-§4) (the `tools/` provisioning project) and [USER_STORIES](../USER_STORIES.md) backlog item **AUTH-US-F3** when shipped.
