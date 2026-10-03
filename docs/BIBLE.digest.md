# MindAttic.Authentication - Bible Digest
> AUTHORITATIVE - full detail in docs/BIBLE.md
> generatedFrom: docs/BIBLE.md (#AUTH-§1, #AUTH-§3, #AUTH-§5, #AUTH-§9)
> generated: 2026-10-03 by tools/codex.ps1 digest - do not hand-edit

## The one sentence (AUTH-§1)
MindAttic.Authentication is a maximally-secure, **Vault-backed** authentication engine shipped as a single Razor Class Library (NuGet) so every consuming MindAttic app (MindAttic.Ideas, Prose, Tutor, IdiotProof) authenticates **identically** — built to OWASP ASVS L2 (L3 where feasible) and NIST SP 800-63B AAL2, under a threat model that assumes a skilled attacker **and a future full database breach**.

## What it is NOT (AUTH-§3)
- **NOT a per-app rolled scheme.** Apps do not implement password hashing, lockout, MFA, or sessions; they adopt this library (org [HOUSE-LAW-7](../../MindAttic.HouseRules.md#HOUSE-LAW-7)).
- **NOT a cross-app SSO / identity provider.** Each consuming app is a **separate trust boundary**; there is no shared login session across apps.
- **NOT a secrets store.** It *reads* secrets from configuration under `MindAttic:Vault:Security:*`, which the host fills (typically through MindAttic.Vault or Key Vault references); it never invents defaults and the running app never writes prod secrets (provisioning is a separate operator tool).
- **NOT WebAuthn/FIDO2 (yet).** Phishing-resistant hardware MFA is planned (AUTH-US-D4); until then AITM/Evilginx relay against TOTP is an **accepted residual** ([§6](#AUTH-§6)).
- **NOT the owner of UI markup.** Components take a small typed parameter set (`ReturnUrl`, `Error`, `Text`, `Sent`, `Token`); the host brands them with its own surrounding markup. No auth surface renders raw `MarkupString`/HTML.
- **NOT a hard-delete system.** Account removal is a reversible disable (org [HOUSE-LAW-2](../../MindAttic.HouseRules.md#HOUSE-LAW-2)).
- **NOT semver.** Whole-number major bumps only (org [HOUSE-LAW-1](../../MindAttic.HouseRules.md#HOUSE-LAW-1); [VERSIONING.md](VERSIONING.md)).

## The Laws (AUTH-§5)
This project **inherits all org-wide laws** in [`MindAttic.HouseRules.md`](../../MindAttic.HouseRules.md) by reference (do not restate). Most directly load-bearing here: [HOUSE-LAW-1](../../MindAttic.HouseRules.md#HOUSE-LAW-1) (whole-number versioning), [HOUSE-LAW-2](../../MindAttic.HouseRules.md#HOUSE-LAW-2) (soft-disable), [HOUSE-LAW-3](../../MindAttic.HouseRules.md#HOUSE-LAW-3) (Vault secrets), [HOUSE-LAW-7](../../MindAttic.HouseRules.md#HOUSE-LAW-7) (adopt this library), [HOUSE-LAW-8](../../MindAttic.HouseRules.md#HOUSE-LAW-8) (done = verified). The following are **project-specific** laws.

## Glossary (AUTH-§9)
- **PHC string** — self-describing password-hash encoding `$argon2id$v=19$m=…,t=…,p=…$salt$hash`; makes `NeedsRehash` deterministic.
- **Pepper** — a Vault-resident secret HMAC'd with the password before Argon2id; lives in a different trust domain than the DB.
- **Decoy verify** — a precomputed Argon2id verify run for absent/inactive users to keep timing uniform (anti-enumeration).
- **SecurityStamp** — per-user GUID rotated on password/MFA/role/disable/global-logout; revalidated every ~1 min to revoke live sessions.
- **Step-up / `amr`** — partial principal `amr=pwd` after password, exchanged for full `amr=[pwd,mfa]` only after MFA verify.
- **Timing floor** — minimum elapsed time (750ms + jitter) enforced on the login endpoint so fast/slow paths are indistinguishable.
- **Throttle scope** — `Account` or `Ip`; the unit a brute-force backoff counter is keyed on.
- **HIBP** — Have I Been Pwned k-anonymity breached-password check; fail-open online with a bundled offline fallback.
- **DP key ring** — ASP.NET Data Protection keys, persisted wherever the host's `ConfigureDataProtection` puts them (e.g. Azure Blob + Key Vault), app-name-isolated per consumer.
- **Trust boundary** — an app's isolated auth domain; a cookie/ticket valid in one is invalid in another.

## Status index (from docs/USER_STORIES.md)
- done: 19 | partial: 7 | planned: 6
