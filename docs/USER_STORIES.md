---
codex: 1
project: MindAttic.Authentication
code: AUTH
layer: stories
status: living
updated: 2026-06-07
---

# MindAttic.Authentication — User Stories
> ✅ done (shipped & tested) · 🟡 partial · ⬜ planned · 🗑️ cut. Every ✅ cites its verifying test.
> Personas: **U** = end user of a consuming app · **Admin** = elevated operator · **Host** = the app developer adopting the library · **Op** = the secrets/deployment operator.
> Status reflects the 2026-06-07 run: build clean, 184/184 tests green ([BIBLE §6](BIBLE.md#AUTH-§6)).

## Epic A — Password storage
- **AUTH-US-A1 ✅** As a Host, I can store passwords as Argon2id+pepper so a DB-only breach yields nothing crackable. *Given a password, When hashed, Then the result is a canonical argon2id PHC string with a random salt and verifies back.* *(verified by `Argon2idPasswordHasherTests.Hash_ThenVerify_Succeeds_AndDoesNotNeedRehashAtCurrentParams`, `Argon2idPasswordHasherTests.Hash_UsesRandomSalt_SoSamePasswordHashesDiffer`.)*
- **AUTH-US-A2 ✅** As a Host, I get a wrong password rejected and a self-describing hash so work factors can rise over time. *(verified by `Argon2idPasswordHasherTests.Verify_WrongPassword_Fails`, `PhcArgon2Tests.Encode_ProducesCanonicalArgon2idString`, `PhcArgon2Tests.RoundTrip_PreservesAllFields`.)*
- **AUTH-US-A3 ✅** As a Host, I get fail-closed crypto floors so a misconfigured weak Argon2 setting cannot start. *Given params below the OWASP floor, When validated at startup, Then it throws.* *(verified by `AuthCryptoOptionsTests.BelowMemoryFloor_Throws`, `AuthCryptoOptionsTests.Defaults_PassValidation`, `AuthCryptoOptionsTests.AtExactFloors_PassesValidation`.)*

## Epic B — Secrets (Vault contract)
- **AUTH-US-B1 ✅** As a Host, a required secret that is missing throws rather than silently becoming empty, so auth fails closed. *(verified by `ConfigAuthSecretsTests.GetRequired_Missing_Throws`, `ConfigAuthSecretsTests.GetRequired_Blank_Throws_NeverCoercesToEmpty`.)*
- **AUTH-US-B2 ✅** As a Host, a present secret resolves and an optional absent secret returns null (not throw). *(verified by `ConfigAuthSecretsTests.GetRequired_Present_ReturnsValue`, `ConfigAuthSecretsTests.GetOptional_Missing_ReturnsNull`, `ConfigAuthSecretsTests.GetOptional_Present_ReturnsValue`.)*

## Epic C — Brute-force, lockout & enumeration
- **AUTH-US-C1 ✅** As a Host, repeated failures trigger persistent exponential backoff matching the spec curve, surviving restart. *(verified by `AccountLockoutServiceTests.BackoffFor_MatchesSpecCurve`, `AccountLockoutServiceTests.RecordFailure_BelowThreshold_StaysAllowed`.)*
- **AUTH-US-C2 ✅** As a U, an unknown key is allowed through to the (decoy) verify so failures don't reveal account existence. *(verified by `AccountLockoutServiceTests.Check_OnUnknownKey_IsAllowed`.)*
- **AUTH-US-C3 ✅** As a Host, login timing is floored so fast and slow paths are indistinguishable. *Given fast work, When the floor is enforced, Then the call waits to the floor; Given slow work, Then it does not block further.* *(verified by `TimingFloorTests.EnforceAsync_WaitsUntilFloorWhenWorkWasFast`, `TimingFloorTests.EnforceAsync_DoesNotBlockWhenWorkAlreadyExceededFloor`, `TimingFloorTests.Defaults_AreSpecValues`.)*
- **AUTH-US-C4 ✅** As a Host, account keys are NFKC-normalized + lowercased so equivalent identifiers collapse to one throttle/lookup key. *(verified by `AuthKeysTests.NormalizeAccount_LowercasesAndTrims`, `AuthKeysTests.NormalizeAccount_IsNfkcSoCompatibilityFormsCollapse`.)*
- **AUTH-US-C5 ✅** As an Admin reviewing logs, every attempt is audited with a hashed account key and sanitized user-agent (no raw key, no log injection). *(verified by `AuthAuditWriterTests.Write_HashesAccountKey_NeverStoresRaw`, `AuthAuditWriterTests.Write_SanitizesUserAgent_StrippingNewlinesAndNul`.)*

## Epic D — MFA (TOTP + recovery)
- **AUTH-US-D1 ✅** As a U, my TOTP code validates per RFC 6238 within the ±1 window. *(verified by `TotpServiceTests.Validate_MatchesRfc6238TestVectors`, `TotpServiceTests.Validate_AcceptsCodeWithinWindow`.)*
- **AUTH-US-D2 ✅** As a U, a replayed TOTP step is rejected so a captured code can't be reused. *(verified by `TotpServiceTests.Validate_RejectsReplayedStep`.)*
- **AUTH-US-D3 🟡** As a U, I can enroll MFA (verify-before-enable) and receive single-use recovery codes. *`MfaEnrollmentService` is implemented and compiles; not yet covered by a dedicated unit test.* (downgraded to 🟡 — no test names it.)

## Epic E — Password policy, change & reset
- **AUTH-US-E1 ✅** As a U, my password is rejected if too short/too long/blank per NIST policy. *(verified by `PasswordPolicyTests.TooShort_IsRejected`, `PasswordPolicyTests.TooLong_IsRejected`, `PasswordPolicyTests.Null_IsRejected`.)*
- **AUTH-US-E2 ✅** As a U requesting a reset, an unknown user creates no token but still audits (enumeration-safe), and a known user gets a hashed token + emailed link. *(verified by `PasswordResetServiceTests.Request_UnknownUser_CreatesNoToken_ButStillAudits`, `PasswordResetServiceTests.Request_KnownUser_CreatesHashedToken_AndEmailsLink`, `PasswordResetServiceTests.Request_UserWithoutEmail_DoesNotCreateTokenOrEmail`.)*
- **AUTH-US-E3 🟡** As a U, change-password requires my current password + fresh reauth and rotates my stamp. *`PasswordChangeService` is implemented and compiles; not yet covered by a dedicated unit test.*

## Epic F — Account administration
- **AUTH-US-F1 ✅** As an Admin, creating a user hashes the password (never stored raw) and rejects duplicate/blank usernames. *(verified by `UserAdminServiceTests.Create_HashesPassword_AndNeverStoresRaw`, `UserAdminServiceTests.Create_DuplicateUserName_Fails`, `UserAdminServiceTests.Create_BlankUserName_Fails`.)*
- **AUTH-US-F2 ✅** As a Host, return URLs are open-redirect-safe (same-site relative accepted; off-site/scheme/null rejected). *(verified by `UrlSafetyTests.IsLocalUrl_AcceptsSameSiteRelativePaths`, `UrlSafetyTests.IsLocalUrl_RejectsOffSiteAndSchemeUrls`, `UrlSafetyTests.IsLocalUrl_RejectsNullAndEmpty`.)*

## Epic G — Login pipeline & web wiring
- **AUTH-US-G1 🟡** As a U, I can log in → step up through MFA → receive a fresh session cookie. *`AuthenticationService.LoginAsync`/`ConfirmMfaAsync` are implemented and compile; covered indirectly by lockout/timing/TOTP units but no end-to-end pipeline test yet.*
- **AUTH-US-G2 🟡** As a Host, `AddMindAtticAuthentication` / `UseMindAtticAuthentication` / `MapMindAtticAuthEndpoints` wire cookie + MFA-pending schemes, per-app DP isolation, and ordered fail-closed middleware. *Implemented and compiling; no integration test in the suite yet.*
- **AUTH-US-G3 🟡** As an Admin, a revoked stamp logs me out of a live circuit within ≤1 min. *`MaRevalidatingAuthenticationStateProvider` implemented; no timing/integration test yet.*
- **AUTH-US-G4 🟡** As a Host, first-run bootstrap seeds an admin only with a Vault bootstrap token, race-safe, no defaults. *`AuthBootstrapper` implemented; no concurrency test yet.*

## Priority backlog
Dependency-ordered toward the headline goal (one engine adopted by all three apps):
1. ⬜ **AUTH-US-E4** — Wire email-delivered reset end-to-end through `IAuthEmailSender`/MindAttic.Psst (consume token → rehash → no auto-login). (depends on E2)
2. ⬜ **AUTH-US-G5** — Add the fail-closed `IStartupFilter` integration test asserting middleware order. (hardens G2)
3. ⬜ **AUTH-US-F3** — Provisioning CLI emitting CSPRNG pepper/KEK/reset-key (see [RFC 0001](rfc/0001-provisioning-cli.md)). (depends on B1/B2)
4. ⬜ **AUTH-US-F4** — Signed, deterministic NuGet pack with committed `packages.lock.json`.
5. ⬜ **AUTH-US-G6** — Adopt into **StreetSamurai**, then **Ideas** (+ Ideas Admin Users UI), then **Tutor**; each subscriber references the version and builds ([AUTH-LAW-7](BIBLE.md#AUTH-LAW-7)).
6. ⬜ **AUTH-US-D4** — WebAuthn/FIDO2 (v2, additive) to close the accepted AITM residual.

### Audit log
No story has had its original ask changed or narrowed since inception. This file is the first formal capture of the stories (previously implicit in `README.md` and `docs/SECURITY_SPEC.md`); the README's ✅/🔨/📋 markers were reconciled to the verified test evidence above — anything the README marked ✅ that lacks an isolated unit test was downgraded here to 🟡 (Epics D3, E3, G1–G4) per [AUTH-§8](BIBLE.md#AUTH-§8). The original README spec remains verbatim in `README.md` (original spec — audit log).
