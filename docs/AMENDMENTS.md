---
codex: 1
project: MindAttic.Authentication
code: AUTH
layer: amendments
status: living
updated: 2026-06-07
---

# MindAttic.Authentication — Amendments (append-only; amendment wins over the bible)
> Never rewrite an amendment — supersede it with a new one. Beyond ~25, fold into [BIBLE.md](BIBLE.md) and start a new epoch (note the git tag); history stays in git.

## AUTH-A1 — Adopt the Codex documentation standard (supersedes —)
**What changed.** Installed the MindAttic Codex canon over the existing docs set: added [BIBLE.md](BIBLE.md) (L0), [USER_STORIES.md](USER_STORIES.md) (L2), this amendments log (L1), [docs/rfc/](rfc/), the generated [BIBLE.digest.md](BIBLE.digest.md), the `tools/codex.ps1` doctor/digest CLI, and the `.claude/` SessionStart digest hook.
**Why.** Give the library a single navigable source of truth with stable IDs and verified status, and inherit the org-wide [House Rules](../../MindAttic.HouseRules.md) by reference instead of restating them.
**Migration.** No application/source code changed. The pre-existing prose docs were **kept and superseded as detail references**, not deleted: [`SECURITY_SPEC.md`](SECURITY_SPEC.md) remains the authoritative design rationale that [BIBLE §4–§6](BIBLE.md#AUTH-§4) navigates; [`API.md`](API.md), [`INTEGRATION.md`](INTEGRATION.md), [`CONFIGURATION.md`](CONFIGURATION.md), [`OPERATIONS.md`](OPERATIONS.md), [`VERSIONING.md`](VERSIONING.md), [`ADOPTION_PLAYBOOK.md`](ADOPTION_PLAYBOOK.md) stay as-is. README ✅/🔨/📋 markers were reconciled to test evidence in USER_STORIES (unproven claims downgraded to 🟡/⬜); the README text itself is unchanged. No L5 `docs/data/` was created — this is a `library` domain with no tabular canon to extract.

## AUTH-A2 — Codex full-sync 2026-06-07: reconcile §4 architecture canon to disk (supersedes AUTH-A1 §4 coverage)
**What changed.** First full-sync pass reconciling BIBLE §4 against the working tree (build: 0 warnings, 0 errors; tests: 184/184 green, NUnit 4, net10.0).
- **§4.1**: Added `MaClaims.cs` to the layout note (root-level canonical constants — claim types, roles, policies, scheme names — not inside any subfolder).
- **§4.3 Web seam**: Added three files that exist on disk but were absent from canon: `Web/CookieValidation.cs` (idle-timeout + SecurityStamp recheck on the HTTP path, complements the Blazor-circuit revalidator), `Web/IMaClaimsAugmentor.cs` (app-implemented hook to inject extra claims at sign-in), `Web/DevAuthBypass.cs` (`#if MA_DEV_AUTH` — Debug-only dev credential replay; compiled out of Release entirely; triple-gated at runtime by flag + IsDevelopment + loopback).
- **README Build status**: Updated Components listing to match disk — `MaForgotPassword.razor` and `MaResetPassword.razor` are present and compile (listed as done); `MaAccount` (previously shown as 📋 planned) does not exist on disk and was removed.
**Why.** Docs-follow-code: the §4 architecture canon must cite what is actually present, not what was planned at a prior point in time.
**Migration.** No application/source code changed. `docs/BIBLE.digest.md` regenerated.
