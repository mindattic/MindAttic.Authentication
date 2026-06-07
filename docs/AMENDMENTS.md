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
