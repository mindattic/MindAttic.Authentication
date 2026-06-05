# Versioning policy

MindAttic.Authentication follows the **MindAttic ecosystem whole-number / major-only** rule.

- The package & assembly version is a **single increasing major**: `1.0.0`, then `2.0.0`, then `3.0.0`, …
  **Minor and patch are always `0`.** There is no `1.1.0`, `1.0.1`, or SemVer-style minor/patch.
- `1.0.0` is the version for **all of v1 development** — it is not re-numbered as features land during v1.
  The next *release* after v1 is `2.0.0`.
- Consumers exact-pin: `<PackageReference Include="MindAttic.Authentication" Version="1.0.0" />`.

## What a major bump means here

The library's frozen behaviors (see [`API.md`](API.md) and [`SECURITY_SPEC.md`](SECURITY_SPEC.md)) — the
PHC hash format, the cookie/claim shape, the `auth` EF schema, the public service/option contracts, and
the security control set — are stable within a major. A change to any of them ships as the **next major**.

- **`auth` schema:** `AuthModel.ModelFingerprint` (e.g. `"auth-v1"`) tracks the schema generation; a host
  asserts its applied migration matches. A schema change ⇒ new fingerprint ⇒ new major + a migration.
- **SDK/contract:** additive, source-compatible changes are still delivered as a new major release (no
  minor channel exists); breaking changes obviously are.
- **Crypto agility is in-band, not via version:** Argon2 parameters and the pepper are upgraded at runtime
  (config + `NeedsRehash` + pepper rotation), so raising work factors or rotating the pepper does **not**
  require a library version bump.

## Internal vs public surface

Types under `MindAttic.Authentication.Internal` (`AuthKeys`, `UrlSafety`, `TimingFloor`) are implementation
details and not covered by the cross-major stability promise. Everything else in [`API.md`](API.md) is.
