# MindAttic.Authentication — project instructions

## Codex — canonical documentation (read first)

This repo uses the **MindAttic Codex** standard. The single source of truth lives in `docs/`:

- `docs/BIBLE.md` — L0 source of truth (what it IS / is NOT / Architecture / **Laws** / verified state). Stable IDs like `{#AUTH-§5}`, `{#AUTH-LAW-1}`.
- `docs/AMENDMENTS.md` — L1 append-only change log; **an amendment wins over the bible**.
- `docs/USER_STORIES.md` — L2 stories; every `✅` names its verifying test.
- `docs/rfc/` — design notes that graduate into L0+L2.
- `docs/BIBLE.digest.md` — **generated**; never hand-edit (run the tool).
- `docs/SECURITY_SPEC.md` and the other prose docs remain the exhaustive detail the bible navigates.

Org-wide laws are inherited by reference from `../MindAttic.HouseRules.md` (do not restate them).

**Working rules:** put a fact in exactly one layer and link to it by ID; keep `✅` honest (a build/test must prove it, per `#AUTH-§8`); after editing `docs/BIBLE.md` run `powershell -File tools/codex.ps1 digest` then `powershell -File tools/codex.ps1 doctor` — **doctor must pass**. A SessionStart hook (`.claude/hooks/inject-digest.ps1`) injects the digest as authoritative context.

## Downstream propagation (MANDATORY)

This library is consumed as a **NuGet `PackageReference`** (not a project reference) by
three subscribers. **Every change shipped from here MUST be propagated to all of them, at
every reference point.** A change is not "done" until all subscribers reference the new
version and build.

### Subscribers and their reference points

| Subscriber       | Project files referencing `MindAttic.Authentication`                                   |
|------------------|-----------------------------------------------------------------------------------------|
| **Ideas**        | `MindAttic.Ideas/src/MindAttic.Ideas.Web/MindAttic.Ideas.Web.csproj`                    |
|                  | `MindAttic.Ideas/src/MindAttic.Ideas.Core/MindAttic.Ideas.Core.csproj`                  |
| **StreetSamurai**| `StreetSamurai/v3/StreetSamurai.Core/StreetSamurai.Core.csproj`                         |
| **Tutor**        | `Tutor/Tutor.Core/Tutor.Core.csproj`                                                    |

All subscriber repos live under `D:\Projects\MindAttic\`.

### Release + propagation procedure

1. Bump `<Version>` in `src/MindAttic.Authentication/MindAttic.Authentication.csproj`.
   **Whole-number major bumps only** — `1.0.0` → `2.0.0` → `3.0.0` (never minor/patch).
2. Pack into the local feed: `dotnet pack -c Release -o C:\LocalNuGet`
   (feed `LocalNuGet` = `C:\LocalNuGet`, configured in `nuget.config`).
3. Update the `MindAttic.Authentication` `PackageReference Version` to the new version in
   **all five** csproj files in the table above.
4. Restore/build each subscriber to confirm it resolves and compiles
   (clear the NuGet cache for this package if the new version doesn't resolve).

Missing any reference point leaves a subscriber pinned to a stale package — treat the list
as exhaustive and re-check it whenever a subscriber adds a project.
