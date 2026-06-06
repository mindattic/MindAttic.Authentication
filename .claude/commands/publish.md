---
description: Release MindAttic.Authentication and propagate the new version to all subscribers (Ideas, StreetSamurai, Tutor)
argument-hint: "[version]  (optional; defaults to next whole-number major)"
allowed-tools: Read, Edit, Grep, Glob, Bash(dotnet pack:*), Bash(dotnet build:*), Bash(dotnet restore:*), Bash(dotnet nuget locals:*)
---

You are publishing a new release of **MindAttic.Authentication** and propagating it to every
downstream subscriber. The library is consumed as a NuGet `PackageReference` (not a project
reference), so nothing propagates automatically — you must bump, pack, and update each
subscriber explicitly. See this repo's `CLAUDE.md` for the canonical rule.

## Target version

- If the user passed an argument (`$ARGUMENTS`), use it as the new version.
- Otherwise read `<Version>` in `src/MindAttic.Authentication/MindAttic.Authentication.csproj`
  and increment the **major** by one. **Whole-number major bumps only** —
  `1.0.0` → `2.0.0` → `3.0.0`. Minor and patch are always `0`. Never do a semver minor/patch
  bump.

## Steps

1. **Bump** `<Version>` in `src/MindAttic.Authentication/MindAttic.Authentication.csproj` to
   the target version.

2. **Pack** into the local feed:
   `dotnet pack -c Release -o C:\LocalNuGet`
   (feed `LocalNuGet` = `C:\LocalNuGet`, per `nuget.config`). Confirm
   `MindAttic.Authentication.<version>.nupkg` was produced. If the pack fails, STOP and report —
   do not touch subscribers.

3. **Propagate** — update the `MindAttic.Authentication` `PackageReference Version` to the new
   version in ALL of these (re-grep in case a subscriber added a project; this list is the
   known minimum, not a cap):
   - `D:\Projects\MindAttic\MindAttic.Ideas\src\MindAttic.Ideas.Web\MindAttic.Ideas.Web.csproj`
   - `D:\Projects\MindAttic\MindAttic.Ideas\src\MindAttic.Ideas.Core\MindAttic.Ideas.Core.csproj`
   - `D:\Projects\MindAttic\StreetSamurai\v3\StreetSamurai.Core\StreetSamurai.Core.csproj`
   - `D:\Projects\MindAttic\Tutor\Tutor.Core\Tutor.Core.csproj`

   Before editing, run a grep for `MindAttic.Authentication` across all subscriber repos to
   verify no new reference points exist beyond this list.

4. **Verify** each subscriber resolves and builds against the new package. If the old version
   resolves from cache, clear it: `dotnet nuget locals global-packages --clear` (or remove the
   `mindattic.authentication` cache folder), then restore/build again.

5. **Report** a summary table: the new version, pack result, each subscriber's reference update,
   and each subscriber's build result (pass/fail). If any subscriber fails to build, flag it
   prominently — propagation is not complete until all subscribers build green.

Do not commit or push unless the user explicitly asks.
