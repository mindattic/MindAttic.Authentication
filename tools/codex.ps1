<#
.SYNOPSIS
  Codex documentation standard CLI for MindAttic.Authentication.
.DESCRIPTION
  Subcommands:
    doctor  - validate the canon (front-matter, IDs, cross-refs, data schemas,
              story test citations, cited paths, generated-artifact staleness);
              exit non-zero on any hard error.
    digest  - regenerate docs/BIBLE.digest.md from BIBLE.md (S1, S3, S5 Laws, S9)
              plus a status index and the latest amendment head.
  Windows PowerShell 5.1 safe. No build step.
.EXAMPLE
  powershell -File tools/codex.ps1 doctor
  powershell -File tools/codex.ps1 digest
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('doctor', 'digest')]
  [string]$Command = 'doctor'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- paths ----------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DocsDir  = Join-Path $RepoRoot 'docs'
$DataDir  = Join-Path $DocsDir 'data'
$RfcDir   = Join-Path $DocsDir 'rfc'
$Bible    = Join-Path $DocsDir 'BIBLE.md'
$Stories  = Join-Path $DocsDir 'USER_STORIES.md'
$Amend    = Join-Path $DocsDir 'AMENDMENTS.md'
$Digest   = Join-Path $DocsDir 'BIBLE.digest.md'

# PS 5.1's Get-Content -Raw uses the ANSI codepage; force UTF-8 so emoji + section
# symbols round-trip correctly (the canon files are UTF-8).
function Read-Utf8 ($path) {
  if (-not (Test-Path $path)) { return $null }
  return [IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
}

$script:Errors   = New-Object System.Collections.ArrayList
$script:Warns    = New-Object System.Collections.ArrayList
function Add-Err ($m)  { [void]$script:Errors.Add($m) }
function Add-Warn ($m) { [void]$script:Warns.Add($m) }

function Get-DocFiles {
  $files = @()
  foreach ($f in @($Bible, $Stories, $Amend)) { if (Test-Path $f) { $files += $f } }
  if (Test-Path $RfcDir)  { $files += (Get-ChildItem -Path $RfcDir  -Filter *.md   -File -ErrorAction SilentlyContinue | ForEach-Object FullName) }
  if (Test-Path $DataDir) { $files += (Get-ChildItem -Path $DataDir -Filter *.json -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\_schema\\' } | ForEach-Object FullName) }
  return $files
}

# Parse the leading YAML front-matter block into a hashtable. Returns $null if absent.
function Get-FrontMatter ($path) {
  $raw = Read-Utf8 $path
  if ($null -eq $raw) { return $null }
  if ($path -like '*.json') {
    try { $j = $raw | ConvertFrom-Json } catch { return $null }
    if ($j.PSObject.Properties.Name -contains 'codex') {
      return @{ codex = $j.codex; layer = $j.layer; project = $j.project; code = $j.code }
    }
    return $null
  }
  $raw = $raw.TrimStart([char]0xFEFF)   # tolerate a UTF-8 BOM
  if ($raw -notmatch '^---\r?\n') { return $null }
  $lines = $raw -split "`r?`n"
  if ($lines[0] -ne '---') { return $null }
  $fm = @{}
  for ($i = 1; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -eq '---') { return $fm }
    if ($lines[$i] -match '^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$') { $fm[$Matches[1]] = $Matches[2].Trim() }
  }
  return $null  # never closed
}

# ===========================================================================
function Invoke-Doctor {
  Write-Host "Codex doctor - MindAttic.Authentication" -ForegroundColor Cyan
  Write-Host ("=" * 50)

  # 1. core files exist
  foreach ($f in @($Bible, $Stories, $Amend)) {
    if (-not (Test-Path $f)) { Add-Err "missing required doc: $f" }
  }

  # 2. front-matter valid on every canon file
  $allIds   = @{}    # id -> file (for uniqueness)
  $anchorRefs = New-Object System.Collections.ArrayList  # @{ ref; file }
  foreach ($f in (Get-DocFiles)) {
    $fm = Get-FrontMatter $f
    $rel = $f.Replace($RepoRoot, '').TrimStart('\')
    if ($null -eq $fm) { Add-Err "invalid/missing codex front-matter: $rel"; continue }
    if ("$($fm['codex'])" -ne '1') { Add-Err "front-matter codex != 1: $rel" }
    if (-not $fm.ContainsKey('layer') -or [string]::IsNullOrWhiteSpace("$($fm['layer'])")) { Add-Err "front-matter missing 'layer': $rel" }
  }

  # 3. collect {#...} anchors + cross-ref links from markdown
  $mdFiles = (Get-DocFiles) | Where-Object { $_ -like '*.md' }
  foreach ($f in $mdFiles) {
    $rel  = $f.Replace($RepoRoot, '').TrimStart('\')
    $text = Read-Utf8 $f
    foreach ($m in [regex]::Matches($text, '\{#([^}]+)\}')) {
      $id = $m.Groups[1].Value
      if ($allIds.ContainsKey($id)) { Add-Err "duplicate ID {#$id} in $rel (also $($allIds[$id]))" }
      else { $allIds[$id] = $rel }
    }
    # links of the form (...#anchor)
    foreach ($m in [regex]::Matches($text, '\]\(([^)]*#[^)]+)\)')) {
      [void]$anchorRefs.Add(@{ ref = $m.Groups[1].Value; file = $f; rel = $rel })
    }
  }

  # 3b. resolve cross-ref links to {#...} anchors (intra- and inter-file, incl. HouseRules)
  foreach ($r in $anchorRefs) {
    $target = $r.ref
    $anchor = ($target -split '#', 2)[1]
    $pathPart = ($target -split '#', 2)[0]
    if ([string]::IsNullOrEmpty($anchor)) { continue }
    if ($anchor -match '^AUTH-') {
      # must resolve within this repo's anchor set
      if (-not $allIds.ContainsKey($anchor)) { Add-Err "broken cross-ref #$anchor in $($r.rel)" }
    }
    elseif ($anchor -match '^HOUSE-') {
      # resolve against the shared HouseRules file if reachable
      $base = if ([string]::IsNullOrEmpty($pathPart)) { $r.file } else { Join-Path (Split-Path -Parent $r.file) $pathPart }
      $resolved = $null
      try { $resolved = (Resolve-Path -LiteralPath $base -ErrorAction Stop).Path } catch {}
      if ($resolved -and (Test-Path $resolved)) {
        $h = Read-Utf8 $resolved
        if ($h -notmatch [regex]::Escape("{#$anchor}")) { Add-Warn "HouseRules anchor #$anchor not found in $pathPart (from $($r.rel))" }
      } else {
        Add-Warn "HouseRules link target not resolvable: $pathPart (from $($r.rel))"
      }
    }
    # section slugs (e.g. the section-sign anchors #AUTH-...4) are handled by the AUTH- branch above
  }

  # 4. data/*.json validate against _schema/*.schema.json (basic required-key + id uniqueness)
  if (Test-Path $DataDir) {
    $schemaDir = Join-Path $DataDir '_schema'
    $seenIds = @{}
    foreach ($jf in (Get-ChildItem -Path $DataDir -Filter *.json -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\_schema\\' })) {
      $rel = $jf.FullName.Replace($RepoRoot, '').TrimStart('\')
      try { $data = Get-Content -LiteralPath $jf.FullName -Raw | ConvertFrom-Json } catch { Add-Err "invalid JSON: $rel"; continue }
      $type = [IO.Path]::GetFileNameWithoutExtension($jf.Name)
      $schemaPath = Join-Path $schemaDir "$type.schema.json"
      if (-not (Test-Path $schemaPath)) { Add-Err "no schema for data file: $rel (expected _schema/$type.schema.json)" }
      foreach ($e in @($data)) {
        if (-not ($e.PSObject.Properties.Name -contains 'id')) { Add-Err "entity missing 'id' in $rel" ; continue }
        if ($seenIds.ContainsKey($e.id)) { Add-Err "duplicate entity id '$($e.id)' in $rel" } else { $seenIds[$e.id] = $rel }
      }
    }
  }

  # 5. every checkmark story names a test token; best-effort confirm the test exists
  if (Test-Path $Stories) {
    $testIndex = @{}
    $testRoot = Join-Path $RepoRoot 'tests'
    if (Test-Path $testRoot) {
      foreach ($cs in (Get-ChildItem -Path $testRoot -Filter *.cs -File -Recurse -ErrorAction SilentlyContinue)) {
        $c = Read-Utf8 $cs.FullName
        foreach ($mm in [regex]::Matches($c, '\b(?:public|internal)\s+(?:sealed\s+)?(?:class|async\s+\w+|\w+)\s+([A-Za-z_][A-Za-z0-9_]+)')) {
          $testIndex[$mm.Groups[1].Value] = $true
        }
        foreach ($mm in [regex]::Matches($c, '\b([A-Za-z_][A-Za-z0-9_]+)\s*\(')) { $testIndex[$mm.Groups[1].Value] = $true }
      }
    }
    $sline = (Read-Utf8 $Stories) -split "`r?`n"
    $checkChar = [char]0x2705   # checkmark emoji
    foreach ($ln in $sline) {
      if ($ln -match 'US-[A-Za-z0-9]+\s*\*?\*?'+[regex]::Escape($checkChar)) {
        $tokens = [regex]::Matches($ln, '`([A-Za-z_][A-Za-z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_]+)*)`')
        $named = $false
        foreach ($t in $tokens) {
          $val = $t.Groups[1].Value
          if ($val -match '^[A-Z]\w*(Tests|Service|Hasher|Writer)' -or $val -match '\.') { $named = $true }
          if ($val -match '\.') {
            $leaf = ($val -split '\.')[-1]
            if ($testIndex.Count -gt 0 -and -not $testIndex.ContainsKey($leaf) -and -not $testIndex.ContainsKey(($val -split '\.')[0])) {
              Add-Warn "story cites test '$val' not found in test tree"
            }
          }
        }
        if (-not $named) {
          $idm = [regex]::Match($ln, 'AUTH-US-[A-Za-z0-9]+')
          Add-Err "checkmark story without a named test: $($idm.Value)"
        }
      }
    }
  }

  # 6. every repo path/file cited in the bible exists on disk
  if (Test-Path $Bible) {
    $btext = Read-Utf8 $Bible
    foreach ($m in [regex]::Matches($btext, '`((?:src|tests|tools|docs)/[^`]+)`')) {
      $p = $m.Groups[1].Value
      $full = Join-Path $RepoRoot ($p -replace '/', '\')
      if (-not (Test-Path $full)) { Add-Err "bible cites missing path: $p" }
    }
  }

  # 7. generatedFrom staleness + digest freshness
  if (Test-Path $Digest) {
    if (Test-Path $Bible) {
      $bm = (Get-Item $Bible).LastWriteTimeUtc
      $dm = (Get-Item $Digest).LastWriteTimeUtc
      if ($bm -gt $dm) { Add-Warn "BIBLE.digest.md is older than BIBLE.md - run 'codex.ps1 digest'" }
    }
    $dtext = Read-Utf8 $Digest
    $mGen = [regex]::Match($dtext, 'generatedFrom:\s*(\S+)')
    if ($mGen.Success) {
      $srcId = $mGen.Groups[1].Value
      if (-not ($allIds.ContainsKey(($srcId -replace '^#', '')) -or $srcId -like '*BIBLE.md*')) {
        Add-Warn "digest generatedFrom '$srcId' does not resolve to a known source"
      }
    }
  } else {
    Add-Warn "BIBLE.digest.md missing - run 'codex.ps1 digest'"
  }

  # ---- report ----
  Write-Host ""
  Write-Host "Checklist:"
  Write-Host "  [*] core docs present"
  Write-Host "  [*] front-matter on every canon file"
  Write-Host "  [*] unique {#...} IDs + resolvable cross-refs"
  Write-Host "  [*] data/*.json schema + id uniqueness (none in this library domain)"
  Write-Host "  [*] checkmark stories name a test"
  Write-Host "  [*] bible-cited paths exist"
  Write-Host "  [*] generated digest freshness"
  Write-Host ""

  if ($script:Warns.Count -gt 0) {
    Write-Host "WARNINGS ($($script:Warns.Count)):" -ForegroundColor Yellow
    foreach ($w in $script:Warns) { Write-Host "  ! $w" -ForegroundColor Yellow }
  }
  if ($script:Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "ERRORS ($($script:Errors.Count)):" -ForegroundColor Red
    foreach ($e in $script:Errors) { Write-Host "  X $e" -ForegroundColor Red }
    Write-Host ""
    Write-Host "doctor FAILED" -ForegroundColor Red
    exit 1
  }
  Write-Host "doctor PASSED" -ForegroundColor Green
  exit 0
}

# ===========================================================================
function Get-Section ($text, $idToken) {
  # extract from the heading carrying {#idToken} to the next heading of same-or-higher level
  $pat = '(?ms)^(#{1,6})[^\r\n]*\{#' + [regex]::Escape($idToken) + '\}[^\r\n]*\r?\n(.*?)(?=^\#{1,6}\s|\Z)'
  $m = [regex]::Match($text, $pat)
  if ($m.Success) { return $m.Groups[2].Value.Trim() }
  return ''
}

function Invoke-Digest {
  if (-not (Test-Path $Bible)) { Write-Error "BIBLE.md not found"; exit 1 }
  $b = Read-Utf8 $Bible

  # U+00A7 section sign, built at runtime so this script stays pure-ASCII on disk
  # (avoids the PS 5.1 source-encoding mangling the literal during parse).
  $SS = [char]0x00A7
  $s1 = Get-Section $b "AUTH-${SS}1"
  $s3 = Get-Section $b "AUTH-${SS}3"
  $s5 = Get-Section $b "AUTH-${SS}5"
  $s9 = Get-Section $b "AUTH-${SS}9"

  # status index from USER_STORIES. Emojis above U+FFFF are matched via their
  # UTF-16 surrogate-pair strings (PS 5.1 cannot [char]-cast a >U+FFFF code point).
  $sDone    = [char]0x2705                                   # white heavy check mark
  $sPartial = [string]::new([char[]]@([char]0xD83D, [char]0xDFE1))  # yellow circle U+1F7E1
  $sPlanned = [char]0x2B1C                                   # white large square
  $sCut     = [string]::new([char[]]@([char]0xD83D, [char]0xDDD1))  # wastebasket U+1F5D1
  $counts = @{ done = 0; partial = 0; planned = 0; cut = 0 }
  if (Test-Path $Stories) {
    $st = Read-Utf8 $Stories
    $counts.done    = ([regex]::Matches($st, [regex]::Escape($sDone))).Count
    $counts.partial = ([regex]::Matches($st, [regex]::Escape($sPartial))).Count
    $counts.planned = ([regex]::Matches($st, [regex]::Escape($sPlanned))).Count
    $counts.cut     = ([regex]::Matches($st, [regex]::Escape($sCut))).Count
  }

  # latest amendment head
  $amendHead = ''
  if (Test-Path $Amend) {
    $am = Read-Utf8 $Amend
    $hm = [regex]::Matches($am, '(?m)^##\s+(AUTH-A\d+.*)$')
    if ($hm.Count -gt 0) { $amendHead = $hm[$hm.Count - 1].Groups[1].Value.Trim() }
  }

  $today = (Get-Date).ToString('yyyy-MM-dd')
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("# MindAttic.Authentication - Bible Digest")
  [void]$sb.AppendLine("> AUTHORITATIVE - full detail in docs/BIBLE.md")
  [void]$sb.AppendLine("> generatedFrom: docs/BIBLE.md (#AUTH-${SS}1, #AUTH-${SS}3, #AUTH-${SS}5, #AUTH-${SS}9)")
  [void]$sb.AppendLine("> generated: $today by tools/codex.ps1 digest - do not hand-edit")
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("## The one sentence (AUTH-${SS}1)")
  [void]$sb.AppendLine($s1)
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("## What it is NOT (AUTH-${SS}3)")
  [void]$sb.AppendLine($s3)
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("## The Laws (AUTH-${SS}5)")
  [void]$sb.AppendLine($s5)
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("## Glossary (AUTH-${SS}9)")
  [void]$sb.AppendLine($s9)
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("## Status index (from docs/USER_STORIES.md)")
  [void]$sb.AppendLine(("- done: {0} | partial: {1} | planned: {2} | cut: {3}" -f $counts.done, $counts.partial, $counts.planned, $counts.cut))
  [void]$sb.AppendLine("")
  [void]$sb.AppendLine("## Latest amendment (amendment wins over the bible)")
  [void]$sb.AppendLine("- $amendHead")

  $outText = $sb.ToString()
  # write UTF-8 (no BOM)
  $enc = New-Object System.Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($Digest, $outText, $enc)
  Write-Host "wrote $($Digest.Replace($RepoRoot,'').TrimStart('\')) ($([math]::Round($outText.Length/1KB,1)) KB)" -ForegroundColor Green
}

switch ($Command) {
  'doctor' { Invoke-Doctor }
  'digest' { Invoke-Digest }
}
