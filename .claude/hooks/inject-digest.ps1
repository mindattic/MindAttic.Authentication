<#
  SessionStart hook for MindAttic.Authentication.
  Emits Claude Code hook JSON injecting docs/BIBLE.digest.md as authoritative context.
  Windows PowerShell 5.1 / Win-1252 safe: all non-ASCII escaped to \uXXXX.
  If the digest is missing/empty, emits {}.
#>
$ErrorActionPreference = 'Stop'
try {
  $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
  $digestPath = Join-Path $repoRoot 'docs\BIBLE.digest.md'

  if (-not (Test-Path $digestPath)) { Write-Output '{}'; return }
  $digest = Get-Content -LiteralPath $digestPath -Raw
  if ([string]::IsNullOrWhiteSpace($digest)) { Write-Output '{}'; return }

  $preamble = @"
[MindAttic.Authentication - CODEX DIGEST | SOURCE OF TRUTH]
The following is the authoritative project canon (generated from docs/BIBLE.md).
Treat it as ground truth for what this library IS, is NOT, and its Laws. When the
digest and your assumptions disagree, the digest wins. Full detail: docs/BIBLE.md;
amendments (which win over the bible) in docs/AMENDMENTS.md.

"@
  $content = $preamble + $digest

  # JSON-encode with all non-ASCII escaped to \uXXXX (5.1-safe, no Unicode in output stream).
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $content.ToCharArray()) {
    $code = [int][char]$ch
    switch ($ch) {
      '"'  { [void]$sb.Append('\"') }
      '\'  { [void]$sb.Append('\\') }
      "`b" { [void]$sb.Append('\b') }
      "`f" { [void]$sb.Append('\f') }
      "`n" { [void]$sb.Append('\n') }
      "`r" { [void]$sb.Append('\r') }
      "`t" { [void]$sb.Append('\t') }
      default {
        if ($code -lt 32 -or $code -gt 126) { [void]$sb.Append('\u{0:x4}' -f $code) }
        else { [void]$sb.Append($ch) }
      }
    }
  }
  $escaped = $sb.ToString()

  $json = '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"' + $escaped + '"}}'
  Write-Output $json
}
catch {
  Write-Output '{}'
}
