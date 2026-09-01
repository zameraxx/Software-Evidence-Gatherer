#Requires -Version 5.1

<#
.SYNOPSIS
  Generate docs/runbooks.html from the two target runbooks in docs/.

.DESCRIPTION
  The two Markdown runbooks are the single source. This script renders them into the
  two-track page, using tools/runbooks.template.html as the shell (fonts, CSS, the
  track switcher, and the JavaScript that swaps tracks and drives the copy buttons).

  Run it after editing either runbook:

      .\tools\Build-Runbooks.ps1

  Add -Check to fail instead of writing, which is what a pre-commit hook or CI wants:

      .\tools\Build-Runbooks.ps1 -Check

  WHY A MARKDOWN PARSER LIVES IN THIS REPO
  ----------------------------------------
  Markdown cannot say "this blockquote is a warning" or "these two documents are
  alternate tracks of one page", and the page needs both. Rather than give that up, the
  runbooks use three conventions that stay valid Markdown and still render correctly on
  GitHub:

    1. GitHub alert blockquotes set a callout's severity.
           > [!NOTE] / > [!WARNING] / > [!CAUTION]
       A plain blockquote is a NOTE. The first bold run inside becomes the callout's
       label; the rest is its body.

    2. A fenced code block's info string carries the caption shown above it.
           ```powershell PowerShell - your machine
       GitHub uses the first word for highlighting and ignores the rest, so this is
       invisible there. With no caption, the language name is used.

    3. Headings carry the structure. "## Step N - Title" becomes numbered step N;
       everything after the "# Reference" heading becomes a reference section.

  Heading ids use GitHub's slug rules, so in-document links written for GitHub
  (#if-something-goes-wrong) keep working here. Because both tracks define some of the
  same headings, ids are prefixed per track and matching links are rewritten to suit.

  There is no Node or Python dependency on purpose: an assessment machine is not
  somewhere you want to be installing a toolchain, so this is Windows PowerShell only.
#>

[CmdletBinding()]
param(
    # Verify the committed page matches what the sources would generate, and fail if it
    # does not. Writes nothing.
    [switch]$Check
)

$ErrorActionPreference = 'Stop'

$ToolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ToolsDir
$DocsDir  = Join-Path $RepoRoot 'docs'
$Template = Join-Path $ToolsDir 'runbooks.template.html'
$OutFile  = Join-Path $DocsDir  'runbooks.html'

# Track order is the order they appear in the switcher.
$Tracks = @(
    @{ Id = 'windows'; Prefix = 'win'; File = 'Windows-Target-Runbook.md' },
    @{ Id = 'linux';   Prefix = 'lin'; File = 'Linux-Target-Runbook.md'   }
)

# ============================================================================
# inline and text helpers
# ============================================================================

function ConvertTo-HtmlText {
    param([string]$Text)
    return $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
}

# GitHub's heading-slug rules: lowercase, drop everything that is not a word character,
# space or hyphen, then spaces to hyphens. Reproduced so links written against the
# Markdown on GitHub resolve to the same headings here.
function ConvertTo-Slug {
    param([string]$Text)
    $s = $Text.ToLowerInvariant()
    $s = $s -replace '[^\p{L}\p{Nd} _-]', ''
    $s = $s -replace '[ _]', '-'
    return $s.Trim('-')
}

# Inline Markdown. Code spans are extracted first and restored last, so their contents
# are never treated as emphasis or link syntax.
function ConvertTo-Inline {
    param([string]$Text)
    $spans = New-Object System.Collections.ArrayList
    $work = [regex]::Replace($Text, '`([^`]+)`', {
        param($m)
        $i = $spans.Add('<code>' + (ConvertTo-HtmlText $m.Groups[1].Value) + '</code>')
        return [char]0x1 + [string]$i + [char]0x2
    })

    $work = ConvertTo-HtmlText $work
    # links before emphasis: a link title can contain ** of its own
    $work = [regex]::Replace($work, '\[([^\]]+)\]\(([^)]+)\)', '<a href="$2">$1</a>')
    $work = [regex]::Replace($work, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
    $work = [regex]::Replace($work, '(?<![\w*])\*([^*\n]+)\*(?![\w*])', '<em>$1</em>')

    return [regex]::Replace($work, [string][char]0x1 + '(\d+)' + [string][char]0x2, {
        param($m) $spans[[int]$m.Groups[1].Value]
    })
}

# Status words get a coloured pill wherever they are the entire content of a table cell.
$PillMap = @{ 'Collected' = 'ok'; 'Partial' = 'warn'; 'Failed' = 'stop' }

function ConvertTo-Cell {
    param([string]$Text)
    $t = $Text.Trim()
    if ($t -match '^`([A-Za-z]+)`$' -and $PillMap.ContainsKey($Matches[1])) {
        return '<span class="pill {0}">{1}</span>' -f $PillMap[$Matches[1]], $Matches[1]
    }
    return ConvertTo-Inline $t
}

# ============================================================================
# block rendering
# ============================================================================

# A code fence becomes the dark command card the page uses, with its caption and a copy
# button. Comment lines are dimmed - the whole point of the caption/comment styling is
# that an operator can tell at a glance which lines are commentary and which are the
# command.
function Write-CodeBlock {
    param([string[]]$Lines, [string]$Info)

    $lang    = ''
    $caption = ''
    if ($Info) {
        $parts   = $Info.Trim() -split '\s+', 2
        $lang    = $parts[0]
        if ($parts.Count -gt 1) { $caption = $parts[1] }
    }
    if (-not $caption) {
        switch ($lang) {
            'powershell' { $caption = 'PowerShell' }
            'bash'       { $caption = 'bash' }
            default      { $caption = if ($lang) { $lang } else { 'Output' } }
        }
    }

    $body = foreach ($l in $Lines) {
        $esc = ConvertTo-HtmlText $l
        if ($l.TrimStart().StartsWith('#') -and $lang -in @('powershell', 'bash')) {
            '<span class="c">' + $esc + '</span>'
        } else { $esc }
    }

    return @(
        '            <div class="cmd">'
        '              <div class="cmd-head"><span>' + (ConvertTo-HtmlText $caption) + '</span><button class="copy" type="button">Copy</button></div>'
        '<pre>' + ($body -join "`n") + '</pre>'
        '            </div>'
    )
}

function Write-Table {
    param([string[]]$Rows)
    if ($Rows.Count -lt 2) { return @() }
    $split = { param($r) ($r.Trim().Trim('|') -split '(?<!\\)\|') | ForEach-Object { $_.Trim() } }

    $head = & $split $Rows[0]
    $out = New-Object System.Collections.ArrayList
    [void]$out.Add('            <div class="tablewrap">')
    [void]$out.Add('              <table>')
    [void]$out.Add('                <thead><tr>' + (($head | ForEach-Object { '<th>' + (ConvertTo-Inline $_) + '</th>' }) -join '') + '</tr></thead>')
    [void]$out.Add('                <tbody>')
    foreach ($r in $Rows[2..($Rows.Count - 1)]) {
        $cells = & $split $r
        [void]$out.Add('                  <tr>' + (($cells | ForEach-Object { '<td>' + (ConvertTo-Cell $_) + '</td>' }) -join '') + '</tr>')
    }
    [void]$out.Add('                </tbody>')
    [void]$out.Add('              </table>')
    [void]$out.Add('            </div>')
    return $out.ToArray()
}

# Blockquote -> callout. "> [!WARNING]" on the first line sets severity; the first bold
# run becomes the label above the body.
function Write-Callout {
    param([string[]]$Lines)

    $cls = 'note'
    if ($Lines.Count -and $Lines[0].Trim() -match '^\[!(NOTE|WARNING|CAUTION|IMPORTANT|TIP)\]$') {
        switch ($Matches[1]) {
            'WARNING'   { $cls = 'note warn' }
            'CAUTION'   { $cls = 'note stop' }
            'IMPORTANT' { $cls = 'note stop' }
            default     { $cls = 'note' }
        }
        $Lines = $Lines[1..($Lines.Count - 1)]
    }

    $text = ($Lines -join ' ').Trim()
    $tag  = ''
    # a leading bold run is the label: "**Label:** the rest"
    if ($text -match '^\*\*(?<label>[^*]+?)\*\*:?\s*(?<rest>.*)$') {
        $tag  = $Matches['label'].TrimEnd(':', '?').Trim()
        if ($Matches['label'].TrimEnd().EndsWith('?')) { $tag = $Matches['label'].Trim() }
        $text = $Matches['rest']
    }

    $out = New-Object System.Collections.ArrayList
    [void]$out.Add('            <div class="' + $cls + '">')
    if ($tag) { [void]$out.Add('              <span class="tag">' + (ConvertTo-HtmlText $tag) + '</span>') }
    [void]$out.Add('              <p>' + (ConvertTo-Inline $text) + '</p>')
    [void]$out.Add('            </div>')
    return $out.ToArray()
}

# ============================================================================
# the block walker
# ============================================================================

# Renders a run of Markdown lines. Returns HTML lines. Headings are handled by the
# caller, which is what splits the document into steps and reference sections.
function ConvertTo-Blocks {
    param([string[]]$Lines)

    $out = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $Lines.Count) {
        $line = $Lines[$i]

        if (-not $line.Trim()) { $i++; continue }

        # horizontal rule - the page uses spacing instead, so it is dropped
        if ($line -match '^\s*---+\s*$') { $i++; continue }

        # fenced code
        if ($line -match '^\s*```(.*)$') {
            $info = $Matches[1]
            $i++
            $buf = New-Object System.Collections.ArrayList
            while ($i -lt $Lines.Count -and $Lines[$i] -notmatch '^\s*```\s*$') { [void]$buf.Add($Lines[$i]); $i++ }
            $i++
            foreach ($l in (Write-CodeBlock -Lines $buf.ToArray() -Info $info)) { [void]$out.Add($l) }
            continue
        }

        # table
        if ($line -match '^\s*\|' -and $i + 1 -lt $Lines.Count -and $Lines[$i+1] -match '^\s*\|[\s:|-]+\|?\s*$') {
            $buf = New-Object System.Collections.ArrayList
            while ($i -lt $Lines.Count -and $Lines[$i] -match '^\s*\|') { [void]$buf.Add($Lines[$i]); $i++ }
            foreach ($l in (Write-Table -Rows $buf.ToArray())) { [void]$out.Add($l) }
            continue
        }

        # blockquote / callout
        if ($line -match '^\s*>') {
            $buf = New-Object System.Collections.ArrayList
            while ($i -lt $Lines.Count -and $Lines[$i] -match '^\s*>') {
                [void]$buf.Add(($Lines[$i] -replace '^\s*>\s?', ''))
                $i++
            }
            foreach ($l in (Write-Callout -Lines $buf.ToArray())) { [void]$out.Add($l) }
            continue
        }

        # lists - a blank line inside one continues it only if the next line is a marker
        if ($line -match '^\s*(-|\d+\.)\s+') {
            $ordered = $line -match '^\s*\d+\.\s'
            $tag = if ($ordered) { 'ol' } else { 'ul' }
            [void]$out.Add('            <' + $tag + '>')
            while ($i -lt $Lines.Count) {
                if ($Lines[$i] -match '^\s*(?:-|\d+\.)\s+(.*)$') {
                    $item = $Matches[1]
                    $i++
                    # continuation lines are indented and not a new marker
                    while ($i -lt $Lines.Count -and $Lines[$i] -match '^\s{2,}\S' -and $Lines[$i] -notmatch '^\s*(?:-|\d+\.)\s') {
                        $item += ' ' + $Lines[$i].Trim(); $i++
                    }
                    [void]$out.Add('              <li>' + (ConvertTo-Inline $item) + '</li>')
                } elseif (-not $Lines[$i].Trim() -and $i + 1 -lt $Lines.Count -and $Lines[$i+1] -match '^\s*(?:-|\d+\.)\s') {
                    $i++
                } else { break }
            }
            [void]$out.Add('            </' + $tag + '>')
            continue
        }

        # paragraph
        $buf = New-Object System.Collections.ArrayList
        while ($i -lt $Lines.Count -and $Lines[$i].Trim() -and
               $Lines[$i] -notmatch '^\s*(```|\||>|-\s|\d+\.\s|#|---+\s*$)') {
            [void]$buf.Add($Lines[$i].Trim()); $i++
        }
        if ($buf.Count) { [void]$out.Add('            <p>' + (ConvertTo-Inline ($buf -join ' ')) + '</p>') }
        elseif ($i -lt $Lines.Count -and $Lines[$i].Trim() -and $Lines[$i] -notmatch '^\s*#') { $i++ }
    }
    return $out.ToArray()
}

# ============================================================================
# document -> track
# ============================================================================

function ConvertTo-Track {
    param([hashtable]$Track)

    $path = Join-Path $DocsDir $Track.File
    if (-not (Test-Path -LiteralPath $path)) { throw "Source runbook not found: $path" }
    $lines = [System.IO.File]::ReadAllLines($path)

    $title = ''
    $intro = New-Object System.Collections.ArrayList
    $steps = New-Object System.Collections.ArrayList
    $refs  = New-Object System.Collections.ArrayList
    $mode  = 'intro'
    $cur   = $null

    foreach ($line in $lines) {
        if ($line -match '^#\s+(.*)$') {
            $h = $Matches[1].Trim()
            if ($h -eq 'Reference') { $mode = 'ref'; $cur = $null; continue }
            if (-not $title) { $title = $h; continue }
            continue
        }
        if ($line -match '^##\s+(.*)$') {
            $h = $Matches[1].Trim()
            if ($h -match '^Step\s+(\d+)\s*\p{Pd}\s*(.*)$') {
                $cur = @{ Num = $Matches[1]; Title = $Matches[2].Trim(); Body = (New-Object System.Collections.ArrayList) }
                [void]$steps.Add($cur); $mode = 'step'
            } else {
                $cur = @{ Title = $h; Body = (New-Object System.Collections.ArrayList) }
                [void]$refs.Add($cur); $mode = 'ref'
            }
            continue
        }
        if ($cur) { [void]$cur.Body.Add($line) }
        elseif ($mode -eq 'intro') { [void]$intro.Add($line) }
    }

    # ---- emit ----
    $p = $Track.Prefix
    $out = New-Object System.Collections.ArrayList
    $hidden = if ($Track.Id -eq 'windows') { '' } else { ' hidden' }

    [void]$out.Add('      <section class="track" id="track-' + $Track.Id + '" role="tabpanel" aria-labelledby="tab-' + $Track.Id + '"' + $hidden + '>')
    [void]$out.Add('')
    [void]$out.Add('        <div class="track-head">')
    [void]$out.Add('          <h2>' + (ConvertTo-HtmlText ($title -replace '\s*\p{Pd}\s*Runbook$','')) + '</h2>')
    foreach ($l in (ConvertTo-Blocks $intro.ToArray())) { [void]$out.Add($l) }
    [void]$out.Add('        </div>')
    [void]$out.Add('')

    foreach ($s in $steps) {
        $id = $p + '-' + (ConvertTo-Slug $s.Title)
        [void]$out.Add('        <article class="step">')
        [void]$out.Add('          <div class="marker"><span class="num">' + $s.Num + '</span><span class="spine"></span></div>')
        [void]$out.Add('          <h3 id="' + $id + '">' + (ConvertTo-HtmlText $s.Title) + '</h3>')
        [void]$out.Add('          <div class="body">')
        foreach ($l in (ConvertTo-Blocks $s.Body.ToArray())) { [void]$out.Add($l) }
        [void]$out.Add('          </div>')
        [void]$out.Add('        </article>')
        [void]$out.Add('')
    }

    if ($refs.Count) {
        [void]$out.Add('        <div class="ref-divider">Reference</div>')
        [void]$out.Add('')
        foreach ($r in $refs) {
            $id = $p + '-' + (ConvertTo-Slug $r.Title)
            [void]$out.Add('        <section class="refsec">')
            [void]$out.Add('          <h3 id="' + $id + '">' + (ConvertTo-HtmlText $r.Title) + '</h3>')
            [void]$out.Add('          <div class="body">')
            foreach ($l in (ConvertTo-Blocks $r.Body.ToArray())) { [void]$out.Add($l) }
            [void]$out.Add('          </div>')
            [void]$out.Add('        </section>')
            [void]$out.Add('')
        }
    }

    [void]$out.Add('      </section>')

    # In-document links were written against the Markdown's own slugs. Both tracks define
    # some of the same headings, so ids are prefixed per track - rewrite the links to match.
    $html = $out -join "`r`n"
    $known = @()
    $known += $steps | ForEach-Object { ConvertTo-Slug $_.Title }
    $known += $refs  | ForEach-Object { ConvertTo-Slug $_.Title }
    foreach ($slug in ($known | Sort-Object Length -Descending)) {
        if ($slug) { $html = $html.Replace('href="#' + $slug + '"', 'href="#' + $p + '-' + $slug + '"') }
    }
    # a link to the sibling .md becomes a link to that track
    $html = $html -replace 'href="Windows-Target-Runbook\.md"', 'href="#" data-goto="windows"'
    $html = $html -replace 'href="Linux-Target-Runbook\.md"',   'href="#" data-goto="linux"'
    return $html
}

# ============================================================================
# main
# ============================================================================

if (-not (Test-Path -LiteralPath $Template)) { throw "Template not found: $Template" }

$rendered = ($Tracks | ForEach-Object { ConvertTo-Track $_ }) -join "`r`n`r`n"
$page = [System.IO.File]::ReadAllText($Template).Replace('<!--TRACKS-->', $rendered)

$enc = New-Object System.Text.UTF8Encoding($false)

if ($Check) {
    if (-not (Test-Path -LiteralPath $OutFile)) { Write-Error "docs/runbooks.html does not exist. Run this script without -Check."; exit 1 }
    $current = [System.IO.File]::ReadAllText($OutFile)
    if ($current -eq $page) { Write-Host "runbooks.html is up to date with the Markdown sources." -ForegroundColor Green; exit 0 }
    Write-Error "docs/runbooks.html is out of date. Run .\tools\Build-Runbooks.ps1 and commit the result."
    exit 1
}

[System.IO.File]::WriteAllText($OutFile, $page, $enc)

$steps = ([regex]::Matches($page, 'class="step"')).Count
$refs  = ([regex]::Matches($page, 'class="refsec"')).Count
$notes = ([regex]::Matches($page, 'class="note')).Count
$cmds  = ([regex]::Matches($page, 'class="cmd"')).Count
Write-Host "Wrote $OutFile" -ForegroundColor Green
Write-Host "  from : $(($Tracks | ForEach-Object { $_.File }) -join ', ')"
Write-Host "  steps $steps   reference sections $refs   callouts $notes   command blocks $cmds"
