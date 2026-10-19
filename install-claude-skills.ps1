<#
.SYNOPSIS
  install-claude-skills.ps1 -- install this package's Claude Code skills (Windows).

.DESCRIPTION
  Copies (or links) each directory under claude-skills\ into
  <ConfigDir>\skills\<name>\. Same behaviour and options as
  install-claude-skills.sh; see install-claude-skills.sh(1).

.EXAMPLE
  .\install-claude-skills.ps1                 # %CLAUDE_CONFIG_DIR% or ~\.claude
  .\install-claude-skills.ps1 -All            # every ~\.claude* config dir
  .\install-claude-skills.ps1 -Target D:\cc -Link
  .\install-claude-skills.ps1 -Uninstall -All
#>
[CmdletBinding()]
param(
    [string[]]$Target = @(),
    [switch]$All,
    [switch]$Link,       # directory junction; needs no admin rights
    [switch]$Uninstall,
    [switch]$Force,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'

$src    = Join-Path $PSScriptRoot 'claude-skills'
$marker = '.installed-from-requests-fermi-sso'
if (-not (Test-Path $src -PathType Container)) { Write-Error "no skills directory at $src"; exit 1 }

function Test-ClaudeDir([string]$d) {
    foreach ($f in 'settings.json','projects','skills','CLAUDE.md','sessions','plugins') {
        if (Test-Path (Join-Path $d $f)) { return $true }
    }
    return $false
}

$targets = [System.Collections.Generic.List[string]]::new()
foreach ($t in $Target) { $targets.Add($t) }
if ($All) {
    $cands = @(Get-ChildItem -Path $HOME -Directory -Force -Filter '.claude*' | ForEach-Object FullName)
    if ($env:CLAUDE_CONFIG_DIR) { $cands += $env:CLAUDE_CONFIG_DIR }
    foreach ($d in $cands) {
        if (Test-ClaudeDir $d) { $targets.Add($d) }
        else { Write-Host "skip  $d (not a Claude Code config dir; use -Target to force it)" }
    }
}
if ($targets.Count -eq 0) {
    $targets.Add($(if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR } else { Join-Path $HOME '.claude' }))
}

function Invoke-Step([string]$what, [scriptblock]$do) {
    if ($DryRun) { Write-Host "  would: $what" } else { & $do }
}

$seen = @{}
$action = if ($Uninstall) { 'uninstall' } else { 'install' }
$mode   = if ($Link) { 'link' } else { 'copy' }
foreach ($t in $targets) {
    if ($t -eq '~' -or $t.StartsWith('~\') -or $t.StartsWith('~/')) { $t = $HOME + $t.Substring(1) }
    if (-not (Test-Path $t) -and -not $DryRun) { New-Item -ItemType Directory -Path $t | Out-Null }
    $real = if (Test-Path $t) { (Resolve-Path $t).ProviderPath.TrimEnd('\','/') } else { $t }
    if ($seen.ContainsKey($real.ToLower())) { continue }
    $seen[$real.ToLower()] = $true
    $skills = Join-Path $real 'skills'
    Write-Host "$action into $skills"
    foreach ($skill in Get-ChildItem -Path $src -Directory) {
        if (-not (Test-Path (Join-Path $skill.FullName 'SKILL.md'))) { continue }
        $name = $skill.Name
        $dest = Join-Path $skills $name
        $item = Get-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        $ours = $item -and ($item.LinkType -or (Test-Path (Join-Path $dest $marker)))
        if ($Uninstall) {
            if ($item) {
                if ($ours -or $Force) {
                    Invoke-Step "remove $dest" { Remove-Item -LiteralPath $dest -Recurse -Force }
                    Write-Host "  removed  $name"
                } else { Write-Host "  kept     $name (not installed by this script; -Force removes it)" }
            }
            continue
        }
        if ($item -and -not $ours -and -not $Force) {
            Write-Host "  kept     $name (exists and was not installed by this script; -Force replaces it)"
            continue
        }
        Invoke-Step "install $name -> $dest" {
            New-Item -ItemType Directory -Path $skills -Force | Out-Null
            if ($item) {
                # a junction must be removed as a link, not recursed into
                if ($item.LinkType) { $item.Delete() } else { Remove-Item -LiteralPath $dest -Recurse -Force }
            }
            if ($Link) {
                New-Item -ItemType Junction -Path $dest -Target $skill.FullName | Out-Null
            } else {
                Copy-Item -LiteralPath $skill.FullName -Destination $dest -Recurse
                Set-Content -Path (Join-Path $dest $marker) -Value $PSScriptRoot
            }
        }
        Write-Host "  $mode     $name"
    }
}
