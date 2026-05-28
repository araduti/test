<#
.SYNOPSIS
    Ampliosoft — Normalize Policy Names
    Applies naming convention rules to exported policy JSON files.

.DESCRIPTION
    Reads naming-convention.json and applies prefix rules, exact renames,
    and skip patterns to all exported policy files in the policies/ folder.

    Run this after export and before committing to git.
    The script modifies the displayName/name field inside each JSON file
    and optionally renames the file itself to match.

    Modes:
      -WhatIf   : Shows what would change without modifying any files (default)
      -Apply    : Makes the changes

.PARAMETER PoliciesRoot
    Root of the policies folder. Defaults to the policies folder in this repo.

.PARAMETER ConfigPath
    Path to naming-convention.json. Defaults to policies/naming-convention.json.

.PARAMETER Apply
    Switch to actually apply changes. Without this, runs in preview mode.

.PARAMETER Folder
    Target a specific subfolder only (e.g. device-configuration).

.NOTES
    Version:    2026.1
    Author:     Ampliosoft
#>

#Requires -Version 7.2

[CmdletBinding()]
param(
    [string]$PoliciesRoot = (Join-Path $PSScriptRoot ".." "policies"),
    [string]$ConfigPath   = "",
    [switch]$Apply,
    [string]$Folder       = ""
)

$PoliciesRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PoliciesRoot)

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $PoliciesRoot "naming-convention.json"
}

if (-not (Test-Path $ConfigPath)) {
    Write-Host "Naming convention config not found: $ConfigPath" -ForegroundColor Red
    exit 1
}

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

$mode = if ($Apply) { "APPLY" } else { "PREVIEW" }
Write-Host "`n--- Ampliosoft Policy Name Normalisation ($mode) ---" -ForegroundColor Cyan
if (-not $Apply) {
    Write-Host "  Running in preview mode. Use -Apply to make changes.`n" -ForegroundColor Yellow
}

# Determine which folders to process
$searchRoot = if ($Folder) {
    Join-Path $PoliciesRoot $Folder
} else {
    $PoliciesRoot
}

$jsonFiles = Get-ChildItem -Path $searchRoot -Filter "*.json" -Recurse |
    Where-Object { $_.Name -ne "_index.json" -and $_.Name -ne "naming-convention.json" }

Write-Host "  Found $($jsonFiles.Count) policy files to check.`n" -ForegroundColor Gray

$stats = @{ Renamed = 0; Skipped = 0; Unchanged = 0; Errors = 0 }

foreach ($file in $jsonFiles) {

    try {
        $content = Get-Content $file.FullName -Raw | ConvertFrom-Json -AsHashtable
    } catch {
        Write-Host "  [ERROR] Cannot parse $($file.Name): $_" -ForegroundColor Red
        $stats.Errors++
        continue
    }

    # Extract the policy name — two structures exist in the repo:
    # Intune export:    { _ampliosoft_export_metadata: {...}, policy: { displayName/name: "..." } }
    # CA export:        { _ampliosoft_export_metadata: {...}, displayName: "...", state: "..." }
    $policyObj = $content['policy']

    $currentName = if ($policyObj -and $policyObj['displayName']) {
        $policyObj['displayName']
    } elseif ($policyObj -and $policyObj['name']) {
        $policyObj['name']
    } elseif ($content['displayName']) {
        $content['displayName']    # CA policy structure — name at top level
    } elseif ($content['name']) {
        $content['name']
    } else {
        $null
    }

    if (-not $currentName) {
        Write-Host "  [SKIP] No name found in: $($file.Name)" -ForegroundColor DarkGray
        $stats.Unchanged++
        continue
    }

    # Check skip patterns first
    $shouldSkip = $false
    foreach ($skip in $config.skipPatterns) {
        if ($currentName -match $skip.match) {
            Write-Host "  [SKIP — Microsoft-managed] $currentName" -ForegroundColor DarkGray
            $shouldSkip = $true
            break
        }
    }
    if ($shouldSkip) { $stats.Skipped++; continue }

    # Check exact renames
    $newName = $currentName
    foreach ($exact in $config.exactRenames) {
        if ($currentName -eq $exact.from) {
            $newName = $exact.to
            break
        }
    }

    # Apply prefix rules if no exact rename matched
    if ($newName -eq $currentName) {
        foreach ($rule in $config.prefixRules) {
            if ($currentName -match $rule.match) {
                $newName = $currentName -replace $rule.match, $rule.replace
                break
            }
        }
    }

    if ($newName -eq $currentName) {
        $stats.Unchanged++
        continue
    }

    # Show the change
    $relPath = $file.FullName.Replace($PoliciesRoot, "").TrimStart([System.IO.Path]::DirectorySeparatorChar)
    Write-Host "  [RENAME] $relPath" -ForegroundColor $(if ($Apply) { "Green" } else { "Cyan" })
    Write-Host "    Before: $currentName" -ForegroundColor DarkGray
    Write-Host "    After:  $newName" -ForegroundColor White

    if ($Apply) {
        # Update name in the correct location depending on file structure
        if ($policyObj) {
            # Intune structure — name is inside the policy wrapper
            if ($policyObj['displayName']) { $policyObj['displayName'] = $newName }
            if ($policyObj['name'])        { $policyObj['name']        = $newName }
        } else {
            # CA structure — name is at the top level
            if ($content['displayName']) { $content['displayName'] = $newName }
            if ($content['name'])        { $content['name']        = $newName }
        }

        # Update metadata fields in both cases
        $meta = $content['_ampliosoft_export_metadata']
        if ($meta) {
            if ($meta['policyName']) { $meta['policyName'] = $newName }
            if ($meta['name'])       { $meta['name']       = $newName }
        }

        try {
            $json = $content | ConvertTo-Json -Depth 20
            [System.IO.File]::WriteAllText($file.FullName, $json, [System.Text.Encoding]::UTF8)

            # Rename the file itself to match the new name
            $safeNewName = $newName -replace '[^a-zA-Z0-9\s\-_]', '' -replace '\s+', '-'

            # Determine the file prefix to preserve:
            # - Intune files: CATALOG-, LEGACY-, SECURITY-, iOS-, Android-, Windows-, macOS-, Autopilot-, Enrolment-
            # - CA files:     GLOBAL-, NON-STANDARD-
            $prefixMatch = $file.BaseName -match '^(CATALOG|LEGACY|SECURITY|iOS|Android|Windows-MAM|macOS|AutopilotProfile|Enrolment-\w+|GLOBAL-\d{4}-\w+-|NON-STANDARD)-'
            $prefix      = if ($prefixMatch) { $Matches[1] } else { "" }
            $newFileName = if ($prefix) { "$prefix-$safeNewName.json" } else { "$safeNewName.json" }
            $newFilePath = Join-Path $file.DirectoryName $newFileName

            if ($newFileName -ne $file.Name -and -not (Test-Path $newFilePath)) {
                Rename-Item -Path $file.FullName -NewName $newFileName
                Write-Host "    File:   $($file.Name) → $newFileName" -ForegroundColor DarkGreen
            }

        } catch {
            Write-Host "    ERROR applying rename: $_" -ForegroundColor Red
            $stats.Errors++
            continue
        }

        $stats.Renamed++
    } else {
        $stats.Renamed++  # count as "would rename" in preview
    }
}

# Summary
Write-Host ""
Write-Host "--- Summary ---" -ForegroundColor Cyan
if ($Apply) {
    Write-Host "  Renamed:    $($stats.Renamed)" -ForegroundColor Green
} else {
    Write-Host "  Would rename: $($stats.Renamed)  (run with -Apply to apply)" -ForegroundColor Cyan
}
Write-Host "  Skipped (Microsoft-managed): $($stats.Skipped)" -ForegroundColor DarkGray
Write-Host "  Unchanged:  $($stats.Unchanged)" -ForegroundColor Gray
if ($stats.Errors -gt 0) {
    Write-Host "  Errors:     $($stats.Errors)" -ForegroundColor Red
}

if ($Apply -and $stats.Renamed -gt 0) {
    Write-Host ""
    Write-Host "  Names updated. Review with git diff before committing." -ForegroundColor Yellow
}
