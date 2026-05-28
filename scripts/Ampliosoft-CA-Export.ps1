<#
.SYNOPSIS
    Ampliosoft Golden Tenant — Conditional Access Policy Export
    Exports all Conditional Access policies and Named Locations to versioned
    JSON files plus a timestamped backup archive.

.DESCRIPTION
    Run against any tenant before making Conditional Access changes (Phase 1
    of package 1.1). Also run against the Ampliosoft Golden Tenant after any
    policy change to keep the repo in sync.

    Exports to two locations:
      policies/conditional-access/   — one JSON file per policy (repo baseline)
      policies/conditional-access/   — _index.json summarising all policies

    A timestamped backup file (CA-Backup-<timestamp>.json) is written to the
    current directory so the operator has a portable rollback artefact.

.PARAMETER PoliciesRoot
    Root path of the policies folder. Defaults to the policies folder in this repo.

.PARAMETER BackupPath
    Directory for the timestamped backup file. Defaults to the current directory.

.PARAMETER SkipBackup
    If set, skips writing the timestamped backup file (useful in CI pipelines
    where only the per-policy JSON files are needed).

.NOTES
    Version:    2026.2
    Author:     Ampliosoft
    Requires:   Microsoft.Graph
    Scopes:     Policy.Read.All
#>

#Requires -Version 7.2

[CmdletBinding()]
param(
    [string]$PoliciesRoot = (Join-Path $PSScriptRoot ".." "policies"),
    [string]$BackupPath   = (Get-Location).Path,
    [switch]$SkipBackup
)

# ── Helpers ───────────────────────────────────────────────────────────────────

function Resolve-AbsolutePath ([string]$Path) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Get-SafeFileName ([string]$Name) {
    $safe = $Name -replace '[^a-zA-Z0-9\s\-_]', '' -replace '\s+', '-'
    return "$safe.json"
}

function Remove-Fields ([hashtable]$obj, [string[]]$Fields) {
    foreach ($f in $Fields) { $obj.Remove($f) }
}

# ── Connect ───────────────────────────────────────────────────────────────────

Write-Host "`n--- Ampliosoft Golden Tenant — Conditional Access Export ---" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication")) {
    Write-Host "Microsoft.Graph modules not found. Run Ampliosoft-ModuleInstaller.ps1 first." -ForegroundColor Red
    exit 1
}

$PoliciesRoot = Resolve-AbsolutePath $PoliciesRoot
$BackupPath   = Resolve-AbsolutePath $BackupPath
Write-Host "Policies root: $PoliciesRoot" -ForegroundColor Gray
Write-Host "Backup path:   $BackupPath`n" -ForegroundColor Gray

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$org = Get-MgOrganization
Write-Host "Connected to: $($org.DisplayName)" -ForegroundColor White
Write-Host ""

$exportedAt = (Get-Date).ToString("o")

# ── 1. EXPORT CONDITIONAL ACCESS POLICIES ─────────────────────────────────────

Write-Host "Exporting Conditional Access policies..." -ForegroundColor Yellow
$folder   = Join-Path $PoliciesRoot "conditional-access"
New-Item -ItemType Directory -Force -Path $folder | Out-Null

$policies = Get-MgIdentityConditionalAccessPolicy -All
Write-Host "  Found $($policies.Count) policies." -ForegroundColor Gray

$exported      = 0
$indexEntries  = @()

foreach ($policy in $policies) {
    # Build per-policy metadata matching the existing CA export format
    $globalIndexId = if ($policy.DisplayName -match '(\d{4})') { $Matches[1] } else { $null }

    $meta = @{
        globalIndexId = $globalIndexId
        tenantId      = $org.Id
        policyName    = $policy.DisplayName
        state         = $policy.State
        exportedAt    = $exportedAt
        exportedFrom  = $org.DisplayName
    }

    # Convert to hashtable and strip tenant-specific identifiers
    $clean = $policy | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
    Remove-Fields $clean @('id', 'createdDateTime', 'modifiedDateTime')

    # Inject metadata
    $clean['_ampliosoft_export_metadata'] = $meta

    $fileName = Get-SafeFileName -Name $policy.DisplayName
    $outPath  = Join-Path $folder $fileName

    try {
        $json = $clean | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($outPath, $json, [System.Text.Encoding]::UTF8)
        Write-Host "  $($policy.DisplayName)" -ForegroundColor Green
        $exported++
    } catch {
        Write-Host "  ERROR: $($policy.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
    }

    $indexEntries += @{
        displayName = $policy.DisplayName
        state       = $policy.State
        id          = $policy.Id
    }
}

# Write _index.json
$index = @{
    totalPolicies    = $policies.Count
    sourceTenant     = $org.DisplayName
    _ampliosoft_note = "Auto-generated index. Do not edit manually."
    exportedAt       = $exportedAt
    policies         = $indexEntries
}
$indexPath = Join-Path $folder "_index.json"
[System.IO.File]::WriteAllText(
    $indexPath,
    ($index | ConvertTo-Json -Depth 10),
    [System.Text.Encoding]::UTF8
)
Write-Host "  Index written: _index.json ($($policies.Count) entries)" -ForegroundColor White

# ── 2. TIMESTAMPED BACKUP ────────────────────────────────────────────────────

if (-not $SkipBackup) {
    Write-Host "`nWriting timestamped backup..." -ForegroundColor Yellow
    $backupFile = Join-Path $BackupPath "CA-Backup-$(Get-Date -Format 'yyyyMMdd-HHmm').json"
    $policies | ConvertTo-Json -Depth 10 | Out-File $backupFile
    Write-Host "  Backup: $backupFile" -ForegroundColor Green
} else {
    Write-Host "`nTimestamped backup skipped (SkipBackup flag)." -ForegroundColor Gray
}

# ── 3. NAMED LOCATIONS ───────────────────────────────────────────────────────

Write-Host "`nExporting Named Locations..." -ForegroundColor Yellow
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
Write-Host "  Found $($namedLocations.Count) named locations." -ForegroundColor Gray

$nlFolder = Join-Path $folder "named-locations"
New-Item -ItemType Directory -Force -Path $nlFolder | Out-Null
$nlExported = 0

foreach ($nl in $namedLocations) {
    $nlClean = $nl | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
    $nlId    = $nlClean['id']
    Remove-Fields $nlClean @('id', 'createdDateTime', 'modifiedDateTime')
    $nlClean['_ampliosoft_export_metadata'] = @{
        exportedAt   = $exportedAt
        exportedFrom = $org.DisplayName
        tenantId     = $org.Id
        namedLocationId = $nlId
        name         = $nl.DisplayName
    }

    $nlFileName = Get-SafeFileName -Name $nl.DisplayName
    $nlOutPath  = Join-Path $nlFolder $nlFileName
    try {
        $json = $nlClean | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($nlOutPath, $json, [System.Text.Encoding]::UTF8)
        Write-Host "  $($nl.DisplayName)" -ForegroundColor Green
        $nlExported++
    } catch {
        Write-Host "  ERROR: $($nl.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host "`n--- Export complete ---" -ForegroundColor Green
Write-Host ""
Write-Host "  CA policies exported:   $exported of $($policies.Count)" -ForegroundColor White
Write-Host "  Named locations exported: $nlExported of $($namedLocations.Count)" -ForegroundColor White
Write-Host ""

if ($exported -lt $policies.Count -or $nlExported -lt $namedLocations.Count) {
    Write-Host "  Some items failed — check the errors above." -ForegroundColor Yellow
}

Write-Host "  Next step:" -ForegroundColor Cyan
Write-Host "  git add 00-core-toolkit/policies/conditional-access/" -ForegroundColor White
Write-Host "  git commit -m 'CA policy export $(Get-Date -Format yyyy-MM-dd)'" -ForegroundColor White
