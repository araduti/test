<#
.SYNOPSIS
    Ampliosoft Conditional Access Validator

.DESCRIPTION
    Validates client tenant CA posture against the GLOBAL baseline policy set.
    Checks policy presence, break-glass exclusions, and non-standard enabled
    policies that may conflict with the baseline.

.NOTES
    Version: 2026.1
    Author: Ampliosoft
    Requires: Microsoft.Graph
    Scopes: Policy.Read.All, User.Read.All
#>

#Requires -Version 7.2

[CmdletBinding()]
param(
    [string]$PoliciesRoot = (Join-Path $PSScriptRoot ".." "policies" "conditional-access"),
    [string[]]$BreakGlassObjectIds = @(),
    [ValidateSet("reportOnly", "enabled", "mixed")]
    [string]$ExpectedStateMode = "mixed",
    [switch]$IncludeNonStandardInBaseline,
    [switch]$AllowNonStandardEnabled,
    [string]$OutputPath = ""
)

function Resolve-AbsolutePath([string]$Path) {
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Read-JsonAsHashtable([string]$Path) {
    return (Get-Content -Path $Path -Raw | ConvertFrom-Json -AsHashtable)
}

function Get-ExpectedState {
    param([string]$Mode)
    switch ($Mode) {
        "reportOnly" { return "enabledForReportingButNotEnforced" }
        "enabled"    { return "enabled" }
        default       { return $null }
    }
}

Write-Host "`n--- Ampliosoft Conditional Access Validator v2026.1 ---" -ForegroundColor Cyan

$PoliciesRoot = Resolve-AbsolutePath $PoliciesRoot
if (-not (Test-Path $PoliciesRoot)) {
    Write-Host "Policies root not found: $PoliciesRoot" -ForegroundColor Red
    exit 1
}

if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication")) {
    Write-Host "Microsoft.Graph modules not found. Run module installer first." -ForegroundColor Red
    exit 1
}

Connect-MgGraph -Scopes "Policy.Read.All","User.Read.All" -NoWelcome
$org = Get-MgOrganization
Write-Host "Connected to: $($org.DisplayName)" -ForegroundColor White

if ($BreakGlassObjectIds.Count -eq 0) {
    $bgUsers = Get-MgUser -Filter "startsWith(UserPrincipalName,'AMPLIO-9999')" -ErrorAction SilentlyContinue
    if ($bgUsers) {
        $BreakGlassObjectIds = @($bgUsers | Select-Object -ExpandProperty Id)
    }
}

if ($BreakGlassObjectIds.Count -eq 0) {
    Write-Host "No break-glass users discovered. Supply -BreakGlassObjectIds for strict validation." -ForegroundColor Yellow
}

$baselineFiles = Get-ChildItem -Path $PoliciesRoot -Filter "*.json" |
    Where-Object { $_.Name -ne "_index.json" }

if (-not $IncludeNonStandardInBaseline) {
    $baselineFiles = $baselineFiles | Where-Object { $_.BaseName -notlike "NON-STANDARD-*" }
}

$baseline = foreach ($f in ($baselineFiles | Sort-Object Name)) {
    $j = Read-JsonAsHashtable -Path $f.FullName
    [PSCustomObject]@{
        file = $f.Name
        displayName = $j.displayName
        state = $j.state
    }
}

$tenantPolicies = @(Get-MgIdentityConditionalAccessPolicy -All)

$findings = @()

# Presence checks
foreach ($b in $baseline) {
    if ([string]::IsNullOrWhiteSpace($b.displayName)) {
        $findings += [PSCustomObject]@{ Severity = "Error"; Category = "Baseline"; Policy = $b.file; Detail = "Baseline file missing displayName" }
        continue
    }

    $match = $tenantPolicies | Where-Object { $_.DisplayName -eq $b.displayName } | Select-Object -First 1
    if (-not $match) {
        $findings += [PSCustomObject]@{ Severity = "Error"; Category = "Presence"; Policy = $b.displayName; Detail = "Missing in tenant" }
        continue
    }

    $expectedState = Get-ExpectedState -Mode $ExpectedStateMode
    if ($expectedState -and $match.State -ne $expectedState) {
        $findings += [PSCustomObject]@{
            Severity = "Warning"
            Category = "State"
            Policy = $b.displayName
            Detail = "State mismatch. Expected $expectedState, found $($match.State)"
        }
    }

    # Break-glass exclusion for all-users policies
    if ($BreakGlassObjectIds.Count -gt 0 -and $match.Conditions.Users.IncludeUsers -contains "All") {
        foreach ($bg in $BreakGlassObjectIds) {
            if ($match.Conditions.Users.ExcludeUsers -notcontains $bg) {
                $findings += [PSCustomObject]@{
                    Severity = "Error"
                    Category = "BreakGlass"
                    Policy = $b.displayName
                    Detail = "Missing break-glass exclusion for $bg"
                }
            }
        }
    }
}

# Unexpected enabled policies
$allowedPattern = '^GLOBAL - \d{4} - |^NON-STANDARD - Microsoft-managed'
$unexpectedEnabled = $tenantPolicies | Where-Object {
    $_.State -eq "enabled" -and $_.DisplayName -notmatch $allowedPattern
}

if (-not $AllowNonStandardEnabled) {
    foreach ($p in $unexpectedEnabled) {
        $findings += [PSCustomObject]@{
            Severity = "Warning"
            Category = "LegacyConflict"
            Policy = $p.DisplayName
            Detail = "Enabled policy not aligned to GLOBAL naming pattern"
        }
    }
}

Write-Host "`n--- Validation summary ---" -ForegroundColor Cyan
if ($findings.Count -eq 0) {
    Write-Host "No findings. Baseline appears aligned." -ForegroundColor Green
} else {
    $findings | Sort-Object Severity, Category, Policy | Format-Table -AutoSize
}

if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location).Path "CA-Validator-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
} else {
    $OutputPath = Resolve-AbsolutePath $OutputPath
}

[PSCustomObject]@{
    timestamp = (Get-Date).ToString("o")
    tenant = $org.DisplayName
    tenantId = $org.Id
    expectedStateMode = $ExpectedStateMode
    breakGlassIds = $BreakGlassObjectIds
    findings = $findings
} | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutputPath -Encoding utf8

Write-Host "Output written: $OutputPath" -ForegroundColor Gray

$errors = @($findings | Where-Object { $_.Severity -eq "Error" }).Count
if ($errors -gt 0) {
    exit 1
}
