<#
.SYNOPSIS
    Ampliosoft Conditional Access Promotion Script

.DESCRIPTION
    Promotes Conditional Access policies from report-only to enabled in
    controlled waves based on GLOBAL index IDs and/or display names.

.NOTES
    Version: 2026.1
    Author: Ampliosoft
    Requires: Microsoft.Graph
    Scopes: Policy.Read.All, Policy.ReadWrite.ConditionalAccess
#>

#Requires -Version 7.2

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ManifestPath = "",
    [string]$Wave = "",
    [string[]]$GlobalIndexIds = @(),
    [string[]]$PolicyNames = @(),
    [ValidateSet("enabled", "enabledForReportingButNotEnforced", "disabled")]
    [string]$TargetState = "enabled",
    [switch]$OnlyFromReportOnly,
    [switch]$IncludeNonGlobal,
    [string]$LogPath = ""
)

function Resolve-AbsolutePath([string]$Path) {
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Read-JsonAsHashtable([string]$Path) {
    return (Get-Content -Path $Path -Raw | ConvertFrom-Json -AsHashtable)
}

function Get-ManifestSection {
    param(
        [hashtable]$Manifest,
        [string]$Section
    )

    if ($null -eq $Manifest -or -not $Manifest.ContainsKey($Section) -or $null -eq $Manifest[$Section]) {
        return $null
    }

    return $Manifest[$Section]
}

Write-Host "`n--- Ampliosoft Conditional Access Promotion v2026.1 ---" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication")) {
    Write-Host "Microsoft.Graph modules not found. Run module installer first." -ForegroundColor Red
    exit 1
}

Connect-MgGraph -Scopes "Policy.Read.All","Policy.ReadWrite.ConditionalAccess" -NoWelcome
$org = Get-MgOrganization
Write-Host "Connected to: $($org.DisplayName)" -ForegroundColor White
Write-Host "Target state: $TargetState" -ForegroundColor Gray

$manifest = $null
if ($ManifestPath) {
    $ManifestPath = Resolve-AbsolutePath $ManifestPath
    if (-not (Test-Path $ManifestPath)) {
        Write-Host "Manifest not found: $ManifestPath" -ForegroundColor Red
        exit 1
    }
    $manifest = Read-JsonAsHashtable -Path $ManifestPath
    Write-Host "Manifest: $ManifestPath" -ForegroundColor Gray
}

$all = @(Get-MgIdentityConditionalAccessPolicy -All)
$selected = @()

if ($manifest) {
    $waves = Get-ManifestSection -Manifest $manifest -Section "rolloutWaves"
    if ($Wave -and $waves -is [hashtable] -and $waves.ContainsKey($Wave)) {
        $waveConfig = $waves[$Wave]
        if ($waveConfig -is [hashtable] -and $waveConfig.ContainsKey("globalIndexIds")) {
            $GlobalIndexIds = @($waveConfig["globalIndexIds"])
        }
        if ($waveConfig -is [hashtable] -and $waveConfig.ContainsKey("policyNames")) {
            $PolicyNames = @($waveConfig["policyNames"])
        }
        if ($waveConfig -is [hashtable] -and $waveConfig.ContainsKey("targetState") -and $waveConfig["targetState"]) {
            $TargetState = $waveConfig["targetState"]
        }
        if ($waveConfig -is [hashtable] -and $waveConfig.ContainsKey("onlyFromReportOnly")) {
            $OnlyFromReportOnly = [bool]$waveConfig["onlyFromReportOnly"]
        }
    }
}

Write-Host "Wave: $($(if ($Wave) { $Wave } else { 'manual' }))" -ForegroundColor Gray

if ($GlobalIndexIds.Count -gt 0) {
    foreach ($id in $GlobalIndexIds) {
        $pattern = "^GLOBAL - $id - "
        $match = $all | Where-Object { $_.DisplayName -match $pattern }
        if ($match) {
            $selected += $match
        } else {
            Write-Host "No policy found for GLOBAL index $id" -ForegroundColor Yellow
        }
    }
}

if ($PolicyNames.Count -gt 0) {
    foreach ($name in $PolicyNames) {
        $match = $all | Where-Object { $_.DisplayName -eq $name }
        if ($match) {
            $selected += $match
        } else {
            Write-Host "Policy not found: $name" -ForegroundColor Yellow
        }
    }
}

$selected = @($selected | Sort-Object Id -Unique)

if (-not $IncludeNonGlobal) {
    $selected = @($selected | Where-Object { $_.DisplayName -match '^GLOBAL - \d{4} - ' })
}

if ($selected.Count -eq 0) {
    Write-Host "No policies selected. Provide -GlobalIndexIds and/or -PolicyNames." -ForegroundColor Red
    exit 1
}

Write-Host "`nSelected policies:" -ForegroundColor Yellow
$selected | Select-Object DisplayName, State | Format-Table -AutoSize

$results = @()

foreach ($p in $selected) {
    if ($OnlyFromReportOnly -and $p.State -ne "enabledForReportingButNotEnforced") {
        Write-Host "Skip (not report-only): $($p.DisplayName)" -ForegroundColor Gray
        $results += [PSCustomObject]@{ Policy = $p.DisplayName; Action = "Skipped"; Reason = "Not report-only"; PreviousState = $p.State; NewState = $p.State }
        continue
    }

    if ($p.State -eq $TargetState) {
        Write-Host "Skip (already in target state): $($p.DisplayName)" -ForegroundColor Gray
        $results += [PSCustomObject]@{ Policy = $p.DisplayName; Action = "Skipped"; Reason = "Already target state"; PreviousState = $p.State; NewState = $p.State }
        continue
    }

    if ($PSCmdlet.ShouldProcess($p.DisplayName, "Set state to $TargetState")) {
        try {
            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $p.Id -State $TargetState
            Write-Host "Updated: $($p.DisplayName) -> $TargetState" -ForegroundColor Green
            $results += [PSCustomObject]@{ Policy = $p.DisplayName; Action = "Updated"; Reason = ""; PreviousState = $p.State; NewState = $TargetState }
        } catch {
            Write-Host "ERROR updating $($p.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
            $results += [PSCustomObject]@{ Policy = $p.DisplayName; Action = "Error"; Reason = $_.Exception.Message; PreviousState = $p.State; NewState = $p.State }
        }
    }
}

Write-Host "`n--- Promotion summary ---" -ForegroundColor Cyan
$results | Group-Object Action | Sort-Object Name | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
}

if (-not $LogPath) {
    $LogPath = Join-Path (Get-Location).Path "CA-Promote-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}

[PSCustomObject]@{
    timestamp = (Get-Date).ToString("o")
    tenant = $org.DisplayName
    tenantId = $org.Id
    targetState = $TargetState
    onlyFromReportOnly = [bool]$OnlyFromReportOnly
    results = $results
} | ConvertTo-Json -Depth 8 | Out-File -FilePath $LogPath -Encoding utf8

Write-Host "Log written: $LogPath" -ForegroundColor Gray

$errors = @($results | Where-Object { $_.Action -eq "Error" }).Count
if ($errors -gt 0) {
    exit 1
}
