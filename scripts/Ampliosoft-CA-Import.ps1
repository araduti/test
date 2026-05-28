<#
.SYNOPSIS
    Ampliosoft Conditional Access Import Script

.DESCRIPTION
    Imports Conditional Access named locations and policies from
    00-core-toolkit/policies/conditional-access into a client tenant.

    Design goals:
    - Idempotent: create missing objects, update existing by display name
    - Safe by default: report-only deployment state unless overridden
    - Deterministic: explicit source-to-target reference mapping

    The script supports a reference map JSON file for tenant-specific IDs:
      users, groups, namedLocations, applications, servicePrincipals, termsOfUse

.NOTES
    Version: 2026.1
    Author: Ampliosoft
    Requires: Microsoft.Graph
    Scopes: Policy.Read.All, Policy.ReadWrite.ConditionalAccess, User.Read.All
#>

#Requires -Version 7.2

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$PoliciesRoot = (Join-Path $PSScriptRoot ".." "policies" "conditional-access"),
    [string]$ManifestPath = "",
    [string]$ReferenceMapPath = "",
    [string[]]$BreakGlassObjectIds = @(),
    [ValidateSet("reportOnly", "enabled", "disabled", "preserve")]
    [string]$DefaultState = "reportOnly",
    [switch]$SkipNamedLocations,
    [switch]$SkipPolicies,
    [switch]$FailOnUnresolvedReferences = $true,
    [switch]$IncludeNonStandard,
    [string]$LogPath = ""
)

function Resolve-AbsolutePath([string]$Path) {
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Get-SafeMapSection {
    param(
        [hashtable]$Map,
        [string]$Key
    )

    if ($null -eq $Map -or -not $Map.ContainsKey($Key) -or $null -eq $Map[$Key]) {
        return @{}
    }

    if ($Map[$Key] -is [hashtable]) {
        return $Map[$Key]
    }

    return @{}
}

function Test-IsGuidLike([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Value -match '^[0-9a-fA-F\-]{36}$'
}

function Resolve-IdArray {
    param(
        [object[]]$Values,
        [hashtable]$Map,
        [string]$Context,
        [ref]$Unresolved
    )

    if ($null -eq $Values) {
        return $null
    }

    $resolved = @()
    foreach ($v in $Values) {
        if ($v -eq "All" -or -not (Test-IsGuidLike -Value "$v")) {
            $resolved += $v
            continue
        }

        if ($Map.ContainsKey("$v")) {
            $resolved += $Map["$v"]
            continue
        }

        $Unresolved.Value += "[$Context] $v"
        $resolved += $v
    }

    return $resolved
}

function Convert-State {
    param(
        [string]$State,
        [string]$DefaultState
    )

    if ($DefaultState -eq "preserve") {
        return $State
    }

    switch ($DefaultState) {
        "reportOnly" { return "enabledForReportingButNotEnforced" }
        "enabled"    { return "enabled" }
        "disabled"   { return "disabled" }
        default       { return $State }
    }
}

function Remove-KeysIfPresent {
    param(
        [hashtable]$Object,
        [string[]]$Keys
    )

    foreach ($k in $Keys) {
        if ($Object.ContainsKey($k)) {
            $Object.Remove($k)
        }
    }
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

function Get-TenantSkuNames {
    $skuNames = @()
    try {
        $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop)
        foreach ($sku in $skus) {
            if ($sku.SkuPartNumber) {
                $skuNames += $sku.SkuPartNumber
            }
        }
    } catch {
        Write-Host "Unable to read subscribed SKUs: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    return @($skuNames | Sort-Object -Unique)
}

function Test-LicenseCoverage {
    param(
        [string[]]$SkuNames,
        [string[]]$RequiredSkus
    )

    if ($RequiredSkus.Count -eq 0) {
        return $true
    }

    foreach ($required in $RequiredSkus) {
        if ($SkuNames -contains $required) {
            return $true
        }
    }

    return $false
}

Write-Host "`n--- Ampliosoft Conditional Access Import v2026.1 ---" -ForegroundColor Cyan

$PoliciesRoot = Resolve-AbsolutePath $PoliciesRoot
if (-not (Test-Path $PoliciesRoot)) {
    Write-Host "Policies root not found: $PoliciesRoot" -ForegroundColor Red
    exit 1
}

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

$map = @{}
if ($manifest) {
    $manifestReferenceMapPath = Get-ManifestSection -Manifest $manifest -Section "referenceMapPath"
    if ($manifestReferenceMapPath) {
        $ReferenceMapPath = $manifestReferenceMapPath
    }

    $manifestReferenceMap = Get-ManifestSection -Manifest $manifest -Section "referenceMap"
    if ($manifestReferenceMap -is [hashtable]) {
        $map = $manifestReferenceMap
    }
}

if ($ReferenceMapPath) {
    $ReferenceMapPath = Resolve-AbsolutePath $ReferenceMapPath
    if (-not (Test-Path $ReferenceMapPath)) {
        Write-Host "Reference map not found: $ReferenceMapPath" -ForegroundColor Red
        exit 1
    }
    $map = Read-JsonAsHashtable -Path $ReferenceMapPath
}

if ($manifest) {
    $manifestDeployment = Get-ManifestSection -Manifest $manifest -Section "deployment"
    if ($manifestDeployment -is [hashtable]) {
        if ($manifestDeployment.ContainsKey("defaultState") -and $manifestDeployment["defaultState"]) {
            $DefaultState = $manifestDeployment["defaultState"]
        }
        if ($manifestDeployment.ContainsKey("breakGlassObjectIds") -and $manifestDeployment["breakGlassObjectIds"]) {
            $BreakGlassObjectIds = @($manifestDeployment["breakGlassObjectIds"])
        }
    }
}

if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication")) {
    Write-Host "Microsoft.Graph modules not found. Run module installer first." -ForegroundColor Red
    exit 1
}

Connect-MgGraph -Scopes "Policy.Read.All","Policy.ReadWrite.ConditionalAccess","User.Read.All" -NoWelcome
$org = Get-MgOrganization
$skuNames = Get-TenantSkuNames
Write-Host "Connected to: $($org.DisplayName)" -ForegroundColor White
Write-Host "Policies root: $PoliciesRoot" -ForegroundColor Gray
Write-Host "Default state: $DefaultState" -ForegroundColor Gray
if ($skuNames.Count -gt 0) {
    Write-Host "Tenant SKUs: $($skuNames -join ', ')" -ForegroundColor Gray
}

if ($BreakGlassObjectIds.Count -eq 0) {
    $bgUsers = Get-MgUser -Filter "startsWith(UserPrincipalName,'AMPLIO-9999')" -ErrorAction SilentlyContinue
    if ($bgUsers) {
        $BreakGlassObjectIds = @($bgUsers | Select-Object -ExpandProperty Id)
    }
}

if ($BreakGlassObjectIds.Count -gt 0) {
    Write-Host "Break-glass IDs detected: $($BreakGlassObjectIds -join ', ')" -ForegroundColor Gray
} else {
    Write-Host "No break-glass IDs supplied or discovered. Exclusion checks may fail." -ForegroundColor Yellow
}

$namedLocationMap = Get-SafeMapSection -Map $map -Key "namedLocations"
$usersMap = Get-SafeMapSection -Map $map -Key "users"
$groupsMap = Get-SafeMapSection -Map $map -Key "groups"
$appMap = Get-SafeMapSection -Map $map -Key "applications"
$spMap = Get-SafeMapSection -Map $map -Key "servicePrincipals"
$termsMap = Get-SafeMapSection -Map $map -Key "termsOfUse"

$results = @()
$unresolvedGlobal = @()
$policyToggles = @{}
if ($manifest) {
    $maybeToggles = Get-ManifestSection -Manifest $manifest -Section "policyToggles"
    if ($maybeToggles -is [hashtable]) {
        $policyToggles = $maybeToggles
    }
}

$preflight = @()
$preflight += [PSCustomObject]@{ Check = "PoliciesRoot"; Status = "OK"; Detail = $PoliciesRoot }
$preflight += [PSCustomObject]@{ Check = "ReferenceMap"; Status = $(if ($map.Count -gt 0) { "OK" } else { "Warn" }); Detail = "Sections: users/groups/namedLocations/applications/servicePrincipals/termsOfUse" }
$preflight += [PSCustomObject]@{ Check = "BreakGlass"; Status = $(if ($BreakGlassObjectIds.Count -gt 0) { "OK" } else { "Warn" }); Detail = "Count: $($BreakGlassObjectIds.Count)" }
$preflight += [PSCustomObject]@{ Check = "Manifest"; Status = $(if ($manifest) { "OK" } else { "Info" }); Detail = $(if ($manifest) { $ManifestPath } else { "Not supplied" }) }

$selectedPolicyFiles = @()
if (-not $SkipPolicies) {
    $selectedPolicyFiles = @(Get-ChildItem -Path $PoliciesRoot -Filter "*.json" | Where-Object { $_.Name -ne "_index.json" })
    if (-not $IncludeNonStandard) {
        $selectedPolicyFiles = @($selectedPolicyFiles | Where-Object { $_.BaseName -notlike "NON-STANDARD-*" })
    }
}

$selectedPolicyNames = @()
foreach ($file in $selectedPolicyFiles) {
    try {
        $candidate = Read-JsonAsHashtable -Path $file.FullName
        if ($candidate.ContainsKey("displayName") -and $candidate["displayName"]) {
            $selectedPolicyNames += $candidate["displayName"]
        }
    } catch {
        continue
    }
}

$selectedPolicyNames = @($selectedPolicyNames | Sort-Object -Unique)
$needsP2 = $selectedPolicyNames | Where-Object { $_ -match '^GLOBAL - (1090|1100|2010|2020) - ' }
$needsGsa = $selectedPolicyNames | Where-Object { $_ -match '^GLOBAL - 4020 - ' }

if ($needsP2) {
    $p2Present = Test-LicenseCoverage -SkuNames $skuNames -RequiredSkus @('ENTERPRISEPREMIUM','EMS','EMS_E5','AAD_PREMIUM_P2','M365_E5')
    $preflight += [PSCustomObject]@{ Check = "License:P2"; Status = $(if ($p2Present) { "OK" } else { "Fail" }); Detail = "Risk-based controls selected: $($needsP2.Count) policies" }
}

if ($needsGsa) {
    $preflight += [PSCustomObject]@{ Check = "Prereq:GSA"; Status = "Warn"; Detail = "GLOBAL-4020 selected; confirm Entra Internet Access / Global Secure Access before promotion." }
}

$manifestRequiresWhatIf = $false
if ($manifest) {
    $deploymentSection = Get-ManifestSection -Manifest $manifest -Section "deployment"
    if ($deploymentSection -is [hashtable] -and $deploymentSection.ContainsKey("requireWhatIfFirst")) {
        $manifestRequiresWhatIf = [bool]$deploymentSection["requireWhatIfFirst"]
    }
    if ($manifestRequiresWhatIf -and -not $WhatIfPreference) {
        $preflight += [PSCustomObject]@{ Check = "Manifest:WhatIf"; Status = "Warn"; Detail = "Manifest requests a WhatIf-first rollout. Run with -WhatIf before apply." }
    }
}

Write-Host "`nPreflight checks:" -ForegroundColor Yellow
$preflight | Format-Table -AutoSize

if ($preflight | Where-Object { $_.Status -eq 'Fail' }) {
    Write-Host "Preflight failed. Resolve the failed checks before importing." -ForegroundColor Red
    exit 1
}

# 1) Import named locations first so location IDs can be remapped for policies.
if (-not $SkipNamedLocations) {
    $nlPath = Join-Path $PoliciesRoot "named-locations"
    if (Test-Path $nlPath) {
        Write-Host "`nImporting named locations..." -ForegroundColor Yellow

        $existingNls = @(Get-MgIdentityConditionalAccessNamedLocation -All)
        $nlFiles = Get-ChildItem -Path $nlPath -Filter "*.json" | Sort-Object Name

        foreach ($f in $nlFiles) {
            $raw = Read-JsonAsHashtable -Path $f.FullName
            $meta = $raw["_ampliosoft_export_metadata"]
            Remove-KeysIfPresent -Object $raw -Keys @("_ampliosoft_export_metadata", "id", "createdDateTime", "modifiedDateTime")

            $displayName = $raw["displayName"]
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                Write-Host "  SKIP $($f.Name): missing displayName" -ForegroundColor Yellow
                $results += [PSCustomObject]@{ Type = "NamedLocation"; Name = $f.Name; Action = "Skipped"; Reason = "Missing displayName" }
                continue
            }

            if ($policyToggles.ContainsKey($displayName) -and $policyToggles[$displayName] -is [hashtable]) {
                $toggle = $policyToggles[$displayName]
                if ($toggle.ContainsKey("enabled") -and -not [bool]$toggle["enabled"]) {
                    Write-Host "  SKIP $displayName: disabled in manifest" -ForegroundColor DarkGray
                    $results += [PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Skipped"; Reason = "Disabled in manifest" }
                    continue
                }
            }

            $existing = $existingNls | Where-Object { $_.DisplayName -eq $displayName } | Select-Object -First 1
            if ($existing) {
                Write-Host "  Exists: $displayName" -ForegroundColor Gray
                if ($meta -and $meta.ContainsKey("namedLocationId") -and (Test-IsGuidLike -Value "$($meta.namedLocationId)")) {
                    $namedLocationMap["$($meta.namedLocationId)"] = $existing.Id
                }
                $results += [PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Found"; Reason = "Already exists" }
                continue
            }

            if ($PSCmdlet.ShouldProcess($displayName, "Create named location")) {
                try {
                    $created = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $raw
                    if ($meta -and $meta.ContainsKey("namedLocationId") -and (Test-IsGuidLike -Value "$($meta.namedLocationId)")) {
                        $namedLocationMap["$($meta.namedLocationId)"] = $created.Id
                    }
                    Write-Host "  Created: $displayName" -ForegroundColor Green
                    $results += [PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Created"; Reason = "" }
                } catch {
                    Write-Host "  ERROR creating $displayName: $($_.Exception.Message)" -ForegroundColor Red
                    $results += [PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Error"; Reason = $_.Exception.Message }
                }
            }
        }
    } else {
        Write-Host "`nNo named-locations folder found. Skipping named location import." -ForegroundColor Gray
    }
}

# 2) Import policies.
if (-not $SkipPolicies) {
    Write-Host "`nImporting policies..." -ForegroundColor Yellow

    $policyFiles = Get-ChildItem -Path $PoliciesRoot -Filter "*.json" |
        Where-Object { $_.Name -ne "_index.json" }

    if (-not $IncludeNonStandard) {
        $policyFiles = $policyFiles | Where-Object { $_.BaseName -notlike "NON-STANDARD-*" }
    }

    $policyFiles = $policyFiles | Sort-Object Name
    $existingPolicies = @(Get-MgIdentityConditionalAccessPolicy -All)

    foreach ($file in $policyFiles) {
        $unresolved = @()
        $raw = Read-JsonAsHashtable -Path $file.FullName

        Remove-KeysIfPresent -Object $raw -Keys @("_ampliosoft_export_metadata", "id", "createdDateTime", "modifiedDateTime")

        $displayName = $raw["displayName"]
        if ([string]::IsNullOrWhiteSpace($displayName)) {
            Write-Host "  SKIP $($file.Name): missing displayName" -ForegroundColor Yellow
            $results += [PSCustomObject]@{ Type = "Policy"; Name = $file.Name; Action = "Skipped"; Reason = "Missing displayName" }
            continue
        }

        if ($policyToggles.ContainsKey($displayName) -and $policyToggles[$displayName] -is [hashtable]) {
            $toggle = $policyToggles[$displayName]
            if ($toggle.ContainsKey("enabled") -and -not [bool]$toggle["enabled"]) {
                Write-Host "  SKIP $displayName: disabled in manifest" -ForegroundColor DarkGray
                $results += [PSCustomObject]@{ Type = "Policy"; Name = $displayName; Action = "Skipped"; Reason = "Disabled in manifest" }
                continue
            }
            if ($toggle.ContainsKey("state") -and $toggle["state"]) {
                $raw["state"] = $toggle["state"]
            }
        }

        # Force deployment state unless preserve requested.
        $raw["state"] = Convert-State -State $raw["state"] -DefaultState $DefaultState

        # Resolve references in policy conditions and grant controls.
        if ($raw.ContainsKey("conditions")) {
            $conditions = $raw["conditions"]

            if ($conditions.ContainsKey("Users") -and $conditions["Users"] -is [hashtable]) {
                $users = $conditions["Users"]

                if ($users.ContainsKey("ExcludeUsers") -and $users["ExcludeUsers"] -ne $null) {
                    $users["ExcludeUsers"] = @(Resolve-IdArray -Values $users["ExcludeUsers"] -Map $usersMap -Context "$displayName Users.ExcludeUsers" -Unresolved ([ref]$unresolved))
                }
                if ($users.ContainsKey("IncludeUsers") -and $users["IncludeUsers"] -ne $null) {
                    $users["IncludeUsers"] = @(Resolve-IdArray -Values $users["IncludeUsers"] -Map $usersMap -Context "$displayName Users.IncludeUsers" -Unresolved ([ref]$unresolved))
                }
                if ($users.ContainsKey("ExcludeGroups") -and $users["ExcludeGroups"] -ne $null) {
                    $users["ExcludeGroups"] = @(Resolve-IdArray -Values $users["ExcludeGroups"] -Map $groupsMap -Context "$displayName Users.ExcludeGroups" -Unresolved ([ref]$unresolved))
                }
                if ($users.ContainsKey("IncludeGroups") -and $users["IncludeGroups"] -ne $null) {
                    $users["IncludeGroups"] = @(Resolve-IdArray -Values $users["IncludeGroups"] -Map $groupsMap -Context "$displayName Users.IncludeGroups" -Unresolved ([ref]$unresolved))
                }

                # Ensure break-glass exclusions are present for all-users policies.
                if ($BreakGlassObjectIds.Count -gt 0 -and $users.ContainsKey("IncludeUsers") -and @($users["IncludeUsers"]) -contains "All") {
                    if (-not $users.ContainsKey("ExcludeUsers") -or $null -eq $users["ExcludeUsers"]) {
                        $users["ExcludeUsers"] = @()
                    }
                    foreach ($bg in $BreakGlassObjectIds) {
                        if (@($users["ExcludeUsers"]) -notcontains $bg) {
                            $users["ExcludeUsers"] += $bg
                        }
                    }
                    $users["ExcludeUsers"] = @($users["ExcludeUsers"] | Select-Object -Unique)
                }
            }

            if ($conditions.ContainsKey("Locations") -and $conditions["Locations"] -is [hashtable]) {
                $locs = $conditions["Locations"]
                if ($locs.ContainsKey("ExcludeLocations") -and $locs["ExcludeLocations"] -ne $null) {
                    $locs["ExcludeLocations"] = @(Resolve-IdArray -Values $locs["ExcludeLocations"] -Map $namedLocationMap -Context "$displayName Locations.ExcludeLocations" -Unresolved ([ref]$unresolved))
                }
                if ($locs.ContainsKey("IncludeLocations") -and $locs["IncludeLocations"] -ne $null) {
                    $locs["IncludeLocations"] = @(Resolve-IdArray -Values $locs["IncludeLocations"] -Map $namedLocationMap -Context "$displayName Locations.IncludeLocations" -Unresolved ([ref]$unresolved))
                }
            }

            if ($conditions.ContainsKey("Applications") -and $conditions["Applications"] -is [hashtable]) {
                $apps = $conditions["Applications"]
                if ($apps.ContainsKey("IncludeApplications") -and $apps["IncludeApplications"] -ne $null) {
                    $apps["IncludeApplications"] = @(Resolve-IdArray -Values $apps["IncludeApplications"] -Map $appMap -Context "$displayName Applications.IncludeApplications" -Unresolved ([ref]$unresolved))
                }
                if ($apps.ContainsKey("ExcludeApplications") -and $apps["ExcludeApplications"] -ne $null) {
                    $apps["ExcludeApplications"] = @(Resolve-IdArray -Values $apps["ExcludeApplications"] -Map $appMap -Context "$displayName Applications.ExcludeApplications" -Unresolved ([ref]$unresolved))
                }
            }

            if ($conditions.ContainsKey("ClientApplications") -and $conditions["ClientApplications"] -is [hashtable]) {
                $cas = $conditions["ClientApplications"]
                if ($cas.ContainsKey("IncludeServicePrincipals") -and $cas["IncludeServicePrincipals"] -ne $null) {
                    $cas["IncludeServicePrincipals"] = @(Resolve-IdArray -Values $cas["IncludeServicePrincipals"] -Map $spMap -Context "$displayName ClientApplications.IncludeServicePrincipals" -Unresolved ([ref]$unresolved))
                }
                if ($cas.ContainsKey("ExcludeServicePrincipals") -and $cas["ExcludeServicePrincipals"] -ne $null) {
                    $cas["ExcludeServicePrincipals"] = @(Resolve-IdArray -Values $cas["ExcludeServicePrincipals"] -Map $spMap -Context "$displayName ClientApplications.ExcludeServicePrincipals" -Unresolved ([ref]$unresolved))
                }
            }
        }

        if ($raw.ContainsKey("grantControls") -and $raw["grantControls"] -is [hashtable]) {
            $grants = $raw["grantControls"]
            if ($grants.ContainsKey("TermsOfUse") -and $grants["TermsOfUse"] -ne $null) {
                $grants["TermsOfUse"] = @(Resolve-IdArray -Values $grants["TermsOfUse"] -Map $termsMap -Context "$displayName GrantControls.TermsOfUse" -Unresolved ([ref]$unresolved))
            }
        }

        if ($unresolved.Count -gt 0) {
            $unresolvedGlobal += $unresolved
            $msg = "Unresolved references: $($unresolved -join '; ')"
            if ($FailOnUnresolvedReferences) {
                Write-Host "  SKIP $displayName: $msg" -ForegroundColor Red
                $results += [PSCustomObject]@{ Type = "Policy"; Name = $displayName; Action = "Skipped"; Reason = $msg }
                continue
            }
            Write-Host "  WARN $displayName: $msg" -ForegroundColor Yellow
        }

        if ($raw["state"] -eq "enabled" -and $DefaultState -eq "reportOnly") {
            Write-Host "  INFO $displayName: manifest or source requested enabled; import keeps explicit state" -ForegroundColor DarkYellow
        }

        $existing = $existingPolicies | Where-Object { $_.DisplayName -eq $displayName } | Select-Object -First 1

        if ($existing) {
            if ($PSCmdlet.ShouldProcess($displayName, "Update policy")) {
                try {
                    Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $existing.Id -BodyParameter $raw
                    Write-Host "  Updated: $displayName" -ForegroundColor Green
                    $results += [PSCustomObject]@{ Type = "Policy"; Name = $displayName; Action = "Updated"; Reason = "" }
                } catch {
                    Write-Host "  ERROR updating $displayName: $($_.Exception.Message)" -ForegroundColor Red
                    $results += [PSCustomObject]@{ Type = "Policy"; Name = $displayName; Action = "Error"; Reason = $_.Exception.Message }
                }
            }
        } else {
            if ($PSCmdlet.ShouldProcess($displayName, "Create policy")) {
                try {
                    New-MgIdentityConditionalAccessPolicy -BodyParameter $raw | Out-Null
                    Write-Host "  Created: $displayName" -ForegroundColor Green
                    $results += [PSCustomObject]@{ Type = "Policy"; Name = $displayName; Action = "Created"; Reason = "" }
                } catch {
                    Write-Host "  ERROR creating $displayName: $($_.Exception.Message)" -ForegroundColor Red
                    $results += [PSCustomObject]@{ Type = "Policy"; Name = $displayName; Action = "Error"; Reason = $_.Exception.Message }
                }
            }
        }
    }
}

Write-Host "`n--- Import summary ---" -ForegroundColor Cyan
$results | Group-Object Type, Action | Sort-Object Name | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
}

if ($unresolvedGlobal.Count -gt 0) {
    Write-Host "`nUnresolved references encountered:" -ForegroundColor Yellow
    $unresolvedGlobal | Select-Object -Unique | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

if (-not $LogPath) {
    $LogPath = Join-Path (Get-Location).Path "CA-Import-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
} else {
    $LogPath = Resolve-AbsolutePath $LogPath
}

$log = [PSCustomObject]@{
    timestamp = (Get-Date).ToString("o")
    tenant = $org.DisplayName
    tenantId = $org.Id
    policiesRoot = $PoliciesRoot
    manifestPath = $ManifestPath
    defaultState = $DefaultState
    preflight = $preflight
    skipNamedLocations = [bool]$SkipNamedLocations
    skipPolicies = [bool]$SkipPolicies
    failOnUnresolvedReferences = [bool]$FailOnUnresolvedReferences
    results = $results
    unresolvedReferences = ($unresolvedGlobal | Select-Object -Unique)
}

$log | ConvertTo-Json -Depth 8 | Out-File -FilePath $LogPath -Encoding utf8
Write-Host "Log written: $LogPath" -ForegroundColor Gray

$errors = @($results | Where-Object { $_.Action -eq "Error" }).Count
if ($errors -gt 0) {
    exit 1
}

if ($FailOnUnresolvedReferences -and $unresolvedGlobal.Count -gt 0) {
    exit 1
}
