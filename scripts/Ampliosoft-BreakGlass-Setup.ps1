<#
.SYNOPSIS
    Ampliosoft Break-Glass Setup Script — FIDO2 Edition
    Part of package 1.6 (Emergency Recovery Protocol)

.DESCRIPTION
    Creates two cloud-only emergency accounts (AMPLIO-9999-A and AMPLIO-9999-B).
    Generates a strong fallback password for each.
    Assigns permanent Global Administrator (not PIM eligible).
    Outputs credentials for printing on Physical Emergency Protocol cards.

    FIDO2 key registration is performed separately in the browser via TAP
    (see Phase 3 of the 1.6 runbook). This script handles everything except
    the physical key registration step.

.NOTES
    Version:    2026.2
    Author:     Ampliosoft
    Requires:   Microsoft.Graph
    Scopes:     User.ReadWrite.All, Directory.ReadWrite.All,
                RoleManagement.ReadWrite.Directory,
                Policy.ReadWrite.AuthenticationMethod
    WARNING:    Run once per tenant. Print credentials before closing session.
#>

#Requires -Version 7.2

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$ClientName,
    [Parameter(Mandatory)]
    [string]$ClientShortCode
)

Write-Host "`n--- Ampliosoft Break-Glass Setup v2026.2 ---" -ForegroundColor Cyan
Write-Host "Client:     $ClientName" -ForegroundColor White
Write-Host "Short code: $ClientShortCode`n" -ForegroundColor White

Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory","Policy.ReadWrite.AuthenticationMethod","Policy.Read.All" -NoWelcome

# Get onmicrosoft.com domain
$tenantDomain = (Get-MgOrganization).VerifiedDomains |
    Where-Object { $_.Name -like "*.onmicrosoft.com" } |
    Sort-Object IsDefault | Select-Object -First 1 -ExpandProperty Name

Write-Host "Tenant domain: $tenantDomain`n" -ForegroundColor Gray

# Enable TAP
Write-Host "[STEP 1] Enabling Temporary Access Pass..." -ForegroundColor Yellow
$tapBody = @{
    "@odata.type"            = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
    State                    = "enabled"
    DefaultLifetimeInMinutes = 60
    DefaultLength            = 14
    MinimumLifetimeInMinutes = 60
    MaximumLifetimeInMinutes = 480
    IsUsableOnce             = $true
    IncludeTargets           = @(@{ TargetType = "group"; Id = "all_users" })
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "TemporaryAccessPass" `
    -BodyParameter $tapBody
Write-Host "  TAP enabled." -ForegroundColor Green

# Password generator
function New-StrongPassword {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

$accounts = @(
    @{ Label = "A (Primary)"; UPN = "AMPLIO-9999-A-$($ClientShortCode.ToUpper())@$tenantDomain"; Nick = "AMPLIO-9999-A-$($ClientShortCode.ToUpper())" }
    @{ Label = "B (Backup)";  UPN = "AMPLIO-9999-B-$($ClientShortCode.ToUpper())@$tenantDomain"; Nick = "AMPLIO-9999-B-$($ClientShortCode.ToUpper())" }
)

Write-Host ""
Write-Host "[STEP 2] Creating accounts..." -ForegroundColor Yellow

$created = @()

foreach ($acct in $accounts) {
    $existing = Get-MgUser -Filter "UserPrincipalName eq '$($acct.UPN)'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Account $($acct.Label) already exists: $($acct.UPN)" -ForegroundColor Yellow
        $created += @{ UPN = $acct.UPN; Id = $existing.Id; Password = "EXISTING — check records"; Label = $acct.Label }
        continue
    }
    $pw   = New-StrongPassword
    $user = New-MgUser `
        -DisplayName "Ampliosoft Emergency $($acct.Label) — $ClientName" `
        -UserPrincipalName $acct.UPN `
        -MailNickname $acct.Nick `
        -AccountEnabled $true `
        -UsageLocation "SE" `
        -PasswordProfile @{ Password = $pw; ForceChangePasswordNextSignIn = $false }

    Write-Host "  Created: $($acct.UPN)" -ForegroundColor Green
    $created += @{ UPN = $acct.UPN; Id = $user.Id; Password = $pw; Label = $acct.Label }
}

# Assign Global Administrator — permanent active, not PIM eligible
Write-Host ""
Write-Host "[STEP 3] Assigning Global Administrator (permanent, not PIM eligible)..." -ForegroundColor Yellow
$gaRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
if (-not $gaRole) {
    $t = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "Global Administrator" }
    Enable-MgDirectoryRole -RoleTemplateId $t.Id | Out-Null
    $gaRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
}
foreach ($acct in $created) {
    New-MgDirectoryRoleMemberByRef -DirectoryRoleId $gaRole.Id -BodyParameter @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($acct.Id)"
    } | Out-Null
    Write-Host "  Global Admin assigned: $($acct.UPN)" -ForegroundColor Green
}

# CA exclusion check
Write-Host ""
Write-Host "[STEP 4] Checking Conditional Access exclusions..." -ForegroundColor Yellow
$bgIds    = $created.Id
$policies = Get-MgIdentityConditionalAccessPolicy
$issues   = 0
foreach ($policy in $policies) {
    if ($policy.Conditions.Users.IncludeUsers -contains "All") {
        foreach ($id in $bgIds) {
            if ($policy.Conditions.Users.ExcludeUsers -notcontains $id) {
                Write-Host "  NOT EXCLUDED: $($policy.DisplayName)" -ForegroundColor Red
                $issues++
            }
        }
    }
}
if ($issues -eq 0) {
    Write-Host "  Both accounts excluded from all applicable CA policies." -ForegroundColor Green
} else {
    Write-Host "  ACTION REQUIRED: Add exclusions to $issues policies above before enabling them." -ForegroundColor Yellow
}

# Print fallback passwords
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  FALLBACK PASSWORDS — PRINT NOW" -ForegroundColor Cyan
Write-Host "  Store each password with its corresponding FIDO2 key." -ForegroundColor White
Write-Host "  These will not be shown again after this session." -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Cyan
foreach ($acct in $created) {
    Write-Host ""
    Write-Host "  Account $($acct.Label)" -ForegroundColor White
    Write-Host "  UPN:      $($acct.UPN)" -ForegroundColor Gray
    Write-Host "  Password: $($acct.Password)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  NEXT STEPS (see 1.6 runbook Phase 3):" -ForegroundColor White
Write-Host "  For each account, generate a TAP and register the FIDO2 key" -ForegroundColor Gray
Write-Host "  via https://aka.ms/mysecurityinfo in a private browser window." -ForegroundColor Gray
Write-Host ""
Read-Host "  Press Enter once passwords are printed and secured"

Write-Host "`n--- Break-glass account setup complete ---`n" -ForegroundColor Green
