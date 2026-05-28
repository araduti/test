<#
.SYNOPSIS
    Chirita-law Break-Glass Setup Script — FIDO2 Edition
    Part of package 1.6 (Emergency Recovery Protocol)

.DESCRIPTION
    Creates two cloud-only emergency accounts (ACC-9999-A and ACC-9999-B).
    Generates a strong fallback password for each.
    Assigns permanent Global Administrator (not PIM eligible).
    Outputs credentials for printing on Physical Emergency Protocol cards.

    FIDO2 key registration is performed separately in the browser via TAP
    (see Phase 3 of the 1.6 runbook). This script handles everything except
    the physical key registration step.

.NOTES
    Version:    2026.2
    Author:     Accesa
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

Write-Host "`n--- Chirita-law Break-Glass Setup v2026.2 ---" -ForegroundColor Cyan
Write-Host "Client:     $ClientName" -ForegroundColor White
Write-Host "Short code: $ClientShortCode`n" -ForegroundColor White

Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Policy.ReadWrite.AuthenticationMethod", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess" -NoWelcome

# Get onmicrosoft.com domain
$tenantDomain = (Get-MgOrganization).VerifiedDomains |
Where-Object { $_.Name -like "*.onmicrosoft.com" -and $_.Name -notlike "*.mail.onmicrosoft.com" } |
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
  @{ Label = "A (Primary)"; UPN = "ACC-9999-A-$($ClientShortCode.ToUpper())@$tenantDomain"; Nick = "ACC-9999-A-$($ClientShortCode.ToUpper())" }
  @{ Label = "B (Backup)"; UPN = "ACC-9999-B-$($ClientShortCode.ToUpper())@$tenantDomain"; Nick = "ACC-9999-B-$($ClientShortCode.ToUpper())" }
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
  $pw = New-StrongPassword
  $user = New-MgUser `
    -DisplayName "Chirita-law Emergency $($acct.Label) — $ClientName" `
    -UserPrincipalName $acct.UPN `
    -MailNickname $acct.Nick `
    -AccountEnabled:$true `
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
$gaMemberIds = (Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All).Id
foreach ($acct in $created) {
  if ($gaMemberIds -contains $acct.Id) {
    Write-Host "  Already Global Admin: $($acct.UPN)" -ForegroundColor Yellow
    continue
  }
  try {
    New-MgDirectoryRoleMemberByRef -DirectoryRoleId $gaRole.Id -BodyParameter @{
      "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($acct.Id)"
    } -ErrorAction Stop | Out-Null
    Write-Host "  Global Admin assigned: $($acct.UPN)" -ForegroundColor Green
  }
  catch {
    Write-Host "  FAILED to assign Global Admin: $($acct.UPN) — $($_.Exception.Message)" -ForegroundColor Red
  }
}

# CA exclusion check + auto-apply
Write-Host ""
Write-Host "[STEP 4] Checking and applying Conditional Access exclusions..." -ForegroundColor Yellow
$bgIds = @($created.Id)
$policies = Get-MgIdentityConditionalAccessPolicy
$updated = 0
$failed = 0
foreach ($policy in $policies) {
  if ($policy.Conditions.Users.IncludeUsers -contains "All") {
    $missing = $bgIds | Where-Object { $policy.Conditions.Users.ExcludeUsers -notcontains $_ }
    if ($missing) {
      $newExclusions = @(@($policy.Conditions.Users.ExcludeUsers) + @($missing) | Select-Object -Unique)
      try {
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter @{
          Conditions = @{
            Users = @{
              IncludeUsers  = @($policy.Conditions.Users.IncludeUsers)
              ExcludeUsers  = $newExclusions
              IncludeGroups = @($policy.Conditions.Users.IncludeGroups)
              ExcludeGroups = @($policy.Conditions.Users.ExcludeGroups)
              IncludeRoles  = @($policy.Conditions.Users.IncludeRoles)
              ExcludeRoles  = @($policy.Conditions.Users.ExcludeRoles)
            }
          }
        } -ErrorAction Stop
        Write-Host "  EXCLUDED: $($policy.DisplayName)" -ForegroundColor Green
        $updated++
      }
      catch {
        Write-Host "  FAILED:   $($policy.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
        $failed++
      }
    }
  }
}
if ($updated -eq 0 -and $failed -eq 0) {
  Write-Host "  Both accounts were already excluded from all applicable CA policies." -ForegroundColor Green
}
else {
  if ($updated -gt 0) { Write-Host "  Exclusions applied to $updated policies." -ForegroundColor Green }
  if ($failed -gt 0) { Write-Host "  ACTION REQUIRED: $failed policies could not be updated — add exclusions manually." -ForegroundColor Yellow }
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
Clear-Host
Write-Host "Passwords cleared from view. Close this terminal window to wipe scrollback." -ForegroundColor Yellow
Write-Host "`n--- Break-glass account setup complete ---`n" -ForegroundColor Green