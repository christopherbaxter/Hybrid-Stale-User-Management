#Requires -Version 5.1

<#
.SYNOPSIS
Creates review-only stale-user reports for Active Directory and Microsoft Entra ID.

.DESCRIPTION
This script reads users from every domain in the current Active Directory forest,
optionally enriches them with Microsoft Entra ID sign-in data, applies safety
checks and exclusions, and exports CSV reports. It does not change any account.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$StaleAfterDays = 90,

    [ValidateRange(1, 3650)]
    [int]$DisabledReviewAfterDays = 90,

    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\output'),

    [string]$ExclusionsPath = (Join-Path -Path $PSScriptRoot -ChildPath 'UserExclusions.csv'),

    [switch]$SkipMicrosoftGraph
)

$ErrorActionPreference = 'Stop'
$RunDate = Get-Date
$StaleCutoff = $RunDate.Date.AddDays(-$StaleAfterDays)
$DisabledCutoff = $RunDate.Date.AddDays(-$DisabledReviewAfterDays)

Import-Module ActiveDirectory -ErrorAction Stop
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$OutputPath = (Resolve-Path -Path $OutputPath).Path

# Optional exclusions. Required column: SamAccountName.
$Exclusions = @{}
if (Test-Path -LiteralPath $ExclusionsPath) {
    foreach ($Entry in (Import-Csv -LiteralPath $ExclusionsPath)) {
        if (-not [string]::IsNullOrWhiteSpace($Entry.SamAccountName)) {
            $Key = $Entry.SamAccountName.Trim().ToLowerInvariant()
            $Exclusions[$Key] = $Entry
        }
    }
}

# Microsoft Entra users are indexed by normalized UPN. Multiple matches are kept
# so that ambiguous correlations can be sent to manual review.
$GraphUsersByUpn = @{}
$GraphAvailable = $false
if (-not $SkipMicrosoftGraph) {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop

    Connect-MgGraph -Scopes 'User.Read.All', 'AuditLog.Read.All'
    try {
        $GraphProperties = @(
            'id'
            'displayName'
            'userPrincipalName'
            'accountEnabled'
            'onPremisesSyncEnabled'
            'signInActivity'
        )

        $GraphUsers = @(Get-MgUser -All -Property $GraphProperties)
        foreach ($GraphUser in $GraphUsers) {
            if ([string]::IsNullOrWhiteSpace($GraphUser.UserPrincipalName)) {
                continue
            }

            $Key = $GraphUser.UserPrincipalName.Trim().ToLowerInvariant()
            if (-not $GraphUsersByUpn.ContainsKey($Key)) {
                $GraphUsersByUpn[$Key] = @()
            }
            $GraphUsersByUpn[$Key] += $GraphUser
        }
        $GraphAvailable = $true
    }
    finally {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

$Forest = Get-ADForest
$Results = [System.Collections.Generic.List[object]]::new()

foreach ($Domain in $Forest.Domains) {
    $DomainController = Get-ADDomainController -Discover -DomainName $Domain -Writable
    Write-Host "Reading users from $Domain"

    $ADUsers = Get-ADUser -Server $DomainController.HostName -Filter * -Properties @(
        'UserPrincipalName'
        'Mail'
        'Enabled'
        'WhenCreated'
        'WhenChanged'
        'pwdLastSet'
        'lastLogonTimestamp'
        'ObjectGUID'
        'ObjectSID'
        'adminCount'
        'isCriticalSystemObject'
        'ServicePrincipalName'
    )

    foreach ($ADUser in $ADUsers) {
        $Upn = $null
        if (-not [string]::IsNullOrWhiteSpace($ADUser.UserPrincipalName)) {
            $Upn = $ADUser.UserPrincipalName.Trim().ToLowerInvariant()
        }

        $ADLastLogon = $null
        if ([int64]$ADUser.lastLogonTimestamp -gt 0) {
            $ADLastLogon = [DateTime]::FromFileTimeUtc([int64]$ADUser.lastLogonTimestamp).ToLocalTime()
        }

        $ADPasswordLastSet = $null
        if ([int64]$ADUser.pwdLastSet -gt 0) {
            $ADPasswordLastSet = [DateTime]::FromFileTimeUtc([int64]$ADUser.pwdLastSet).ToLocalTime()
        }

        $GraphMatches = @()
        if ($GraphAvailable -and $Upn -and $GraphUsersByUpn.ContainsKey($Upn)) {
            $GraphMatches = @($GraphUsersByUpn[$Upn])
        }

        $GraphUser = $null
        $EntraLastSuccessfulSignIn = $null
        if ($GraphMatches.Count -eq 1) {
            $GraphUser = $GraphMatches[0]
            if ($GraphUser.SignInActivity.LastSuccessfulSignInDateTime) {
                $EntraLastSuccessfulSignIn = [DateTime]$GraphUser.SignInActivity.LastSuccessfulSignInDateTime
            }
        }

        $Reasons = [System.Collections.Generic.List[string]]::new()
        $SamKey = $ADUser.SamAccountName.ToLowerInvariant()
        $Rid = $ADUser.ObjectSID.Value.Split('-')[-1]

        if ($Rid -in @('500', '501', '502', '503')) {
            [void]$Reasons.Add('Built-in account RID')
        }
        if ($ADUser.isCriticalSystemObject) {
            [void]$Reasons.Add('Critical system object')
        }
        if ($Exclusions.ContainsKey($SamKey)) {
            $Reason = $Exclusions[$SamKey].Reason
            if ([string]::IsNullOrWhiteSpace($Reason)) {
                $Reason = 'Explicit exclusion'
            }
            [void]$Reasons.Add($Reason)
        }

        $Excluded = $Reasons.Count -gt 0
        $ReviewFlags = [System.Collections.Generic.List[string]]::new()

        if ($ADUser.adminCount -eq 1) {
            [void]$ReviewFlags.Add('Privileged or formerly privileged account')
        }
        if (@($ADUser.ServicePrincipalName).Count -gt 0 -or $ADUser.SamAccountName -match '^(svc|service)[-_.]') {
            [void]$ReviewFlags.Add('Possible service account')
        }
        if (-not $Upn) {
            [void]$ReviewFlags.Add('Missing AD UPN')
        }
        elseif (-not $GraphAvailable) {
            [void]$ReviewFlags.Add('Microsoft Graph data not collected')
        }
        elseif ($GraphMatches.Count -eq 0) {
            [void]$ReviewFlags.Add('No Entra UPN match')
        }
        elseif ($GraphMatches.Count -gt 1) {
            [void]$ReviewFlags.Add('Multiple Entra UPN matches')
        }
        elseif ($GraphUser.OnPremisesSyncEnabled -ne $true) {
            [void]$ReviewFlags.Add('Entra match is not confirmed as synchronized')
        }

        $Classification = 'Not stale'
        if ($Excluded) {
            $Classification = 'Excluded'
        }
        elseif (-not $ADUser.Enabled) {
            if ($ADUser.WhenChanged -le $DisabledCutoff) {
                $Classification = 'Disabled aged candidate - owner validation required'
            }
            else {
                $Classification = 'Disabled - retention period not reached'
            }
        }
        elseif ($ReviewFlags.Count -gt 0) {
            $Classification = 'Manual review - ' + ($ReviewFlags -join '; ')
        }
        elseif ($ADUser.WhenCreated -gt $StaleCutoff) {
            $Classification = 'Not stale - recently created'
        }
        elseif (-not $ADLastLogon) {
            $Classification = 'Manual review - missing AD logon data'
        }
        elseif (-not $EntraLastSuccessfulSignIn) {
            $Classification = 'Manual review - missing Entra sign-in data'
        }
        elseif (($ADLastLogon -le $StaleCutoff) -and ($EntraLastSuccessfulSignIn -le $StaleCutoff)) {
            $Classification = 'Enabled stale candidate - owner validation required'
        }

        $Result = [pscustomobject][ordered]@{
            SamAccountName                = $ADUser.SamAccountName
            UserPrincipalName             = $ADUser.UserPrincipalName
            DisplayName                   = $ADUser.Name
            SourceDomain                  = $Domain
            DomainController              = $DomainController.HostName
            ADObjectGuid                  = $ADUser.ObjectGUID
            ADEnabled                     = $ADUser.Enabled
            ADCreated                     = $ADUser.WhenCreated
            ADChanged                     = $ADUser.WhenChanged
            ADLastLogonTimestamp          = $ADLastLogon
            ADPasswordLastSet             = $ADPasswordLastSet
            EntraObjectId                 = if ($GraphUser) { $GraphUser.Id } else { $null }
            EntraAccountEnabled           = if ($GraphUser) { $GraphUser.AccountEnabled } else { $null }
            OnPremisesSyncEnabled         = if ($GraphUser) { $GraphUser.OnPremisesSyncEnabled } else { $null }
            EntraLastSuccessfulSignIn     = $EntraLastSuccessfulSignIn
            Excluded                      = $Excluded
            ExclusionReason               = $Reasons -join '; '
            Classification                = $Classification
        }

        [void]$Results.Add($Result)
    }
}

$Stamp = $RunDate.ToString('yyyy-MM-dd')
$AllUsersPath = Join-Path $OutputPath "AllUsers-$Stamp.csv"
$EnabledStalePath = Join-Path $OutputPath "EnabledStaleCandidates-$Stamp.csv"
$DisabledAgedPath = Join-Path $OutputPath "DisabledAgedCandidates-$Stamp.csv"
$ManualReviewPath = Join-Path $OutputPath "ManualReview-$Stamp.csv"
$ExcludedPath = Join-Path $OutputPath "ExcludedUsers-$Stamp.csv"

$Results | Sort-Object SourceDomain, SamAccountName | Export-Csv -Path $AllUsersPath -NoTypeInformation -Encoding UTF8
$Results | Where-Object Classification -eq 'Enabled stale candidate - owner validation required' |
    Sort-Object SourceDomain, SamAccountName | Export-Csv -Path $EnabledStalePath -NoTypeInformation -Encoding UTF8
$Results | Where-Object Classification -eq 'Disabled aged candidate - owner validation required' |
    Sort-Object SourceDomain, SamAccountName | Export-Csv -Path $DisabledAgedPath -NoTypeInformation -Encoding UTF8
$Results | Where-Object Classification -like 'Manual review*' |
    Sort-Object SourceDomain, SamAccountName | Export-Csv -Path $ManualReviewPath -NoTypeInformation -Encoding UTF8
$Results | Where-Object Excluded -eq $true |
    Sort-Object SourceDomain, SamAccountName | Export-Csv -Path $ExcludedPath -NoTypeInformation -Encoding UTF8

Write-Host "Reports created in $OutputPath"
Write-Host "All users: $($Results.Count)"
Write-Host "Enabled stale candidates: $(@($Results | Where-Object Classification -eq 'Enabled stale candidate - owner validation required').Count)"
Write-Host "Disabled aged candidates: $(@($Results | Where-Object Classification -eq 'Disabled aged candidate - owner validation required').Count)"
Write-Host "Manual review: $(@($Results | Where-Object Classification -like 'Manual review*').Count)"
Write-Host "Excluded: $(@($Results | Where-Object Excluded -eq $true).Count)"
