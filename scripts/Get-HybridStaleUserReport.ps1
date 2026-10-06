#requires -Version 5.1
#requires -Modules ActiveDirectory, Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
Creates a report-first view of potentially stale user accounts across
Active Directory and Microsoft Entra ID.

.DESCRIPTION
The script:
- Reads users from every domain in the current AD forest.
- Reads users and sign-in activity from Microsoft Entra ID.
- Correlates records by UserPrincipalName.
- Reports AD and Entra activity.
- Reports password age separately from account inactivity.
- Applies built-in and CSV-based exclusions.
- Exports a single CSV report.
- Performs no disablement, deletion, or password reset.

IMPORTANT
Review every result before taking remediation action.
Missing activity data is classified as Review, not Stale.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

$StaleDays = 90
$PasswordReviewDays = 180

$OutputFolder = Join-Path $PSScriptRoot "..\output"
$ExclusionFile = Join-Path $PSScriptRoot "..\examples\UserExclusions.csv"
$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$ReportPath = Join-Path $OutputFolder "Hybrid-Stale-User-Report-$ReportDate.csv"

$StaleCutoff = (Get-Date).AddDays(-$StaleDays)
$PasswordCutoff = (Get-Date).AddDays(-$PasswordReviewDays)

# ------------------------------------------------------------
# Prepare output and exclusions
# ------------------------------------------------------------

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$BuiltInNames = @(
    "Administrator"
    "Guest"
    "krbtgt"
    "DefaultAccount"
    "WDAGUtilityAccount"
)

$CustomExclusions = @()

if (Test-Path $ExclusionFile) {
    $CustomExclusions = Import-Csv -Path $ExclusionFile
}

# ------------------------------------------------------------
# Connect to Microsoft Graph
# ------------------------------------------------------------

Connect-MgGraph -Scopes @(
    "User.Read.All"
    "Directory.Read.All"
    "AuditLog.Read.All"
) -NoWelcome

$GraphProperties = @(
    "id"
    "displayName"
    "userPrincipalName"
    "accountEnabled"
    "onPremisesSyncEnabled"
    "onPremisesSamAccountName"
    "lastPasswordChangeDateTime"
    "signInActivity"
)

Write-Host "Reading Microsoft Entra ID users..." -ForegroundColor Cyan

$GraphUsers = Get-MgUser `
    -All `
    -Property $GraphProperties |
    Select-Object `
        Id,
        DisplayName,
        UserPrincipalName,
        AccountEnabled,
        OnPremisesSyncEnabled,
        OnPremisesSamAccountName,
        LastPasswordChangeDateTime,
        @{
            Name = "LastSuccessfulSignInDateTime"
            Expression = {
                $_.SignInActivity.LastSuccessfulSignInDateTime
            }
        },
        @{
            Name = "LastInteractiveSignInDateTime"
            Expression = {
                $_.SignInActivity.LastSignInDateTime
            }
        },
        @{
            Name = "LastNonInteractiveSignInDateTime"
            Expression = {
                $_.SignInActivity.LastNonInteractiveSignInDateTime
            }
        }

$GraphByUpn = @{}

foreach ($GraphUser in $GraphUsers) {
    if (-not :IsNullOrWhiteSpace($GraphUser.UserPrincipalName)) {
        $GraphByUpn[$GraphUser.UserPrincipalName.ToLowerInvariant()] = $GraphUser
    }
}

# ------------------------------------------------------------
# Read Active Directory
# ------------------------------------------------------------

$Forest = Get-ADForest
$ADUsers = @()

foreach ($DomainName in $Forest.Domains) {
    Write-Host "Reading Active Directory users from $DomainName..." -ForegroundColor Cyan

    $DomainController = (
        Get-ADDomainController -Discover -DomainName $DomainName -Writable
    ).HostName

    $DomainUsers = Get-ADUser `
        -Server $DomainController `
        -Filter * `
        -Properties @(
            "DisplayName"
            "UserPrincipalName"
            "Enabled"
            "ObjectGUID"
            "ObjectSID"
            "DistinguishedName"
            "whenCreated"
            "whenChanged"
            "lastLogonTimestamp"
            "pwdLastSet"
            "PasswordNeverExpires"
            "PasswordNotRequired"
            "ServicePrincipalName"
        )

    foreach ($ADUser in $DomainUsers) {
        $ADLastLogon = $null
        $ADPasswordLastSet = $null

        if ($ADUser.lastLogonTimestamp -and $ADUser.lastLogonTimestamp -gt 0) {
            $ADLastLogon = [DateTime]::FromFileTime(
                [Int64]$ADUser.lastLogonTimestamp
            )
        }

        if ($ADUser.pwdLastSet -and $ADUser.pwdLastSet -gt 0) {
            $ADPasswordLastSet = [DateTime]::FromFileTime(
                [Int64]$ADUser.pwdLastSet
            )
        }

        $Rid = $null

        if ($ADUser.SID) {
            $Rid = $ADUser.SID.Value.Split("-"[-1])
        }

        $ADUsers += [PSCustomObject]@{
            Domain                  = $DomainName
            DomainController        = $DomainController
            DisplayName             = $ADUser.DisplayName
            SamAccountName          = $ADUser.SamAccountName
            UserPrincipalName       = $ADUser.UserPrincipalName
            ADEnabled               = $ADUser.Enabled
            ADObjectGuid            = $ADUser.ObjectGUID
            ADSid                   = $ADUser.SID.Value
            RID                     = $Rid
            DistinguishedName       = $ADUser.DistinguishedName
            WhenCreated             = $ADUser.whenCreated
            WhenChanged             = $ADUser.whenChanged
            ADLastLogonTimestamp    = $ADLastLogon
            ADPasswordLastSet       = $ADPasswordLastSet
            PasswordNeverExpires    = $ADUser.PasswordNeverExpires
            PasswordNotRequired     = $ADUser.PasswordNotRequired
            HasServicePrincipalName = [bool]$ADUser.ServicePrincipalName
        }
    }
}

# ------------------------------------------------------------
# Correlate AD and Entra evidence
# ------------------------------------------------------------

$Results = foreach ($ADUser in $ADUsers) {
    $GraphUser = $null
    $MatchStatus = "ADOnly"

    if (-not :IsNullOrWhiteSpace($ADUser.UserPrincipalName)) {
        $UpnKey = $ADUser.UserPrincipalName.ToLowerInvariant()

        if ($GraphByUpn.ContainsKey($UpnKey)) {
            $GraphUser = $GraphByUpn[$UpnKey]
            $MatchStatus = "Matched"
        }
    }

    $EntraLastSuccessfulSignIn = $null
    $EntraPasswordLastChanged = $null
    $EntraEnabled = $null
    $EntraObjectId = $null
    $OnPremisesSyncEnabled = $null

    if ($GraphUser) {
        $EntraEnabled = $GraphUser.AccountEnabled
        $EntraObjectId = $GraphUser.Id
        $OnPremisesSyncEnabled = $GraphUser.OnPremisesSyncEnabled

        if ($GraphUser.LastSuccessfulSignInDateTime) {
            $EntraLastSuccessfulSignIn = [DateTime]$GraphUser.LastSuccessfulSignInDateTime
        }

        if ($GraphUser.LastPasswordChangeDateTime) {
            $EntraPasswordLastChanged = [DateTime]$GraphUser.LastPasswordChangeDateTime
        }
    }

    $Excluded = $false
    $ExclusionReason = $null

    if ($ADUser.SamAccountName -in $BuiltInNames) {
        $Excluded = $true
        $ExclusionReason = "Built-in account name"
    }

    if ($ADUser.RID -in @(500, 501, 502)) {
        $Excluded = $true
        $ExclusionReason = "Well-known built-in account RID"
    }

    $CustomMatch = $CustomExclusions |
        Where-Object {
            $_.SamAccountName -and
            $_.SamAccountName -ieq $ADUser.SamAccountName
        } |
        Select-Object -First 1

    if ($CustomMatch) {
        $Excluded = $true
        $ExclusionReason = $CustomMatch.Reason
    }

    $ADActivityStatus = "Missing"
    $EntraActivityStatus = "NotApplicable"

    if ($ADUser.ADLastLogonTimestamp) {
        if ($ADUser.ADLastLogonTimestamp -lt $StaleCutoff) {
            $ADActivityStatus = "Old"
        }
        else {
            $ADActivityStatus = "Recent"
        }
    }

    if ($GraphUser) {
        $EntraActivityStatus = "Missing"

        if ($EntraLastSuccessfulSignIn) {
            if ($EntraLastSuccessfulSignIn -lt $StaleCutoff) {
                $EntraActivityStatus = "Old"
            }
            else {
                $EntraActivityStatus = "Recent"
            }
        }
    }

    $Classification = "Review"
    $ClassificationReason = "Insufficient or conflicting activity evidence"

    if ($Excluded) {
        $Classification = "Excluded"
        $ClassificationReason = $ExclusionReason
    }
    elseif ($ADActivityStatus -eq "Recent" -or $EntraActivityStatus -eq "Recent") {
        $Classification = "Active"
        $ClassificationReason = "Recent activity exists in AD or Microsoft Entra ID"
    }
    elseif (
        $MatchStatus -eq "Matched" -and
        $ADActivityStatus -eq "Old" -and
        $EntraActivityStatus -eq "Old"
    ) {
        $Classification = "Stale"
        $ClassificationReason = "AD and Entra activity are both older than the threshold"
    }
    elseif (
        $MatchStatus -eq "ADOnly" -and
        $ADActivityStatus -eq "Old"
    ) {
        $Classification = "Review"
        $ClassificationReason = "AD-only account has old activity and requires owner review"
    }

    $ADPasswordAgeDays = $null
    $EntraPasswordAgeDays = $null
    $PasswordReview = $false

    if ($ADUser.ADPasswordLastSet) {
        $ADPasswordAgeDays = (
            (Get-Date) - $ADUser.ADPasswordLastSet
        ).Days

        if ($ADUser.ADPasswordLastSet -lt $PasswordCutoff) {
            $PasswordReview = $true
        }
    }

    if ($EntraPasswordLastChanged) {
        $EntraPasswordAgeDays = (
            (Get-Date) - $EntraPasswordLastChanged
        ).Days

        if ($EntraPasswordLastChanged -lt $PasswordCutoff) {
            $PasswordReview = $true
        }
    }

    [PSCustomObject]@{
        Classification                    = $Classification
        ClassificationReason              = $ClassificationReason
        Excluded                          = $Excluded
        ExclusionReason                   = $ExclusionReason
        MatchStatus                       = $MatchStatus
        DisplayName                       = $ADUser.DisplayName
        UserPrincipalName                 = $ADUser.UserPrincipalName
        SamAccountName                    = $ADUser.SamAccountName
        Domain                            = $ADUser.Domain
        DistinguishedName                 = $ADUser.DistinguishedName
        ADEnabled                         = $ADUser.ADEnabled
        EntraEnabled                      = $EntraEnabled
        OnPremisesSyncEnabled             = $OnPremisesSyncEnabled
        ADLastLogonTimestamp              = $ADUser.ADLastLogonTimestamp
        EntraLastSuccessfulSignInDateTime = $EntraLastSuccessfulSignIn
        ADActivityStatus                  = $ADActivityStatus
        EntraActivityStatus               = $EntraActivityStatus
        ADPasswordLastSet                 = $ADUser.ADPasswordLastSet
        ADPasswordAgeDays                 = $ADPasswordAgeDays
        EntraPasswordLastChanged          = $EntraPasswordLastChanged
        EntraPasswordAgeDays              = $EntraPasswordAgeDays
        PasswordReview                    = $PasswordReview
        PasswordNeverExpires              = $ADUser.PasswordNeverExpires
        PasswordNotRequired               = $ADUser.PasswordNotRequired
        HasServicePrincipalName           = $ADUser.HasServicePrincipalName
        WhenCreated                       = $ADUser.WhenCreated
        WhenChanged                       = $ADUser.WhenChanged
        ADObjectGuid                      = $ADUser.ADObjectGuid
        EntraObjectId                     = $EntraObjectId
        DomainController                  = $ADUser.DomainController
        StaleThresholdDays                = $StaleDays
        PasswordReviewThresholdDays       = $PasswordReviewDays
        ReportGenerated                   = Get-Date
    }
}

# ------------------------------------------------------------
# Add cloud-only users
# ------------------------------------------------------------

$ADUpns = @{}

foreach ($ADUser in $ADUsers) {
    if (-not :IsNullOrWhiteSpace($ADUser.UserPrincipalName)) {
        $ADUpns[$ADUser.UserPrincipalName.ToLowerInvariant()] = $true
    }
}

foreach ($GraphUser in $GraphUsers) {
    if (:IsNullOrWhiteSpace($GraphUser.UserPrincipalName)) {
        continue
    }

    $UpnKey = $GraphUser.UserPrincipalName.ToLowerInvariant()

    if ($ADUpns.ContainsKey($UpnKey)) {
        continue
    }

    $EntraLastSuccessfulSignIn = $null
    $EntraPasswordLastChanged = $null

    if ($GraphUser.LastSuccessfulSignInDateTime) {
        $EntraLastSuccessfulSignIn = [DateTime]$GraphUser.LastSuccessfulSignInDateTime
    }

    if ($GraphUser.LastPasswordChangeDateTime) {
        $EntraPasswordLastChanged = [DateTime]$GraphUser.LastPasswordChangeDateTime
    }

    $EntraActivityStatus = "Missing"
    $Classification = "Review"
    $ClassificationReason = "No successful Entra sign-in value is available"

    if ($EntraLastSuccessfulSignIn) {
        if ($EntraLastSuccessfulSignIn -lt $StaleCutoff) {
            $EntraActivityStatus = "Old"
            $Classification = "Stale"
            $ClassificationReason = "Cloud-only account activity is older than the threshold"
        }
        else {
            $EntraActivityStatus = "Recent"
            $Classification = "Active"
            $ClassificationReason = "Recent Microsoft Entra activity exists"
        }
    }

    $EntraPasswordAgeDays = $null
    $PasswordReview = $false

    if ($EntraPasswordLastChanged) {
        $EntraPasswordAgeDays = (
            (Get-Date) - $EntraPasswordLastChanged
        ).Days

        if ($EntraPasswordLastChanged -lt $PasswordCutoff) {
            $PasswordReview = $true
        }
    }

    $Results += [PSCustomObject]@{
        Classification                    = $Classification
        ClassificationReason              = $ClassificationReason
        Excluded                          = $false
        ExclusionReason                   = $null
        MatchStatus                       = "CloudOnly"
        DisplayName                       = $GraphUser.DisplayName
        UserPrincipalName                 = $GraphUser.UserPrincipalName
        SamAccountName                    = $GraphUser.OnPremisesSamAccountName
        Domain                            = $null
        DistinguishedName                 = $null
        ADEnabled                         = $null
        EntraEnabled                      = $GraphUser.AccountEnabled
        OnPremisesSyncEnabled             = $GraphUser.OnPremisesSyncEnabled
        ADLastLogonTimestamp              = $null
        EntraLastSuccessfulSignInDateTime = $EntraLastSuccessfulSignIn
        ADActivityStatus                  = "NotApplicable"
        EntraActivityStatus               = $EntraActivityStatus
        ADPasswordLastSet                 = $null
        ADPasswordAgeDays                 = $null
        EntraPasswordLastChanged          = $EntraPasswordLastChanged
        EntraPasswordAgeDays              = $EntraPasswordAgeDays
        PasswordReview                    = $PasswordReview
        PasswordNeverExpires              = $null
        PasswordNotRequired               = $null
        HasServicePrincipalName           = $null
        WhenCreated                       = $null
        WhenChanged                       = $null
        ADObjectGuid                      = $null
        EntraObjectId                     = $GraphUser.Id
        DomainController                  = $null
        StaleThresholdDays                = $StaleDays
        PasswordReviewThresholdDays       = $PasswordReviewDays
        ReportGenerated                   = Get-Date
    }
}

# ------------------------------------------------------------
# Export
# ------------------------------------------------------------

$Results |
    Sort-Object Classification, UserPrincipalName |
    Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

Disconnect-MgGraph | Out-Null

Write-Host ""
Write-Host "Report created successfully:" -ForegroundColor Green
Write-Host $ReportPath -ForegroundColor Green
Write-Host ""
Write-Host "No accounts were changed." -ForegroundColor Yellow
Write-Host "Review all Stale and Review results before remediation." -ForegroundColor Yellow
