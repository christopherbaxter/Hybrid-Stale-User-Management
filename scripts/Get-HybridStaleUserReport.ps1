<#
.SYNOPSIS
    Produces report-only stale-user, exclusion and disabled-account
    validation reports across Active Directory and Microsoft Entra ID.

.DESCRIPTION
    The script:

      - Queries each domain in the current Active Directory forest.
      - Retrieves Microsoft Entra users through Microsoft Graph.
      - Correlates AD and Entra identities by UserPrincipalName.
      - Compares AD lastLogonTimestamp with Microsoft Entra
        lastSuccessfulSignInDateTime.
      - Excludes built-in and possible service accounts.
      - Supports explicit exclusions by AD object GUID.
      - Creates a separate non-expiring-password report.
      - Identifies provisional disabled-aged accounts.
      - Validates only those provisional accounts against every
        discoverable writable DC in their source domain.
      - Retains the most recent whenChanged value observed.
      - Exports CSV reports and an optional Excel workbook.

.NOTES
    IMPORTANT DISCLAIMER

    This example script was generated with the assistance of AI using
    generalised concepts and patterns derived from earlier operational
    scripts.

    It is not a copy of any production script and does not contain customer
    names, account information, tenant details, domain names, server names,
    file paths or other environment-specific configuration.

    The script has been statically reviewed for PowerShell syntax, logical
    consistency and alignment with the public Microsoft documentation
    referenced in the accompanying article.

    It has not been executed or tested against a live Active Directory
    forest or Microsoft Entra tenant.

    Treat this script as an educational framework, not a production-ready
    solution. Review, adapt and test it in an isolated non-production
    environment before using it with organisational data.

    PowerShell versions, module versions, permissions, licensing, directory
    design and environmental configuration may cause errors or unexpected
    results.

    This script is report-only. It does not reset passwords, disable users,
    enable users, remove licences or delete directory objects.
#>

[CmdletBinding()]
param(
    [ValidateRange(30, 730)]
    [int]$StaleAfterDays = 90,

    [ValidateRange(30, 3650)]
    [int]$DisabledRetentionDays = 180,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "C:\Temp\HybridStaleUserReports",

    [string]$ExclusionFile = "C:\Temp\UserExclusions.csv",

    [switch]$ExportExcel
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Configuration

$BuiltInSamAccountNames = @(
    "Administrator",
    "Guest",
    "krbtgt"
)

$ServiceAccountPatterns = @(
    "^svc[-_]",
    "^sa[-_]",
    "^sql[-_]",
    "^app[-_]",
    "^iis[-_]",
    "^batch[-_]",
    "^job[-_]"
)

$ExcludedDistinguishedNamePatterns = @(
    "*OU=Service Accounts,*",
    "*OU=Managed Service Accounts,*",
    "*OU=Emergency Access,*"
)

#endregion Configuration

#region Helper functions

function Convert-ADFileTime {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        $FileTime = [Int64]$Value

        if ($FileTime -le 0) {
            return $null
        }

        return [DateTime\]::FromFileTimeUtc($FileTime)
    }
    catch {
        Write-Verbose "Could not convert an AD file-time value."
        return $null
    }
}

function Convert-ToUtcDateTime {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([DateTimeOffset]$Value).UtcDateTime
    }
    catch {
        Write-Verbose "Could not convert a value to UTC."
        return $null
    }
}

function Test-DateOlderThan {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Date,

        [Parameter(Mandatory)]
        [DateTime]$Cutoff
    )

    if ($null -eq $Date) {
        return $null
    }

    return ([DateTime]$Date).ToUniversalTime() -le $Cutoff
}

function Get-BuiltInAccountType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Sid,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SamAccountName
    )

    switch -Regex ($Sid) {
        "-500$" {
            return "Built-in domain Administrator account"
        }

        "-501$" {
            return "Built-in domain Guest account"
        }

        "-502$" {
            return "Kerberos ticket-granting account"
        }
    }

    if ($BuiltInSamAccountNames -contains $SamAccountName) {
        return "Built-in account name"
    }

    return $null
}

function Test-ServiceAccountName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SamAccountName
    )

    foreach ($Pattern in $ServiceAccountPatterns) {
        if ($SamAccountName -match $Pattern) {
            return $true
        }
    }

    return $false
}

function Test-ExcludedDistinguishedName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName
    )

    foreach ($Pattern in $ExcludedDistinguishedNamePatterns) {
        if ($DistinguishedName -like $Pattern) {
            return $true
        }
    }

    return $false
}

function Get-LatestWhenChangedAcrossDomainControllers {
    <#
    .SYNOPSIS
        Retrieves the most recent whenChanged value observed across
        writable domain controllers in a user's source domain.

    .DESCRIPTION
        This function is called only for accounts that have already passed
        the initial provisional disabled-aged test.

        The result is an object-change observation. It is not an
        authoritative account-disablement timestamp.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceDomain,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectGuid
    )

    $Observations =
        [System.Collections.Generic.List[object]\]::new()

    $FailedDomainControllers =
        [System.Collections.Generic.List[string]\]::new()

    try {
        $DomainControllers = @(
            Get-ADDomainController `
                -Filter * `
                -Server $SourceDomain `
                -ErrorAction Stop |
            Where-Object {
                $_.IsReadOnly -eq $false
            } |
            Sort-Object HostName
        )
    }
    catch {
        return [PSCustomObject]@{
            ValidationStatus         = "FailedToEnumerateDCs"
            SourceDomain             = $SourceDomain
            ADObjectGUID             = $ObjectGuid
            LatestWhenChangedUTC     = $null
            LatestWhenChangedDC      = $null
            DomainControllersFound   = 0
            DomainControllersQueried = 0
            DomainControllersFailed  = 0
            FailedDomainControllers  = $null
            ErrorMessage             = $_.Exception.Message
            Observations             = @()
        }
    }

    foreach ($DomainController in $DomainControllers) {
        $DomainControllerName = $DomainController.HostName

        try {
            $UserFromDomainController = Get-ADUser `
                -Identity $ObjectGuid `
                -Server $DomainControllerName `
                -Properties whenChanged, Enabled `
                -ErrorAction Stop

            $WhenChangedUtc = $null

            if ($null -ne $UserFromDomainController.whenChanged) {
                $WhenChangedUtc = (
                    [DateTime]$UserFromDomainController.whenChanged
                ).ToUniversalTime()
            }

            $Observations.Add(
                [PSCustomObject]@{
                    DomainController = $DomainControllerName
                    QuerySuccessful  = $true
                    AccountEnabled   =
                        $UserFromDomainController.Enabled
                    WhenChangedUTC   = $WhenChangedUtc
                    ErrorMessage     = $null
                }
            )
        }
        catch {
            $FailedDomainControllers.Add(
                $DomainControllerName
            )

            $Observations.Add(
                [PSCustomObject]@{
                    DomainController = $DomainControllerName
                    QuerySuccessful  = $false
                    AccountEnabled   = $null
                    WhenChangedUTC   = $null
                    ErrorMessage     = $_.Exception.Message
                }
            )
        }
    }

    $SuccessfulObservations = @(
        $Observations |
            Where-Object {
                $_.QuerySuccessful -eq $true -and
                $null -ne $_.WhenChangedUTC
            }
    )

    $LatestObservation = $null

    if ($SuccessfulObservations.Count -gt 0) {
        $LatestObservation = $SuccessfulObservations |
            Sort-Object WhenChangedUTC -Descending |
            Select-Object -First 1
    }

    $ValidationStatus = if ($DomainControllers.Count -eq 0) {
        "NoWritableDomainControllersFound"
    }
    elseif ($SuccessfulObservations.Count -eq 0) {
        "NoSuccessfulQueries"
    }
    elseif ($FailedDomainControllers.Count -gt 0) {
        "PartiallyValidated"
    }
    else {
        "ValidatedAgainstAllWritableDCs"
    }

    $LatestWhenChangedUtc = $null
    $LatestWhenChangedDc = $null

    if ($null -ne $LatestObservation) {
        $LatestWhenChangedUtc =
            $LatestObservation.WhenChangedUTC

        $LatestWhenChangedDc =
            $LatestObservation.DomainController
    }

    return [PSCustomObject]@{
        ValidationStatus         = $ValidationStatus
        SourceDomain             = $SourceDomain
        ADObjectGUID             = $ObjectGuid
        LatestWhenChangedUTC     = $LatestWhenChangedUtc
        LatestWhenChangedDC      = $LatestWhenChangedDc
        DomainControllersFound   = $DomainControllers.Count
        DomainControllersQueried =
            $SuccessfulObservations.Count
        DomainControllersFailed  =
            $FailedDomainControllers.Count
        FailedDomainControllers  =
            ($FailedDomainControllers -join "; ")
        ErrorMessage             = $null
        Observations             = @($Observations)
    }
}

function Export-ReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$InputData
    )

    if ($InputData.Count -gt 0) {
        $InputData |
            Export-Csv `
                -LiteralPath $Path `
                -NoTypeInformation `
                -Encoding UTF8
    }
    else {
        "No matching records were found." |
            Set-Content `
                -LiteralPath $Path `
                -Encoding UTF8
    }
}

#endregion Helper functions

#region Prerequisites

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item `
        -Path $OutputPath `
        -ItemType Directory `
        -Force |
        Out-Null
}

$RunDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$NowUtc = (Get-Date).ToUniversalTime()
$StaleCutoffUtc = $NowUtc.AddDays(-$StaleAfterDays)
$DisabledCutoffUtc =
    $NowUtc.AddDays(-$DisabledRetentionDays)

#endregion Prerequisites

#region Import explicit exclusions

$ExplicitExclusionIndex = @{}

if (Test-Path -LiteralPath $ExclusionFile) {
    $ExplicitExclusions = @(
        Import-Csv `
            -LiteralPath $ExclusionFile `
            -Delimiter ";"
    )

    foreach ($Exclusion in $ExplicitExclusions) {
        $HasGuidProperty = (
            $Exclusion.PSObject.Properties.Name -contains
                "ADObjectGUID"
        )

        if (
            -not $HasGuidProperty -or
            [string\]::IsNullOrWhiteSpace(
                $Exclusion.ADObjectGUID
            )
        ) {
            continue
        }

        $Key = $Exclusion.ADObjectGUID.
            Trim().
            ToLowerInvariant()

        $ExplicitExclusionIndex[$Key] = $Exclusion
    }
}
else {
    Write-Warning (
        "The exclusion file was not found: {0}" -f
        $ExclusionFile
    )
}

#endregion Import explicit exclusions

#region Retrieve Microsoft Entra users

Write-Host "Connecting to Microsoft Graph..." `
    -ForegroundColor Cyan

Connect-MgGraph `
    -Scopes @(
        "User.Read.All",
        "AuditLog.Read.All"
    ) `
    -NoWelcome

try {
    $GraphProperties = @(
        "id",
        "displayName",
        "userPrincipalName",
        "accountEnabled",
        "onPremisesSyncEnabled",
        "createdDateTime",
        "userType",
        "signInActivity"
    )

    Write-Host "Retrieving Microsoft Entra users..." `
        -ForegroundColor Cyan

    $AllGraphUsers = @(
        Get-MgUser `
            -All `
            -Property $GraphProperties `
            -ErrorAction Stop
    )

    $GraphUsersByUpn = @{}

    foreach ($GraphUser in $AllGraphUsers) {
        if (
            -not [string\]::IsNullOrWhiteSpace(
                $GraphUser.UserPrincipalName
            )
        ) {
            $GraphKey = $GraphUser.
                UserPrincipalName.
                ToLowerInvariant()

            $GraphUsersByUpn[$GraphKey] = $GraphUser
        }
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}

#endregion Retrieve Microsoft Entra users

#region Retrieve AD users

$Forest = Get-ADForest -ErrorAction Stop
$DomainTargets = @($Forest.Domains)

$AllAdUsers =
    [System.Collections.Generic.List[object]\]::new()

$ADProperties = @(
    "UserPrincipalName",
    "Enabled",
    "whenCreated",
    "whenChanged",
    "pwdLastSet",
    "lastLogonTimestamp",
    "PasswordNeverExpires",
    "PasswordNotRequired",
    "CannotChangePassword",
    "SmartcardLogonRequired",
    "ServicePrincipalName",
    "Description",
    "DistinguishedName",
    "SID",
    "ObjectGUID",
    "adminCount",
    "AccountExpirationDate"
)

foreach ($DomainTarget in $DomainTargets) {
    Write-Host (
        "Retrieving users from domain: {0}" -f
        $DomainTarget
    ) -ForegroundColor Cyan

    $ServerTarget = (
        Get-ADDomainController `
            -Discover `
            -DomainName $DomainTarget `
            -Writable `
            -ErrorAction Stop
    ).HostName

    $DomainUsers = @(
        Get-ADUser `
            -Server $ServerTarget `
            -Filter * `
            -Properties $ADProperties `
            -ErrorAction Stop
    )

    foreach ($DomainUser in $DomainUsers) {
        $AllAdUsers.Add(
            [PSCustomObject]@{
                SourceDomain = $DomainTarget
                DomainController = $ServerTarget
                Name = $DomainUser.Name
                SamAccountName =
                    $DomainUser.SamAccountName
                UserPrincipalName =
                    $DomainUser.UserPrincipalName
                Enabled = $DomainUser.Enabled
                SID = $DomainUser.SID.Value
                ObjectGUID = $DomainUser.ObjectGUID
                DistinguishedName =
                    $DomainUser.DistinguishedName
                Description = $DomainUser.Description
                WhenCreated = $DomainUser.whenCreated
                WhenChanged = $DomainUser.whenChanged
                PwdLastSetRaw = $DomainUser.pwdLastSet
                LastLogonTimestampRaw =
                    $DomainUser.lastLogonTimestamp
                PasswordNeverExpires =
                    $DomainUser.PasswordNeverExpires
                PasswordNotRequired =
                    $DomainUser.PasswordNotRequired
                CannotChangePassword =
                    $DomainUser.CannotChangePassword
                SmartcardLogonRequired =
                    $DomainUser.SmartcardLogonRequired
                ServicePrincipalName = @(
                    $DomainUser.ServicePrincipalName
                )
                AdminCount = $DomainUser.adminCount
                AccountExpirationDate =
                    $DomainUser.AccountExpirationDate
            }
        )
    }
}

#endregion Retrieve AD users

#region Correlate and classify

$CompleteUserData =
    [System.Collections.Generic.List[object]\]::new()

$Counter = 0
$TotalUsers = $AllAdUsers.Count

foreach ($User in $AllAdUsers) {
    $Counter++

    if ($TotalUsers -gt 0) {
        Write-Progress `
            -Activity "Correlating AD and Entra users" `
            -Status (
                "Processing {0} of {1}" -f
                $Counter,
                $TotalUsers
            ) `
            -PercentComplete (
                ($Counter / $TotalUsers) * 100
            )
    }

    $GraphUser = $null

    if (
        -not [string\]::IsNullOrWhiteSpace(
            $User.UserPrincipalName
        )
    ) {
        $UpnKey = $User.
            UserPrincipalName.
            ToLowerInvariant()

        if ($GraphUsersByUpn.ContainsKey($UpnKey)) {
            $GraphUser = $GraphUsersByUpn[$UpnKey]
        }
    }

    $EntraObjectId = $null
    $EntraEnabled = $null
    $OnPremisesSyncEnabled = $null
    $EntraLastSuccessfulSignInUtc = $null

    if ($null -ne $GraphUser) {
        $EntraObjectId = $GraphUser.Id
        $EntraEnabled = $GraphUser.AccountEnabled
        $OnPremisesSyncEnabled =
            $GraphUser.OnPremisesSyncEnabled

        if (
            $null -ne $GraphUser.SignInActivity -and
            $null -ne $GraphUser.SignInActivity.
                LastSuccessfulSignInDateTime
        ) {
            $EntraLastSuccessfulSignInUtc =
                Convert-ToUtcDateTime `
                    -Value (
                        $GraphUser.SignInActivity.
                            LastSuccessfulSignInDateTime
                    )
        }
    }

    $AdLastLogonUtc = Convert-ADFileTime `
        -Value $User.LastLogonTimestampRaw

    $PasswordLastSetUtc = Convert-ADFileTime `
        -Value $User.PwdLastSetRaw

    $WhenCreatedUtc = (
        [DateTime]$User.WhenCreated
    ).ToUniversalTime()

    $InitialWhenChangedUtc = (
        [DateTime]$User.WhenChanged
    ).ToUniversalTime()

    $AdStale = Test-DateOlderThan `
        -Date $AdLastLogonUtc `
        -Cutoff $StaleCutoffUtc

    $EntraStale = Test-DateOlderThan `
        -Date $EntraLastSuccessfulSignInUtc `
        -Cutoff $StaleCutoffUtc

    $AccountOldEnough = (
        $WhenCreatedUtc -le $StaleCutoffUtc
    )

    $ExclusionReasons =
        [System.Collections.Generic.List[string]\]::new()

    $BuiltInType = Get-BuiltInAccountType `
        -Sid $User.SID `
        -SamAccountName $User.SamAccountName

    if ($null -ne $BuiltInType) {
        $ExclusionReasons.Add($BuiltInType)
    }

    if ($User.PasswordNeverExpires -eq $true) {
        $ExclusionReasons.Add(
            "Password does not expire; possible service " +
            "or policy-exception account"
        )
    }

    if (@($User.ServicePrincipalName).Count -gt 0) {
        $ExclusionReasons.Add(
            "User object has one or more SPNs"
        )
    }

    $MatchesServiceAccountName =
        Test-ServiceAccountName `
            -SamAccountName $User.SamAccountName

    if ($MatchesServiceAccountName) {
        $ExclusionReasons.Add(
            "Account matches a service-account naming pattern"
        )
    }

    $LocatedInExcludedOu =
        Test-ExcludedDistinguishedName `
            -DistinguishedName $User.DistinguishedName

    if ($LocatedInExcludedOu) {
        $ExclusionReasons.Add(
            "Account is located in an excluded OU"
        )
    }

    if ($User.AdminCount -eq 1) {
        $ExclusionReasons.Add(
            "Account has the adminCount privilege indicator"
        )
    }

    $UserGuidKey = $User.
        ObjectGUID.
        ToString().
        ToLowerInvariant()

    if ($ExplicitExclusionIndex.ContainsKey($UserGuidKey)) {
        $ExplicitExclusion =
            $ExplicitExclusionIndex[$UserGuidKey]

        $ExplicitReason = "No reason supplied"

        if (
            $ExplicitExclusion.PSObject.Properties.Name `
                -contains "Reason" -and
            -not [string\]::IsNullOrWhiteSpace(
                $ExplicitExclusion.Reason
            )
        ) {
            $ExplicitReason = $ExplicitExclusion.Reason
        }

        $ExclusionReasons.Add(
            "Explicit exclusion: $ExplicitReason"
        )
    }

    $IsExcluded = $ExclusionReasons.Count -gt 0

    $IsServiceAccountCandidate = (
        $User.PasswordNeverExpires -eq $true -or
        @($User.ServicePrincipalName).Count -gt 0 -or
        $MatchesServiceAccountName -or
        $LocatedInExcludedOu
    )

    $ProvisionalDisabledStale = (
        $User.Enabled -eq $false -and
        $IsExcluded -eq $false -and
        $InitialWhenChangedUtc -le
            $DisabledCutoffUtc
    )

    $Classification = if ($null -ne $BuiltInType) {
        "Excluded - built-in AD account"
    }
    elseif ($IsExcluded) {
        "Excluded - manual review required"
    }
    elseif ($User.Enabled -eq $false) {
        "Disabled - pending age and DC validation"
    }
    elseif (-not $AccountOldEnough
