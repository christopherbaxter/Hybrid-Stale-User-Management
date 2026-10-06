#requires -Version 5.1
#requires -Modules ActiveDirectory, Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
Creates a report of potentially stale user accounts across Active Directory
and Microsoft Entra ID.

.DESCRIPTION
The script:

1. Reads users from every domain in the current AD forest.
2. Uses the replicated AD lastLogonTimestamp attribute.
3. Reads Microsoft Entra successful sign-in information.
4. Correlates AD and Entra users by UserPrincipalName.
5. Uses real DateTime comparisons.
6. Applies built-in and CSV-based exclusions.
7. Identifies enabled stale accounts for review.
8. Identifies disabled accounts with stale replicated logon information.
9. Queries whenChanged from every writable DC only for disabled stale candidates.
10. Exports complete, stale, and disabled-stale CSV reports.

The script is report-only. It makes no account changes.

IMPORTANT
A stale result is a review candidate, not an instruction to disable or delete
an account. Validate all results against account ownership, mailbox usage,
service dependencies, exclusions, current activity, and the applicable
change-management process.
#>

[CmdletBinding()]
param (
    [ValidateRange(30, 3650)]
    [int]$StaleDays = 180,

    [ValidateRange(0, 3650)]
    [int]$MinimumAccountAgeDays = 90,

    [string]$OutputFolder = "$PSScriptRoot\output",

    [string]$ExclusionFile = "$PSScriptRoot\UserExclusions.csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Validate required modules
# ------------------------------------------------------------

$RequiredModules = @(
    "ActiveDirectory"
    "Microsoft.Graph.Authentication"
    "Microsoft.Graph.Users"
)

foreach ($ModuleName in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        throw "Required PowerShell module is not installed: $ModuleName"
    }
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

# ------------------------------------------------------------
# Prepare report settings
# ------------------------------------------------------------

$ReportDate = Get-Date
$StaleDate = $ReportDate.AddDays(-$StaleDays)
$MinimumCreatedDate = $ReportDate.AddDays(-$MinimumAccountAgeDays)
$FileDate = $ReportDate.ToString("yyyy-MM-dd_HHmmss")

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force |
        Out-Null
}

$AllUsersReport = Join-Path `
    -Path $OutputFolder `
    -ChildPath "All-Hybrid-Users-$FileDate.csv"

$StaleUsersReport = Join-Path `
    -Path $OutputFolder `
    -ChildPath "Stale-User-Candidates-$FileDate.csv"

$DisabledStaleUsersReport = Join-Path `
    -Path $OutputFolder `
    -ChildPath "Disabled-Stale-User-Candidates-$FileDate.csv"

$ValidationFailuresReport = Join-Path `
    -Path $OutputFolder `
    -ChildPath "Disabled-Stale-DC-Validation-Failures-$FileDate.csv"

# ------------------------------------------------------------
# Load exclusions
# ------------------------------------------------------------

$BuiltInAccountNames = @(
    "Administrator"
    "Guest"
    "krbtgt"
    "DefaultAccount"
    "WDAGUtilityAccount"
)

$BuiltInAccountRids = @(
    "500"
    "501"
    "502"
)

$ExcludedSamAccountNames = @()
$ExcludedUserPrincipalNames = @()

if (Test-Path -LiteralPath $ExclusionFile) {
    $Exclusions = @(
        Import-Csv -LiteralPath $ExclusionFile -ErrorAction Stop
    )

    if (
        $Exclusions.Count -gt 0 -and
        -not $Exclusions[0].PSObject.Properties["SamAccountName"] -and
        -not $Exclusions[0].PSObject.Properties["UserPrincipalName"]
    ) {
        throw (
            "The exclusion file must contain a SamAccountName column, " +
            "a UserPrincipalName column, or both."
        )
    }

    $ExcludedSamAccountNames = @(
        $Exclusions |
        Where-Object {
            $_.PSObject.Properties["SamAccountName"] -and
            -not [string\]::IsNullOrWhiteSpace($_.SamAccountName)
        } |
        ForEach-Object {
            $_.SamAccountName.Trim()
        }
    )

    $ExcludedUserPrincipalNames = @(
        $Exclusions |
        Where-Object {
            $_.PSObject.Properties["UserPrincipalName"] -and
            -not [string\]::IsNullOrWhiteSpace($_.UserPrincipalName)
        } |
        ForEach-Object {
            $_.UserPrincipalName.Trim()
        }
    )

    Write-Host "Loaded exclusions from $ExclusionFile" `
        -ForegroundColor Green
}
else {
    Write-Warning (
        "The exclusion file was not found. " +
        "Only built-in account exclusions will be applied."
    )
}

# ------------------------------------------------------------
# Read Microsoft Entra users
# ------------------------------------------------------------

$GraphConnected = $false

try {
    Write-Host "Connecting to Microsoft Graph..." `
        -ForegroundColor Cyan

    Connect-MgGraph `
        -Scopes "User.Read.All", "AuditLog.Read.All" `
        -NoWelcome `
        -ErrorAction Stop

    $GraphConnected = $true

    Write-Host "Reading Microsoft Entra users..." `
        -ForegroundColor Cyan

    $GraphUsers = @(
        Get-MgUser `
            -All `
            -Property @(
                "id"
                "displayName"
                "userPrincipalName"
                "accountEnabled"
                "onPremisesSyncEnabled"
                "onPremisesSamAccountName"
                "lastPasswordChangeDateTime"
                "signInActivity"
            ) `
            -ErrorAction Stop
    )

    $GraphUsersByUPN = @{}

    foreach ($GraphUser in $GraphUsers) {
        if (
            -not [string\]::IsNullOrWhiteSpace(
                $GraphUser.UserPrincipalName
            )
        ) {
            $GraphKey = (
                $GraphUser.UserPrincipalName.Trim().ToLowerInvariant()
            )

            if (-not $GraphUsersByUPN.ContainsKey($GraphKey)) {
                $GraphUsersByUPN[$GraphKey] = $GraphUser
            }
        }
    }

    Write-Host (
        "Microsoft Entra users retrieved: {0}" -f
        $GraphUsers.Count
    ) -ForegroundColor Green
}
catch {
    if ($GraphConnected) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue |
            Out-Null
    }

    throw "Microsoft Graph collection failed: $($_.Exception.Message)"
}

# ------------------------------------------------------------
# Read Active Directory users
# ------------------------------------------------------------

$Forest = Get-ADForest -ErrorAction Stop
$ADUsers = @()
$DomainControllersByDomain = @{}

foreach ($DomainName in $Forest.Domains) {
    Write-Host "Reading AD users from $DomainName..." `
        -ForegroundColor Cyan

    $WritableDomainControllers = @(
        Get-ADDomainController `
            -Server $DomainName `
            -Filter * `
            -ErrorAction Stop |
        Where-Object {
            -not $_.IsReadOnly
        } |
        Sort-Object HostName
    )

    if ($WritableDomainControllers.Count -eq 0) {
        Write-Warning (
            "No writable domain controllers were found for $DomainName."
        )

        continue
    }

    $DomainControllersByDomain[$DomainName] = @(
        $WritableDomainControllers |
        Select-Object -ExpandProperty HostName
    )

    $ReferenceDC = $WritableDomainControllers[0].HostName

    $DomainUsers = @(
        Get-ADUser `
            -Server $ReferenceDC `
            -Filter * `
            -Properties @(
                "DisplayName"
                "UserPrincipalName"
                "Enabled"
                "ObjectGUID"
                "SID"
                "DistinguishedName"
                "whenCreated"
                "lastLogonTimestamp"
                "pwdLastSet"
                "PasswordNeverExpires"
                "PasswordNotRequired"
                "ServicePrincipalName"
            ) `
            -ErrorAction Stop
    )

    foreach ($DomainUser in $DomainUsers) {
        $ADLastLogonTimestamp = $null
        $ADPasswordLastSet = $null
        $SIDValue = $null
        $AccountRid = $null

        if (
            $null -ne $DomainUser.lastLogonTimestamp -and
            [Int64]$DomainUser.lastLogonTimestamp -gt 0
        ) {
            $ADLastLogonTimestamp = [DateTime\]::FromFileTime(
                [Int64]$DomainUser.lastLogonTimestamp
            )
        }

        if (
            $null -ne $DomainUser.pwdLastSet -and
            [Int64]$DomainUser.pwdLastSet -gt 0
        ) {
            $ADPasswordLastSet = [DateTime\]::FromFileTime(
                [Int64]$DomainUser.pwdLastSet
            )
        }

        if ($null -ne $DomainUser.SID) {
            $SIDValue = $DomainUser.SID.Value
            $AccountRid = $SIDValue.Split("-")[-1]
        }

        $ADUsers += [PSCustomObject]@{
            Domain                  = $DomainName
            ReferenceDC             = $ReferenceDC
            DisplayName             = $DomainUser.DisplayName
            SamAccountName          = $DomainUser.SamAccountName
            UserPrincipalName       = $DomainUser.UserPrincipalName
            Enabled                 = $DomainUser.Enabled
            ObjectGUID              = $DomainUser.ObjectGUID.ToString()
            SID                     = $SIDValue
            RID                     = $AccountRid
            DistinguishedName       = $DomainUser.DistinguishedName
            WhenCreated             = $DomainUser.whenCreated
            LastLogonTimestamp      = $ADLastLogonTimestamp
            PasswordLastSet         = $ADPasswordLastSet
            PasswordNeverExpires    = $DomainUser.PasswordNeverExpires
            PasswordNotRequired     = $DomainUser.PasswordNotRequired
            HasServicePrincipalName = (
                @($DomainUser.ServicePrincipalName).Count -gt 0
            )
        }
    }

    Write-Host (
        "AD users retrieved from {0}: {1}" -f
        $DomainName,
        $DomainUsers.Count
    ) -ForegroundColor Green
}

# ------------------------------------------------------------
# Correlate AD and Microsoft Entra information
# ------------------------------------------------------------

$Results = @()

foreach ($ADUser in $ADUsers) {
    $GraphUser = $null

    if (
        -not [string\]::IsNullOrWhiteSpace(
            $ADUser.UserPrincipalName
        )
    ) {
        $UPNKey = (
            $ADUser.UserPrincipalName.Trim().ToLowerInvariant()
        )

        if ($GraphUsersByUPN.ContainsKey($UPNKey)) {
            $GraphUser = $GraphUsersByUPN[$UPNKey]
        }
    }

    $EntraObjectId = $null
    $EntraEnabled = $null
    $OnPremisesSyncEnabled = $null
    $EntraLastSuccessfulSignIn = $null
    $EntraPasswordLastChanged = $null

    if ($null -ne $GraphUser) {
        $EntraObjectId = $GraphUser.Id
        $EntraEnabled = $GraphUser.AccountEnabled
        $OnPremisesSyncEnabled = $GraphUser.OnPremisesSyncEnabled

        if (
            $null -ne $GraphUser.SignInActivity -and
            $null -ne
                $GraphUser.SignInActivity.LastSuccessfulSignInDateTime
        ) {
            $EntraLastSuccessfulSignIn = $GraphUser.SignInActivity.LastSuccessfulSignInDateTime
            
        }

        if ($null -ne $GraphUser.LastPasswordChangeDateTime) {
            $EntraPasswordLastChanged = $GraphUser.LastPasswordChangeDateTime
            
        }
    }

    # --------------------------------------------------------
    # Exclusion checks
    # --------------------------------------------------------

    $Excluded = $false
    $ExclusionReason = $null

    if ($ADUser.SamAccountName -in $BuiltInAccountNames) {
        $Excluded = $true
        $ExclusionReason = "Built-in account name"
    }
    elseif ([string]$ADUser.RID -in $BuiltInAccountRids) {
        $Excluded = $true
        $ExclusionReason = "Built-in account RID"
    }
    elseif (
        $ADUser.SamAccountName -iin
        $ExcludedSamAccountNames
    ) {
        $Excluded = $true
        $ExclusionReason = "Custom SamAccountName exclusion"
    }
    elseif (
        -not [string\]::IsNullOrWhiteSpace(
            $ADUser.UserPrincipalName
        ) -and
        $ADUser.UserPrincipalName -iin
        $ExcludedUserPrincipalNames
    ) {
        $Excluded = $true
        $ExclusionReason = "Custom UserPrincipalName exclusion"
    }

    # Service-linked users are not automatically excluded because some
    # normal user accounts may have an SPN. They are explicitly flagged.
    $RequiresServiceAccountReview = (
        $ADUser.HasServicePrincipalName -eq $true
    )

    # --------------------------------------------------------
    # AD inactivity
    # --------------------------------------------------------

    $ADActivityStatus = "Missing"

    if ($null -ne $ADUser.LastLogonTimestamp) {
        if ($ADUser.LastLogonTimestamp -lt $StaleDate) {
            $ADActivityStatus = "Old"
        }
        else {
            $ADActivityStatus = "Recent"
        }
    }

    # --------------------------------------------------------
    # Microsoft Entra inactivity
    # --------------------------------------------------------

    $EntraActivityStatus = "NotApplicable"

    if ($null -ne $GraphUser) {
        $EntraActivityStatus = "Missing"

        if ($null -ne $EntraLastSuccessfulSignIn) {
            if ($EntraLastSuccessfulSignIn -lt $StaleDate) {
                $EntraActivityStatus = "Old"
            }
            else {
                $EntraActivityStatus = "Recent"
            }
        }
    }

    # --------------------------------------------------------
    # Account age
    # --------------------------------------------------------

    $AccountOldEnough = (
        $ADUser.WhenCreated -lt $MinimumCreatedDate
    )

    # --------------------------------------------------------
    # Stale classification
    # --------------------------------------------------------

    $Classification = "Review"
    $ClassificationReason = "Activity evidence requires review"

    if ($Excluded) {
        $Classification = "Excluded"
        $ClassificationReason = $ExclusionReason
    }
    elseif ($RequiresServiceAccountReview) {
        $Classification = "Review"
        $ClassificationReason = (
            "The account has a service principal name and requires " +
            "service-owner review"
        )
    }
    elseif (-not $AccountOldEnough) {
        $Classification = "Active"
        $ClassificationReason = (
            "Account was created within the minimum account-age period"
        )
    }
    elseif (
        $ADActivityStatus -eq "Recent" -or
        $EntraActivityStatus -eq "Recent"
    ) {
        $Classification = "Active"
        $ClassificationReason = (
            "Recent activity exists in AD or Microsoft Entra ID"
        )
    }
    elseif (
        $null -ne $GraphUser -and
        $ADActivityStatus -eq "Old" -and
        $EntraActivityStatus -eq "Old"
    ) {
        $Classification = "Stale"
        $ClassificationReason = (
            "AD and Microsoft Entra activity are older than " +
            "the configured threshold"
        )
    }
    elseif (
        $null -eq $GraphUser -and
        $ADActivityStatus -eq "Old"
    ) {
        $Classification = "Review"
        $ClassificationReason = (
            "AD-only account has old activity and requires " +
            "owner validation"
        )
    }
    elseif (
        $ADActivityStatus -eq "Missing" -or
        $EntraActivityStatus -eq "Missing"
    ) {
        $Classification = "Review"
        $ClassificationReason = (
            "One or more required activity values are missing"
        )
    }

    # A disabled-stale candidate must be disabled in AD, old enough,
    # not excluded, not service-linked, and have an old replicated
    # lastLogonTimestamp.
    $DisabledStaleCandidate = (
        $ADUser.Enabled -eq $false -and
        $ADActivityStatus -eq "Old" -and
        $AccountOldEnough -eq $true -and
        $Excluded -eq $false -and
        $RequiresServiceAccountReview -eq $false
    )

    $ADPasswordAgeDays = $null
    $EntraPasswordAgeDays = $null

    if ($null -ne $ADUser.PasswordLastSet) {
        $ADPasswordAgeDays = [Math\]::Floor(
            (
                $ReportDate - $ADUser.PasswordLastSet
            ).TotalDays
        )
    }

    if ($null -ne $EntraPasswordLastChanged) {
        $EntraPasswordAgeDays = [Math\]::Floor(
            (
                $ReportDate - $EntraPasswordLastChanged
            ).TotalDays
        )
    }

    $Results += [PSCustomObject]@{
        Classification                 = $Classification
        ClassificationReason           = $ClassificationReason
        DisabledStaleCandidate         = $DisabledStaleCandidate
        DisabledStale                  = $false
        Excluded                       = $Excluded
        ExclusionReason                = $ExclusionReason
        RequiresServiceAccountReview   = $RequiresServiceAccountReview
        DisplayName                    = $ADUser.DisplayName
        UserPrincipalName              = $ADUser.UserPrincipalName
        SamAccountName                 = $ADUser.SamAccountName
        Domain                         = $ADUser.Domain
        DistinguishedName              = $ADUser.DistinguishedName
        ADEnabled                      = $ADUser.Enabled
        EntraEnabled                   = $EntraEnabled
        OnPremisesSyncEnabled          = $OnPremisesSyncEnabled
        ADActivityStatus               = $ADActivityStatus
        EntraActivityStatus            = $EntraActivityStatus
        ADLastLogonTimestamp           = $ADUser.LastLogonTimestamp
        EntraLastSuccessfulSignIn      = $EntraLastSuccessfulSignIn
        ADPasswordLastSet              = $ADUser.PasswordLastSet
        ADPasswordAgeDays              = $ADPasswordAgeDays
        EntraPasswordLastChanged       = $EntraPasswordLastChanged
        EntraPasswordAgeDays           = $EntraPasswordAgeDays
        PasswordNeverExpires           = $ADUser.PasswordNeverExpires
        PasswordNotRequired            = $ADUser.PasswordNotRequired
        WhenCreated                    = $ADUser.WhenCreated
        AccountOldEnough               = $AccountOldEnough
        LatestWhenChanged              = $null
        LatestWhenChangedDC            = $null
        ModifiedDateOld                = $null
        AllWritableDCsQueried          = $null
        WritableDCCount                = $null
        SuccessfulDCQueryCount         = $null
        FailedDomainControllers        = $null
        WhenChangedPerDC               = $null
        ADObjectGUID                   = $ADUser.ObjectGUID
        EntraObjectId                  = $EntraObjectId
        ReferenceDC                    = $ADUser.ReferenceDC
        StaleDays                      = $StaleDays
        MinimumAccountAgeDays          = $MinimumAccountAgeDays
        ReportGenerated                = $ReportDate
    }
}

# ------------------------------------------------------------
# Validate modified date for disabled-stale candidates
# ------------------------------------------------------------

$DisabledCandidates = @(
    $Results |
    Where-Object {
        $_.DisabledStaleCandidate -eq $true
    }
)

$ValidationCounter = 0

foreach ($Candidate in $DisabledCandidates) {
    $ValidationCounter++

    Write-Progress `
        -Activity "Validating disabled stale accounts" `
        -Status (
            "Account {0} of {1}" -f
            $ValidationCounter,
            $DisabledCandidates.Count
        ) `
        -CurrentOperation $Candidate.SamAccountName `
        -PercentComplete (
            ($ValidationCounter / $DisabledCandidates.Count) * 100
        )

    $WritableDCs = @(
        $DomainControllersByDomain[$Candidate.Domain]
    )

    $WhenChangedResults = @()
    $FailedDCs = @()

    foreach ($DomainController in $WritableDCs) {
        try {
            $DCUser = Get-ADUser `
                -Identity $Candidate.ADObjectGUID `
                -Server $DomainController `
                -Properties whenChanged `
                -ErrorAction Stop

            $WhenChangedResults += [PSCustomObject]@{
                DomainController = $DomainController
                WhenChanged      = [DateTime]$DCUser.whenChanged
                QuerySuccessful  = $true
            }
        }
        catch {
            $FailedDCs += $DomainController

            $WhenChangedResults += [PSCustomObject]@{
                DomainController = $DomainController
                WhenChanged      = $null
                QuerySuccessful  = $false
            }
        }
    }

    $SuccessfulResults = @(
        $WhenChangedResults |
        Where-Object {
            $_.QuerySuccessful -eq $true -and
            $null -ne $_.WhenChanged
        } |
        Sort-Object WhenChanged
    )

    $LatestWhenChanged = $null
    $LatestWhenChangedDC = $null

    if ($SuccessfulResults.Count -gt 0) {
        $LatestResult = $SuccessfulResults[-1]
        $LatestWhenChanged = $LatestResult.WhenChanged
        $LatestWhenChangedDC = $LatestResult.DomainController
    }

    $AllWritableDCsQueried = (
        $FailedDCs.Count -eq 0 -and
        $SuccessfulResults.Count -eq $WritableDCs.Count
    )

    $ModifiedDateOld = $false

    if (
        $AllWritableDCsQueried -eq $true -and
        $null -ne $LatestWhenChanged -and
        $LatestWhenChanged -lt $StaleDate
    ) {
        $ModifiedDateOld = $true
    }

    # Fail closed. The account is only marked DisabledStale when all
    # writable DCs responded and the newest whenChanged value is old.
    $Candidate.DisabledStale = (
        $ModifiedDateOld -eq $true
    )

    $Candidate.LatestWhenChanged = $LatestWhenChanged
    $Candidate.LatestWhenChangedDC = $LatestWhenChangedDC
    $Candidate.ModifiedDateOld = $ModifiedDateOld
    $Candidate.AllWritableDCsQueried = $AllWritableDCsQueried
    $Candidate.WritableDCCount = $WritableDCs.Count
    $Candidate.SuccessfulDCQueryCount = $SuccessfulResults.Count
    $Candidate.FailedDomainControllers = $FailedDCs -join "; "

    $Candidate.WhenChangedPerDC = (
        $WhenChangedResults |
        ForEach-Object {
            if ($_.QuerySuccessful) {
                "{0}={1}" -f
                $_.DomainController,
                $_.WhenChanged.ToString("o")
            }
            else {
                "{0}=QUERY_FAILED" -f $_.DomainController
            }
        }
    ) -join "; "

    if (-not $AllWritableDCsQueried) {
        $Candidate.Classification = "Review"
        $Candidate.ClassificationReason = (
            "Disabled account has old logon activity, but not all " +
            "writable DCs returned a modified date"
        )
    }
}

Write-Progress `
    -Activity "Validating disabled stale accounts" `
    -Completed

# ------------------------------------------------------------
# Export reports
# ------------------------------------------------------------

$Results |
    Sort-Object Classification, UserPrincipalName |
    Export-Csv `
        -LiteralPath $AllUsersReport `
        -NoTypeInformation `
        -Encoding UTF8

$Results |
    Where-Object {
        $_.Classification -eq "Stale"
    } |
    Sort-Object UserPrincipalName |
    Export-Csv `
        -LiteralPath $StaleUsersReport `
        -NoTypeInformation `
        -Encoding UTF8

$Results |
    Where-Object {
        $_.DisabledStale -eq $true
    } |
    Sort-Object UserPrincipalName |
    Export-Csv `
        -LiteralPath $DisabledStaleUsersReport `
        -NoTypeInformation `
        -Encoding UTF8

$Results |
    Where-Object {
        $_.DisabledStaleCandidate -eq $true -and
        $_.AllWritableDCsQueried -eq $false
    } |
    Sort-Object UserPrincipalName |
    Export-Csv `
        -LiteralPath $ValidationFailuresReport `
      UTF8

# ------------------------------------------------------------
# Disconnect and display results
# ------------------------------------------------------------

if ($GraphConnected) {
    Disconnect-MgGraph -ErrorAction SilentlyContinue |
        Out-Null
}

Write-Host ""
Write-Host "Reporting completed successfully." `
    -ForegroundColor Green

Write-Host "All-user report:" `
    -ForegroundColor Cyan
Write-Host $AllUsersReport

Write-Host "Stale-user candidate report:" `
    -ForegroundColor Cyan
Write-Host $StaleUsersReport

Write-Host "Disabled-stale candidate report:" `
    -ForegroundColor Cyan
Write-Host $DisabledStaleUsersReport

Write-Host "DC-validation failure report:" `
    -ForegroundColor Cyan
Write-Host $ValidationFailuresReport

Write-Host ""
Write-Host "No accounts were changed." `
    -ForegroundColor Yellow

Write-Host (
    "Review the reports, exclusions, ownership, mailbox use, " +
    "service dependencies, and approval evidence before remediation."
) -ForegroundColor Yellow
