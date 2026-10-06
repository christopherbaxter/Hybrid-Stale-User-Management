# Hybrid Stale User Management

A small, report-only PowerShell script for identifying on-premises Active Directory user accounts that may require stale-account review. When Microsoft Graph is enabled, the report is enriched with matching Microsoft Entra ID activity.

> [!CAUTION]
> The script does **not** disable, enable, move, delete, reset, license, or otherwise modify an identity. Review every candidate with the account owner and follow your organisation's change process before taking action.

## Design goals

- Keep the script linear and easy to audit; it contains no custom functions.
- Retain the useful workflow of the earlier operational script: collect AD data, collect Entra data, correlate by UPN, classify, and export reports.
- Require evidence from both AD and Entra before calling an enabled account stale.
- Keep missing or ambiguous data in manual review instead of treating it as inactivity.
- Exclude built-in and explicitly listed accounts from candidate reports.
- Contain no customer names, domains, tenants, server names, internal paths, real accounts, or production output.

## Scope

The script is **Active Directory-led**. It enumerates user objects in every domain returned by `Get-ADForest`, using one discovered writable domain controller per domain. It then optionally enriches each AD user with Microsoft Entra ID data by matching a normalized user principal name (UPN).

It does not inventory:

- cloud-only Entra users;
- Entra guests without a matching AD user;
- managed service accounts or group managed service accounts;
- service principals or application registrations;
- computer accounts; or
- identities outside the current AD forest.

A UPN match is accepted only when exactly one Entra user is found and `OnPremisesSyncEnabled` is `True`. Other cases are sent to manual review.

## What the script does

1. Calculates two configurable cut-off dates:
   - `StaleAfterDays`, default `90`;
   - `DisabledReviewAfterDays`, default `90`.
2. Loads optional exclusions from `scripts/UserExclusions.csv`.
3. Retrieves selected AD user attributes from one writable domain controller in each forest domain.
4. Unless `-SkipMicrosoftGraph` is used, retrieves Entra users and `signInActivity` with Microsoft Graph.
5. Matches AD and Entra records by normalized UPN.
6. Applies built-in-account and explicit exclusions.
7. Classifies each AD user.
8. Exports five CSV reports.

All comparisons are performed with `DateTime` values. Formatting occurs only when PowerShell serializes the final objects to CSV.

## Classification rules

### Enabled stale candidate

An account is classified as `Enabled stale candidate - owner validation required` only when all of the following are true:

- the AD account is enabled;
- the AD account was created on or before the stale cut-off;
- `lastLogonTimestamp` is available and on or before the stale cut-off;
- exactly one Entra user matches the AD UPN;
- the Entra match has `OnPremisesSyncEnabled` set to `True`;
- `lastSuccessfulSignInDateTime` is available and on or before the stale cut-off; and
- no exclusion applies and no manual-review flag is present.

A newly created but unused account is therefore not marked stale merely because it has no old sign-in history.

### Disabled aged candidate

A disabled AD account is classified as `Disabled aged candidate - owner validation required` when its `whenChanged` value is on or before the disabled-review cut-off and no exclusion applies.

`whenChanged` is **not** a dedicated “disabled since” timestamp. Password resets, group-membership changes, and other updates can change it. This report is therefore a review queue, not proof that an account has been disabled for the configured number of days.

### Manual review

An enabled account is sent to manual review when the script detects any of these conditions:

- privileged or formerly privileged account (`adminCount = 1`);
- possible service account, based on an SPN or a generic `svc`/`service` prefix;
- missing AD UPN;
- Microsoft Graph data was skipped;
- no Entra UPN match;
- multiple Entra UPN matches;
- Entra match not confirmed as synchronized; or
- missing AD or Entra activity data.

Service-account detection is intentionally conservative. Confirmed service, mailbox, emergency-access, shared, or leave-related accounts should be placed in the explicit exclusions file.

### Excluded

The script excludes:

- well-known built-in account RIDs `500`, `501`, `502`, and `503`;
- AD objects marked as critical system objects; and
- accounts listed in `scripts/UserExclusions.csv`.

## Prerequisites

- Windows PowerShell 5.1 or later.
- The Active Directory PowerShell module.
- Network and directory permissions to read every target AD domain.
- For Entra enrichment:
  - `Microsoft.Graph.Authentication`;
  - `Microsoft.Graph.Users`;
  - delegated consent for `User.Read.All` and `AuditLog.Read.All`; and
  - access to the tenant data exposed by `signInActivity`.

Install the Microsoft Graph modules if required:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
```

## Explicit exclusions

Copy the example outside source control before adding operational account names:

```powershell
Copy-Item .\examples\UserExclusions.example.csv .\scripts\UserExclusions.csv
```

The CSV requires `SamAccountName`. The remaining columns document why the exclusion exists and when it should be reviewed:

```csv
SamAccountName,Reason,Owner,ReviewDate
svc-example,Application dependency,Application owner,2027-03-31
```

`scripts/UserExclusions.csv` is ignored by Git because a real exclusions file may contain organisational data.

## Running the script

Run from an administrative workstation that has the required modules and connectivity:

```powershell
.\scripts\Get-HybridStaleUserReport.ps1
```

Use different review periods and paths when required:

```powershell
.\scripts\Get-HybridStaleUserReport.ps1 `
    -StaleAfterDays 120 `
    -DisabledReviewAfterDays 180 `
    -OutputPath 'D:\IdentityReview\Output' `
    -ExclusionsPath 'D:\IdentityReview\UserExclusions.csv'
```

Run without Entra enrichment only when cloud data cannot be collected:

```powershell
.\scripts\Get-HybridStaleUserReport.ps1 -SkipMicrosoftGraph
```

With `-SkipMicrosoftGraph`, enabled users cannot become enabled stale candidates because cloud inactivity has not been established; they are sent to manual review.

## Reports produced

Each file includes the run date in `yyyy-MM-dd` format.

| Report | Contents |
|---|---|
| `AllUsers-<date>.csv` | Every AD user evaluated, with AD, Entra, exclusion, and classification fields. |
| `EnabledStaleCandidates-<date>.csv` | Enabled accounts whose available AD and Entra activity are both older than the stale cut-off. |
| `DisabledAgedCandidates-<date>.csv` | Disabled accounts whose AD `whenChanged` value is older than the disabled-review cut-off. |
| `ManualReview-<date>.csv` | Enabled accounts with missing, ambiguous, privileged, service-like, or unsynchronized identity data. |
| `ExcludedUsers-<date>.csv` | Built-in, critical, and explicitly excluded accounts. |

The output folder is ignored by Git. Reports can contain personal and organisational data and must not be committed to a public repository.

## Recommended operating process

1. Run the report monthly.
2. Confirm that Entra collection completed; do not interpret an on-premises-only report as proof of inactivity.
3. Review `ManualReview` first and update the private exclusions file for confirmed non-user identities.
4. Validate candidate ownership and business use with the appropriate application, mailbox, HR, and service owners.
5. Prepare separate approved change lists for disablement and deletion.
6. Keep disabled accounts in place unless an established organisational design requires otherwise.
7. Record the actual disablement date in an authoritative system if deletion depends on elapsed disabled time. Do not treat `whenChanged` as that record.
8. Use a separate, approved remediation process. This repository intentionally provides no remediation commands.

## Important limitations

- `lastLogonTimestamp` is replicated for broad inactivity searches and is not updated at every logon. It is not suitable for exact forensic timing.
- `lastSuccessfulSignInDateTime` depends on Microsoft Graph permissions and data availability. Missing data is not proof of inactivity.
- UPN correlation is convenient but is not a substitute for validating the organisation's source anchor and synchronization design.
- One writable domain controller is queried per domain. The script does not perform authoritative per-DC `lastLogon` aggregation.
- `whenChanged` indicates the last directory-object modification, not specifically when the account was disabled.
- Classification is evidence for human review, not authorization to change an account.

## Public Microsoft references

- [Get-ADUser](https://learn.microsoft.com/powershell/module/activedirectory/get-aduser)
- [Get-ADForest](https://learn.microsoft.com/powershell/module/activedirectory/get-adforest)
- [Get-ADDomainController](https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontroller)
- [Get-MgUser](https://learn.microsoft.com/powershell/module/microsoft.graph.users/get-mguser)
- [Microsoft Graph signInActivity resource](https://learn.microsoft.com/graph/api/resources/signinactivity)
- [Active Directory lastLogonTimestamp attribute](https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp)

## Repository structure

```text
.
├── examples/
│   └── UserExclusions.example.csv
├── scripts/
│   └── Get-HybridStaleUserReport.ps1
├── .gitignore
├── LICENSE
├── README.md
└── SECURITY.md
```

## Security

Do not commit credentials, tokens, tenant identifiers, real account data, directory names, reports, transcripts, screenshots, or internal links. See [SECURITY.md](SECURITY.md) for responsible disclosure guidance.

## Licence

Released under the [MIT License](LICENSE).
