# Get-EntraPasswordPolicy

Read-only audit of a Microsoft Entra ID (Microsoft 365) tenant's password policy. Collects hybrid/sync status, per-domain expiration policy, smart lockout and password protection settings, Security Defaults state, and per-user password flags with the *effective* expiration date.

## Requirements

- Windows PowerShell 5.1 (`#Requires -Version 5.1`; the Microsoft.Graph module needs it)
- Microsoft Graph PowerShell modules. The script never installs anything. If one is missing it prints the exact command and exits with code 1:

  ```powershell
  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users -Scope CurrentUser
  ```

- Optional: `ImportExcel` (`Install-Module ImportExcel -Scope CurrentUser`). Without it the script writes one UTF-8 CSV per sheet instead of a single `.xlsx`. Excel itself is not needed.
- A sign-in that can consent to the delegated scopes below (for example a Global Reader / User Administrator via GDAP).

## Usage

```powershell
.\Get-EntraPasswordPolicy.ps1 -TenantId contoso.com
.\Get-EntraPasswordPolicy.ps1 -TenantId <tenant-guid> -OutputPath C:\Reports
```

| Parameter | Default | Description |
|---|---|---|
| `-TenantId` | (required) | Tenant ID or primary domain |
| `-OutputPath` | Current directory | Output directory. A value ending in `.xlsx` is still accepted as a full file path |
| `-LoadFunctionsOnly` | off | Define functions and exit (used by tests) |

Output: `PasswordPolicy_<tenant>_<yyyy-MM-dd_HHmmss>.xlsx` with sheets `Summary`, `Tenant`, `Domains`, `Lockout-Protection`, `Users`, `Flag-Reference`. In CSV fallback mode the files are `PasswordPolicy_<tenant>_<timestamp>-<Sheet>.csv`.

## Graph scopes and endpoints

| Scope (delegated) | Call |
|---|---|
| `Organization.Read.All` | `GET /organization` (sync status) |
| `Domain.Read.All` | `GET /domains` (expiration per domain) |
| `GroupSettings.Read.All` | `GET /groupSettings` (Password Rule Settings: smart lockout, banned list) |
| `Policy.Read.All` | `GET /policies/identitySecurityDefaultsEnforcementPolicy` |
| `User.Read.All` | `GET /users` (passwordPolicies, lastPasswordChangeDateTime, onPremisesSyncEnabled) |

## How effective expiration is decided

1. Synced (on-premises) user: **On-prem AD governs** (the default; the cloud policy only applies if `EnforceCloudPasswordPolicyForPasswordSyncedUsers` is turned on).
2. `DisablePasswordExpiration` flag on the user: **Never (user flag)**.
3. Domain `passwordValidityPeriodInDays` of 2147483647: **Never (domain policy)**.
4. Domain value **not set**: Graph documents a **90-day default**, so 90 days is used and labelled "domain default - not set". (Earlier versions treated an unset value as "never", which hid expiring passwords.)
5. Otherwise `<n> days (domain policy)`; `PasswordExpiresOn = LastPasswordChange + n`.

A UPN domain that is not in the tenant's domain list is reported as `Unknown` rather than guessed.

## Known gaps

- The setting value names inside the "Password Rule Settings" object and the `onPremisesLastPasswordSyncDateTime` organization property are not listed on the Microsoft Learn pages checked; the password-hash-sync column is blank when Graph does not return it.
- 2147483647 as the "never expires" value is the observed Int32.MaxValue sentinel, not stated on the Learn pages.

## Tests

```powershell
Invoke-Pester .\Get-EntraPasswordPolicy\Tests
```

Pester 5, Graph cmdlets mocked: effective-expiry logic, the missing-module path (prints instructions, exit 1, no connect, no install), CSV fallback, and an end-to-end run.

References are listed in the script's `.NOTES`.
