# Get-AzureFilesFSLogixProfiles

Lists every FSLogix profile container (`.vhdx` / `.vhd`) on a client's Azure file shares, showing **who it belongs to, how big it is, and when it was last used**.

- **No server needed.** It reads the share through Azure, so you don't have to map a drive or sign in to a file server.
- **No need to know where the profiles are.** Give it the client's tenant and it finds the subscriptions, storage accounts and shares on its own.
- **Read-only.** It never changes, moves or deletes anything.

---

## Quick start (ASTs)

1. Open **PowerShell** on your workstation. It doesn't need to be run as administrator.
2. Go to the folder that holds the script:
   ```powershell
   cd "C:\Path\To\Get-AzureFilesFSLogixProfiles"
   ```
3. Run it with the client's tenant domain:
   ```powershell
   .\Get-AzureFilesFSLogixProfiles.ps1 -TenantId clientname.onmicrosoft.com
   ```
4. A browser window opens. Sign in with your admin account **for that client**.
   - If PowerShell then asks you to pick a subscription, press **Enter**. The script scans all of them anyway.
5. When it finishes, open the **.csv** file it names at the end. Each row is one profile disk.

The first run may install two Microsoft modules (`Az.Accounts`, `Az.Storage`) for your user. Let it finish.

> If you get *"running scripts is disabled on this system"*, run this once and try again:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Sign-in window says "Keep your account secure / Update your browser"

Your admin account in **that** tenant hasn't set up MFA yet. The small Windows sign-in window can't run the MFA setup, and Azure PowerShell requires MFA. To fix it:

1. Close the window.
2. Open an **InPrivate** Edge window, go to **https://aka.ms/mysecurityinfo** and sign in with the same account. Finish the MFA setup.
3. Run the script again, adding `-UseDeviceAuthentication`:
   ```powershell
   .\Get-AzureFilesFSLogixProfiles.ps1 -TenantId clientname.onmicrosoft.com -UseDeviceAuthentication
   ```
   PowerShell shows a code. Open **https://microsoft.com/devicelogin** in your browser, enter the code and sign in.

`-UseDeviceAuthentication` also helps whenever the sign-in window misbehaves or signs you in with the wrong cached account.

---

## What you get

**`FSLogixProfiles_<tenant>_<date>.csv`** has one row per profile disk, largest first:

| Column | Meaning |
|---|---|
| UserName | User the disk belongs to (from the folder/file name) |
| SID | User's security ID (from the folder name) |
| ContainerType | `Profile` = the user's profile disk. `ODFC` = the Office/Outlook cache disk. `Other` = some other VHD |
| SizeGB / SizeBytes | Current size of the disk file |
| LastModified | When the disk was last written to (roughly the user's last sign-out) |
| DaysSinceModified | Days since LastModified |
| FolderPath, Share, StorageAccount, ResourceGroup, Subscription | Where the file is |
| UncPath | The `\\account.file.core.windows.net\share\...` path, for anyone who *can* map it |

**`FSLogixProfiles_<tenant>_<date>.log`** contains the run output, a **per-share totals** table (file count and GB) and every share that could **not** be read, along with the reason.

---

## Permissions: what your account needs

This uses **Azure** permissions, which are separate from M365/Entra admin roles. Being a Global Administrator does **not** by itself give access to the client's storage accounts.

| To... | Your account needs one of these Azure roles |
|---|---|
| Find the storage accounts and shares | **Reader** (or higher) on the subscription or resource group |
| Read inside the shares (option A) | **Owner**, **Contributor**, or **Storage Account Key Operator Service Role** on the storage account |
| Read inside the shares (option B) | **Storage File Data Privileged Reader** on the storage account |

The script tries option A first and falls back to option B on its own.

If you only have Global Admin, the tenant's Global Admin can turn on *Access management for Azure resources* in **Entra ID > Properties**. That grants User Access Administrator at the root, which lets them assign one of the roles above. Escalate to the engineer who owns the client's Azure environment before doing this.

---

## When a share shows "No access"

The log tells you which share failed and why. The usual causes:

| Log says | What it means | What to do |
|---|---|---|
| *not authorized to perform this operation* / *AuthorizationFailure* | The storage account firewall only allows certain networks or a private endpoint | Run the script from a machine inside the client network (e.g. a session host), or ask an engineer |
| *File endpoint did not resolve* | The account is reachable **only** over a private endpoint | Run from inside the client network |
| *AuthorizationPermissionMismatch* | You have Azure access but no data role | Get **Storage File Data Privileged Reader** assigned |
| *Shared key access is disabled* | The client turned off account keys | Rerun with `-AuthMode EntraId` (needs the data role above) |
| *No enabled subscriptions visible* | Your account has no Azure roles in this tenant | See **Permissions** above |

---

## Narrowing the scan (optional)

Use these when you already know where the profiles are, or when a tenant has many storage accounts.

```powershell
# One storage account
.\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -StorageAccountName stavdprofiles01

# One share in that account
.\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -StorageAccountName stavdprofiles01 -ShareName fslogix

# Profiles kept in a subfolder of the share
.\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -ShareName data -Path "Profiles"

# Save the report somewhere specific
.\Get-AzureFilesFSLogixProfiles.ps1 -TenantId contoso.com -OutputPath C:\Temp
```

| Parameter | Default | Purpose |
|---|---|---|
| `-TenantId` | *(required)* | Client tenant domain or GUID |
| `-SubscriptionId` | all enabled | Limit to specific subscriptions (ID or name) |
| `-StorageAccountName` | all | Limit to specific storage accounts |
| `-ShareName` | all SMB shares | Limit to specific shares |
| `-Path` | share root | Start in a subfolder |
| `-MaxDepth` | 3 | How many folder levels to search. FSLogix normally keeps disks one level down |
| `-AuthMode` | Auto | `Auto`, `Key`, or `EntraId` (see Permissions) |
| `-OutputPath` | current folder | Where the CSV and log go |
| `-UseDeviceAuthentication` | off | Sign in with a code in your normal browser instead of the Windows sign-in window |

---

## How it works (for engineers)

1. `Connect-AzAccount -TenantId` signs in interactively, then `Get-AzSubscription` lists the enabled subscriptions.
2. `Get-AzStorageAccount` runs per subscription, then `Get-AzRmStorageShare` runs per account. Both are management-plane calls, so share discovery works even when the storage firewall blocks the data plane. NFS shares are skipped.
3. Data-plane context: the script uses the account key from `Get-AzStorageAccountKey` when the caller has `listkeys` and shared key access is not disabled. Otherwise it uses `New-AzStorageContext -UseConnectedAccount -EnableFileBackupRequestIntent`, which Azure Files requires for OAuth.
4. `Get-AzStorageFile` walks the share recursively to `-MaxDepth`. `Length` and `LastModified` come from the list response, so there's no extra call per file.
5. User and SID are parsed from FSLogix's default folder naming, `%sid%_%username%` or `%username%_%sid%` when *FlipFlopProfileDirectoryName* is set. When the folder name doesn't match, the user comes from the file name (`Profile_%username%` / `ODFC_%username%`). Entra-only users (`S-1-12-1-…` SIDs) are handled.

**Size note:** `SizeGB` is the size of the VHDX file on the share, the same number Storage Explorer or File Explorer shows. A dynamically expanding disk's file grows with use but doesn't shrink when data is deleted inside it.

References:
- [Get-AzStorageFile](https://learn.microsoft.com/powershell/module/az.storage/get-azstoragefile)
- [New-AzStorageContext](https://learn.microsoft.com/powershell/module/az.storage/new-azstoragecontext)
- [Get-AzRmStorageShare](https://learn.microsoft.com/powershell/module/az.storage/get-azrmstorageshare)
- [Authorize with Microsoft Entra ID (Azure Files RBAC)](https://learn.microsoft.com/rest/api/storageservices/authorize-with-azure-active-directory)
- [Manage storage account access keys](https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage)
- [FSLogix configuration settings](https://learn.microsoft.com/fslogix/reference-configuration-settings)
