#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

function Test-IsScalarValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $true
    }

    return (
        ($Value -is [string]) -or
        ($Value -is [bool]) -or
        ($Value -is [int]) -or
        ($Value -is [long]) -or
        ($Value -is [double]) -or
        ($Value -is [decimal])
    )
}

function Test-ObjectHasOnlyScalarLeaves {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $true
    }

    if (Test-IsScalarValue -Value $Value) {
        return $true
    }

    if ($Value -is [System.Array]) {
        foreach ($item in @($Value)) {
            if (-not (Test-ObjectHasOnlyScalarLeaves -Value $item)) {
                return $false
            }
        }

        return $true
    }

    foreach ($property in @($Value.PSObject.Properties)) {
        if (-not (Test-IsScalarValue -Value $property.Value)) {
            return $false
        }
    }

    return $true
}

function Import-WorkbenchFunctions {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors.Count -gt 0) {
        throw "Unable to parse workbench script: $($parseErrors[0].Message)"
    }

    $functions = $ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)

    foreach ($function in $functions) {
        Invoke-Expression ("function global:{0} {1}" -f $function.Name, $function.Body.Extent.Text)
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$workbenchRoot = Join-Path $repoRoot "MSP-TroubleshootingWorkbench"
$checksRoot = Join-Path $workbenchRoot "checks"
$manifestPath = Join-Path $checksRoot "manifest.json"
$citrixCheckPath = Join-Path $checksRoot "Invoke-CitrixFSLogixTriageCheck.ps1"
$serverPath = Join-Path $workbenchRoot "Start-MSPTroubleshootingWorkbench.ps1"
$readmePath = Join-Path $workbenchRoot "README.md"

$manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$citrixEntry = @($manifest.checks | Where-Object { $_.checkId -eq "citrix.fslogix.triage" }) | Select-Object -First 1

Assert-True -Condition ($null -ne $citrixEntry) -Message "Manifest includes citrix.fslogix.triage."
Assert-True -Condition ($citrixEntry.script -eq "Invoke-CitrixFSLogixTriageCheck.ps1") -Message "Manifest points citrix.fslogix.triage at the triage script."
Assert-True -Condition (@($citrixEntry.inputs) -contains "affectedDevice") -Message "Manifest includes affectedDevice input."
Assert-True -Condition (@($citrixEntry.inputs) -contains "affectedUser") -Message "Manifest includes affectedUser input."
Assert-True -Condition ($citrixEntry.readOnly -eq $true) -Message "Manifest marks the Citrix/FSLogix check read-only."

Assert-True -Condition (Test-Path -LiteralPath $citrixCheckPath -PathType Leaf) -Message "Citrix/FSLogix triage script exists."

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($citrixCheckPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
Assert-True -Condition ($parseErrors.Count -eq 0) -Message "Citrix/FSLogix triage script parses cleanly."

$source = Get-Content -LiteralPath $citrixCheckPath -Raw -ErrorAction Stop
Assert-True -Condition ($source -match 'Get-Service\s+-ComputerName\s+\$AffectedDevice') -Message "Service queries use -ComputerName AffectedDevice."
Assert-True -Condition ($source -match "OpenRemoteBaseKey") -Message "Registry checks use a remote registry base key."
Assert-True -Condition ($source -match 'Get-WinEvent\s+-ComputerName\s+\$AffectedDevice') -Message "Event log queries use -ComputerName AffectedDevice."
Assert-True -Condition ($source -match 'Get-CimInstance\s+-ComputerName\s+\$AffectedDevice') -Message "Disk queries use -ComputerName AffectedDevice."
Assert-True -Condition ($source -match 'Invoke-Command\s+-ComputerName\s+\$AffectedDevice') -Message "Profile path reachability uses Invoke-Command against AffectedDevice."
Assert-True -Condition ($source -notmatch "Operator-side Test-Path") -Message "Profile path evidence does not describe operator-side Test-Path."
Assert-True -Condition ($source -notmatch "Win32_Product") -Message "Check does not use Win32_Product."

$readme = Get-Content -LiteralPath $readmePath -Raw -ErrorAction Stop
Assert-True -Condition ($readme -notmatch "operator machine|operator workstation|Operator-side") -Message "README no longer documents operator-side profile path checks."

Import-WorkbenchFunctions -Path $citrixCheckPath

$trimmedLocations = @(Split-FSLogixRegistryLocationEntries -Value "\\fs01\profiles; \\fs02\profiles ")
Assert-True -Condition ($trimmedLocations.Count -eq 2) -Message "Registry location splitter returns each semicolon-separated path."
Assert-True -Condition ($trimmedLocations[0] -eq "\\fs01\profiles") -Message "Registry location splitter preserves the first path."
Assert-True -Condition ($trimmedLocations[1] -eq "\\fs02\profiles") -Message "Registry location splitter trims leading spaces from later paths."

$smbCloudCacheLocations = @(Resolve-FSLogixProfileStorageLocations -ValueName "CCDLocations" -Value "type=smb,name=primary,connectionString=\\fs03\profiles")
Assert-True -Condition ($smbCloudCacheLocations.Count -eq 1) -Message "Cloud Cache SMB provider returns one profile storage location."
Assert-True -Condition ($smbCloudCacheLocations[0].ShouldTestPath -eq $true) -Message "Cloud Cache SMB provider is marked for SMB path reachability testing."
Assert-True -Condition ($smbCloudCacheLocations[0].TestPath -eq "\\fs03\profiles") -Message "Cloud Cache SMB provider extracts the connectionString SMB path."

$azureCloudCacheLocations = @(Resolve-FSLogixProfileStorageLocations -ValueName "CCDLocations" -Value "type=azure,name=cloud,connectionString=DefaultEndpointsProtocol=https")
Assert-True -Condition ($azureCloudCacheLocations.Count -eq 1) -Message "Cloud Cache Azure provider returns one profile storage location."
Assert-True -Condition ($azureCloudCacheLocations[0].ShouldTestPath -eq $false) -Message "Cloud Cache Azure provider is not marked for SMB path reachability testing."
Assert-True -Condition ($azureCloudCacheLocations[0].ProviderType -eq "azure") -Message "Cloud Cache Azure provider type is preserved for evidence."

$sensitiveAzureCcd = "type=azure,name=cloud,connectionString=DefaultEndpointsProtocol=https;AccountName=profiles;AccountKey=abc123;SharedAccessSignature=sv=2024&sig=secret"
$redactedAzureCloudCacheLocations = @(Resolve-FSLogixProfileStorageLocations -ValueName "CCDLocations" -Value $sensitiveAzureCcd)
Assert-True -Condition ($redactedAzureCloudCacheLocations[0].SourceValue -notmatch "abc123|sig=secret|AccountKey=|SharedAccessSignature=") -Message "Cloud Cache Azure SourceValue redacts credential-bearing connection strings."
Assert-True -Condition ($redactedAzureCloudCacheLocations[0].SourceValue -match "type=azure") -Message "Cloud Cache Azure SourceValue preserves provider type for troubleshooting."
Assert-True -Condition ($redactedAzureCloudCacheLocations[0].SourceValue -match "\[REDACTED\]") -Message "Cloud Cache Azure SourceValue records that sensitive connection data was redacted."
$redactedRegistryCcd = (ConvertTo-RedactedFSLogixRegistryValue -ValueName "CCDLocations" -Value $sensitiveAzureCcd) -join "; "
Assert-True -Condition ($redactedRegistryCcd -notmatch "abc123|sig=secret|AccountKey=|SharedAccessSignature=") -Message "Raw registry CCDLocations redaction removes credential-bearing fields."

$multiProviderCloudCacheLocations = @(Resolve-FSLogixProfileStorageLocations -ValueName "CCDLocations" -Value @("type=azure,name=cloud,connectionString=DefaultEndpointsProtocol=https;AccountName=profiles", "type=smb,name=secondary,connectionString=\\fs04\profiles "))
Assert-True -Condition ($multiProviderCloudCacheLocations.Count -eq 2) -Message "Cloud Cache parser preserves array provider entries with semicolons inside connection strings."
Assert-True -Condition ($multiProviderCloudCacheLocations[1].TestPath -eq "\\fs04\profiles") -Message "Cloud Cache parser trims SMB connectionString values from multi-value registry data."

$policyFirstKeys = @(
    [PSCustomObject]@{
        Label = "Local profile configuration"
        Found = $true
        Values = [PSCustomObject]@{
            Enabled = "0"
            VHDLocations = "\\local\profiles"
        }
    },
    [PSCustomObject]@{
        Label = "Policy profile configuration"
        Found = $true
        Values = [PSCustomObject]@{
            Enabled = "1"
            VHDLocations = "\\policy\profiles"
        }
    }
)
Assert-True -Condition ((Get-RegistryValueText -RegistryKeys $policyFirstKeys -ValueName "Enabled") -eq "1") -Message "Effective registry value lookup prefers policy Enabled over local Enabled."
Assert-True -Condition ((Get-RegistryValueText -RegistryKeys $policyFirstKeys -ValueName "VHDLocations") -eq "\\policy\profiles") -Message "Effective registry value lookup prefers policy VHDLocations over local VHDLocations."

Assert-True -Condition (Test-WinEventNoEventsFoundError -Message "No events were found that match the specified selection criteria.") -Message "WinEvent no-match errors are identified as quiet event logs."
Assert-True -Condition (-not (Test-WinEventNoEventsFoundError -Message "Access is denied.")) -Message "WinEvent access errors are not treated as quiet event logs."

$result = & $citrixCheckPath -AffectedDevice $env:COMPUTERNAME -AffectedUser "jdoe"
$expectedFields = @(
    "CheckId",
    "Name",
    "Category",
    "Status",
    "Summary",
    "Evidence",
    "RecommendedNextSteps",
    "RawOutput",
    "StartedAt",
    "FinishedAt",
    "Error"
)

foreach ($field in $expectedFields) {
    Assert-True -Condition ($result.PSObject.Properties.Name -contains $field) -Message "Citrix/FSLogix result includes $field."
}

Assert-True -Condition ($result.CheckId -eq "citrix.fslogix.triage") -Message "Citrix/FSLogix result returns the expected CheckId."
Assert-True -Condition (@("Pass", "Warn", "Fail") -contains $result.Status) -Message "Citrix/FSLogix result status is normalized."
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($result.Summary)) -Message "Citrix/FSLogix result includes a nonblank summary."
Assert-True -Condition (@($result.Evidence).Count -ge 5) -Message "Citrix/FSLogix result includes multiple evidence rows."
foreach ($section in @("Reachability", "Services", "Registry", "Events", "Disks", "ProfilePaths")) {
    foreach ($item in @($result.RawOutput.$section)) {
        Assert-True -Condition (Test-ObjectHasOnlyScalarLeaves -Value $item) -Message "Citrix/FSLogix RawOutput.$section contains scalar leaves only."
    }
}

Import-WorkbenchFunctions -Path $serverPath

function Get-CheckCatalog {
    [PSCustomObject]@{
        CheckId     = "citrix.fslogix.triage"
        Name        = "Citrix/FSLogix Triage"
        Category    = "Citrix"
        Script      = "Invoke-CitrixFSLogixTriageCheck.ps1"
        Description = "Captures Citrix/FSLogix profile triage evidence."
        ReadOnly    = $true
        Inputs      = @("affectedDevice", "affectedUser")
        ScriptPath  = $citrixCheckPath
    }
}

$runnerBody = [PSCustomObject]@{
    affectedDevice = $env:COMPUTERNAME
    affectedUser   = "jdoe"
}

$runnerResult = Invoke-WorkbenchCheck -CheckId "citrix.fslogix.triage" -Body $runnerBody -TimeoutSeconds 30
Assert-True -Condition ($runnerResult.CheckId -eq "citrix.fslogix.triage") -Message "Runner executes Citrix/FSLogix check through manifest inputs."
Assert-True -Condition ($runnerResult.RawOutput.AffectedDevice -eq $env:COMPUTERNAME) -Message "Runner maps affectedDevice to AffectedDevice."
Assert-True -Condition ($runnerResult.RawOutput.AffectedUser -eq "jdoe") -Message "Runner maps affectedUser to AffectedUser."

if ($script:Failures.Count -gt 0) {
    throw ("Task 7 regression harness failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Task 7 regression harness completed." -ForegroundColor Green
