# Get the AD domain from the server the script is running on
$targetDomain = $env:USERDNSDOMAIN

# Retrieve the AD connector for the local domain
$connector = Get-ADSyncConnector | Where-Object { $_.Type -eq "AD" -and $_.Name -like "*$targetDomain*" }

if (-not $connector) {
    Write-Error "No AD connector found for domain: $targetDomain"
    exit
}

$connectorGuid = $connector.Identifier
$ruleGuid = [guid]::NewGuid().ToString()

New-ADSyncRule `
    -Name "Block cloud sign-in - $targetDomain" `
    -Identifier $ruleGuid `
    -Description "If msDS-CloudExtensionAttribute10 attribute is set to BlockCloudSignIn, block cloud sign-in for $targetDomain" `
    -Direction 'Inbound' `
    -Precedence 100 `
    -SourceObjectType 'user' `
    -TargetObjectType 'person' `
    -Connector $connectorGuid `
    -LinkType 'Join' `
    -OutVariable syncRule

Add-ADSyncAttributeFlowMapping `
    -SynchronizationRule $syncRule[0] `
    -Destination 'cloudFiltered' `
    -FlowType 'Expression' `
    -ValueMergeType 'Update' `
    -Expression 'IIF(IsPresent([msDS-cloudExtensionAttribute10]),IIF([msDS-cloudExtensionAttribute10]="BlockCloudSignIn",True,False),NULL)' `
    -OutVariable syncRule

Add-ADSyncRule -SynchronizationRule $syncRule[0]

Get-ADSyncRule -Identifier $ruleGuid
