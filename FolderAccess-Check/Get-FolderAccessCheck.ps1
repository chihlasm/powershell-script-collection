#Requires -Version 3.0
<#
.SYNOPSIS
    STUB (SQ-004): "Can this user open this folder?" access evidence and hedged verdict.
.DESCRIPTION
    Test stubs only. Every function throws until the item is implemented.
.PARAMETER Identity
    User to check.
.PARAMETER Path
    Full UNC path of the folder.
.EXAMPLE
    .\Get-FolderAccessCheck.ps1 -Identity jdoe -Path '\FS01\Finance\Budgets 2027'
.NOTES
    Not implemented yet.
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 1)]
    [string]$Path,

    [ValidateSet('Read', 'Modify')]
    [string]$Access = 'Read',

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputPath,

    [ValidateRange(1, 50)]
    [int]$MaxNestingDepth = 10,

    [Parameter(ParameterSetName = 'Load')]
    [switch]$LoadFunctionsOnly
)

function Split-FolderAccessPath { param([string]$Path, [string[]]$DomainName) throw 'not implemented' }
function Get-UserSidSet { param([object]$ResolvedUser, [string]$Server, [System.Management.Automation.PSCredential]$Credential, [int]$MaxNestingDepth = 10) throw 'not implemented' }
function Get-FolderAccessAssessment {
    param(
        [string]$UserName, [string]$DisplayName, [string]$Path, [string]$Server,
        [string]$PathKind = 'Normal', [string]$Access = 'Read', [bool]$ServerIsDomainController = $false,
        [string[]]$UserSids, [hashtable]$GroupPaths = @{},
        [object[]]$FolderAces, [string]$FolderError, [bool]$FolderConditional = $false,
        [object[]]$ShareAces, [string]$ShareDaclState = 'Present', [string]$ShareError,
        [hashtable]$LocalGroupExpansions = @{}
    )
    throw 'not implemented'
}
function Invoke-FolderAccessCheck {
    param(
        [string]$Identity, [string]$Path, [string]$Access = 'Read', [string]$Server,
        [System.Management.Automation.PSCredential]$Credential, [string]$OutputPath,
        [int]$MaxNestingDepth = 10, [datetime]$Now = (Get-Date)
    )
    throw 'not implemented'
}
function Write-FolderAccessConsole { param([object]$Result) throw 'not implemented' }

if ($LoadFunctionsOnly) { return }

throw 'not implemented'
