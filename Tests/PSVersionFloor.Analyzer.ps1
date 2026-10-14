<#
.SYNOPSIS
    Finds the lowest Windows PowerShell version a script's code needs, by static analysis.

.DESCRIPTION
    Dot-source this file, then call Get-PSVersionFloor on a script path. It parses the script
    (no code is executed) and returns every language feature, cmdlet, or parameter it finds
    that needs more than PowerShell 3.0, with the version it needs and the line.

    Used by PSVersionFloor.Tests.ps1 to check that each script's '#Requires -Version' is not
    lower than what its code uses. It cannot see .NET APIs newer than .NET 4.5, behavior
    differences between versions, or OS-specific modules, so a clean result is a strong
    filter, not proof - test on a real old server where it matters.

    A 5.x-only cmdlet is allowed when it sits inside an 'if' whose condition calls
    Get-Command for that cmdlet (feature detection with a fallback), because that code only
    runs where the cmdlet exists.

.NOTES
    REFERENCES
    - What's New in Windows PowerShell 5.0 (with 4.0 and 3.0 sections): classes/enums,
      -NoNewline, Get-ChildItem -Depth, New-TemporaryFile, Get-ItemPropertyValue, Format-Hex,
      Get/Set-Clipboard, New-Guid, Clear-RecycleBin, InformationAction/InformationVariable,
      New-Item -ItemType SymbolicLink, the runspace-debug and PSHostProcess cmdlets,
      Get-Command -ShowCommandInfo, -FullyQualifiedModule are 5.0; .Where()/.ForEach(),
      -PipelineVariable, Get-FileHash, Get-Process -IncludeUserName,
      Get-Module -FullyQualifiedName, -RepeatIndefinitely are 4.0
      https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
    - about_Windows_PowerShell_5.1: local user/group cmdlets and Get-ComputerInfo are 5.1
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_windows_powershell_5.1
    - about_Requires: -RunAsAdministrator is 4.0; Modules RequiredVersion is 5.0,
      MaximumVersion is 5.1
      https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_requires
    - ConvertFrom-SddlString: introduced in 5.0
      https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertfrom-sddlstring
#>

$script:PSFloorCommands = @{
    # 5.0
    'Compress-Archive' = '5.0'; 'Expand-Archive' = '5.0'; 'New-TemporaryFile' = '5.0'
    'Get-ItemPropertyValue' = '5.0'; 'Get-Clipboard' = '5.0'; 'Set-Clipboard' = '5.0'
    'Format-Hex' = '5.0'; 'ConvertFrom-SddlString' = '5.0'; 'New-Guid' = '5.0'
    'Clear-RecycleBin' = '5.0'; 'Write-Information' = '5.0'; 'ConvertFrom-String' = '5.0'
    'Get-Runspace' = '5.0'; 'Debug-Runspace' = '5.0'; 'Get-RunspaceDebug' = '5.0'
    'Enable-RunspaceDebug' = '5.0'; 'Disable-RunspaceDebug' = '5.0'
    'Enter-PSHostProcess' = '5.0'; 'Exit-PSHostProcess' = '5.0'
    # Learn does not state a version for this one; it shipped with WMF 5.0. Treated as 5.0 -
    # guarded uses (Get-Command check + Import-LocalizedData fallback) pass regardless.
    'Import-PowerShellDataFile' = '5.0'
    # 5.1
    'Get-ComputerInfo' = '5.1'; 'Get-TimeZone' = '5.1'; 'Set-TimeZone' = '5.1'
    'Get-LocalUser' = '5.1'; 'New-LocalUser' = '5.1'; 'Set-LocalUser' = '5.1'
    'Remove-LocalUser' = '5.1'; 'Rename-LocalUser' = '5.1'; 'Enable-LocalUser' = '5.1'
    'Disable-LocalUser' = '5.1'; 'Get-LocalGroup' = '5.1'; 'New-LocalGroup' = '5.1'
    'Set-LocalGroup' = '5.1'; 'Remove-LocalGroup' = '5.1'; 'Rename-LocalGroup' = '5.1'
    'Get-LocalGroupMember' = '5.1'; 'Add-LocalGroupMember' = '5.1'; 'Remove-LocalGroupMember' = '5.1'
    # 4.0
    'Get-FileHash' = '4.0'
}

function Test-InsideGetCommandGuard {
    # True when the command sits in the body of an 'if' clause whose condition calls
    # Get-Command for this same command name.
    param($CommandAst, [string]$Name)
    $node = $CommandAst
    while ($node.Parent) {
        $parent = $node.Parent
        if ($parent -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($clause in $parent.Clauses) {
                if ($clause.Item2 -eq $node) {
                    $cond = $clause.Item1.Extent.Text
                    if ($cond -match 'Get-Command' -and $cond -match [regex]::Escape($Name)) { return $true }
                }
            }
        }
        $node = $parent
    }
    return $false
}

function Get-PSVersionFloor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    $findings = New-Object System.Collections.Generic.List[object]

    $add = {
        param([string]$Version, [string]$Feature, [int]$Line)
        $findings.Add([PSCustomObject]@{ Version = [version]$Version; Feature = $Feature; Line = $Line })
    }

    $req = $ast.ScriptRequirements
    if ($req) {
        if ($req.IsElevationRequired) { & $add '4.0' '#Requires -RunAsAdministrator' 0 }
        foreach ($m in $req.RequiredModules) {
            if ($m.MaximumVersion) { & $add '5.1' "#Requires -Modules MaximumVersion ($($m.Name))" 0 }
            elseif ($m.RequiredVersion) { & $add '5.0' "#Requires -Modules RequiredVersion ($($m.Name))" 0 }
        }
    }

    foreach ($t in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)) {
        & $add '5.0' "class/enum $($t.Name)" $t.Extent.StartLineNumber
    }
    foreach ($u in $ast.UsingStatements) { & $add '5.0' "using statement" $u.Extent.StartLineNumber }

    foreach ($m in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
        $member = $m.Member.Extent.Text
        if ($m.Static -and $member -eq 'new') { & $add '5.0' "::new() $($m.Extent.Text)" $m.Extent.StartLineNumber }
        elseif (-not $m.Static -and ($member -eq 'Where' -or $member -eq 'ForEach')) {
            & $add '4.0' ".$member() method" $m.Extent.StartLineNumber
        }
    }

    foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $c.GetCommandName()
        $line = $c.Extent.StartLineNumber
        if ($name -and $script:PSFloorCommands.ContainsKey($name) -and -not (Test-InsideGetCommandGuard -CommandAst $c -Name $name)) {
            & $add $script:PSFloorCommands[$name] $name $line
        }

        $params = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                    ForEach-Object { $_.ParameterName })
        foreach ($p in $params) {
            if ($p -in 'PipelineVariable', 'pv') { & $add '4.0' "-$p" $line }
            if ($p -in 'InformationAction', 'InformationVariable', 'infa', 'iv') { & $add '5.0' "-$p" $line }
        }
        if ($name -in 'Out-File', 'Set-Content', 'Add-Content' -and $params -contains 'NoNewline') { & $add '5.0' "$name -NoNewline" $line }
        if ($name -in 'Get-ChildItem', 'gci', 'dir', 'ls' -and $params -contains 'Depth') { & $add '5.0' "$name -Depth" $line }
        if ($name -eq 'New-Item' -and $c.Extent.Text -match '(?i)-ItemType\s+[''"]?SymbolicLink') { & $add '5.0' 'New-Item -ItemType SymbolicLink' $line }
        if ($name -eq 'Get-Process' -and $params -contains 'IncludeUserName') { & $add '4.0' 'Get-Process -IncludeUserName' $line }
        if ($name -eq 'Get-Module' -and $params -contains 'FullyQualifiedName') { & $add '4.0' 'Get-Module -FullyQualifiedName' $line }
        if ($name -in 'New-JobTrigger', 'Set-JobTrigger' -and $params -contains 'RepeatIndefinitely') { & $add '4.0' "$name -RepeatIndefinitely" $line }
        if ($name -eq 'Get-Command' -and $params -contains 'ShowCommandInfo') { & $add '5.0' 'Get-Command -ShowCommandInfo' $line }
        if ($name -in 'Save-Help', 'Update-Help', 'Import-PSSession', 'Export-PSSession', 'Get-Command' -and $params -contains 'FullyQualifiedModule') {
            & $add '5.0' "$name -FullyQualifiedModule" $line }
    }

    $floor = [version]'3.0'
    foreach ($f in $findings) { if ($f.Version -gt $floor) { $floor = $f.Version } }

    [PSCustomObject]@{
        Path            = $Path
        DeclaredVersion = if ($req) { $req.RequiredPSVersion } else { $null }
        CodeFloor       = $floor
        ParseErrors     = @($errors)
        Findings        = $findings
    }
}
