# Stand-in for the RSAT ActiveDirectory module: just enough of Get-ADUser, Get-ADGroup and
# Get-ADDomain to run Get-FolderAccessCheck.ps1 end to end. Synthetic data only (contoso.com).
# Adapted from AD-UserQuickCheck\Tests\FakeAD. Behaviour is steered by environment variables:
#   FAC_DOWN      '1' = every cmdlet throws as if the domain controller were unreachable
#   FAC_OVERRIDE  JSON: { "<sam>": { "memberOf": ["<group name>", ...], "primaryGroupID": 513,
#                                     "extraTokenGroups": ["<sid>", ...] } }
#
# Directory (domain SID S-1-5-21-1111111111-2222222222-3333333333):
#   groups  Domain Users (513), FIN-Staff (1105, member of FIN-All), FIN-All (1106),
#           FIN-Managers (1107), FIN-Contractors (1108)
#   users   jdoe 'Jane Doe' (1104, memberOf FIN-Staff, primary group Domain Users)
#           nogroups 'Nora Groups' (1110, memberOf EMPTY, primary group Domain Users)
#           psmith / psmith2 'Pat Smith' (1111 / 1112, two people with the same display name)
# tokenGroups is computed the way a DC does: every group the user is in, nested, plus the
# primary group and its parents. It is returned as SecurityIdentifier objects, like the real one.

if (-not ('Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException' -as [type])) {
    Add-Type -WarningAction SilentlyContinue -TypeDefinition 'namespace Microsoft.ActiveDirectory.Management { public class ADIdentityNotFoundException : System.Exception { public ADIdentityNotFoundException(string m) : base(m) {} } }'
}

$script:DomainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
$script:Base = 'DC=contoso,DC=com'

$script:GroupTable = [ordered]@{
    'Domain Users'    = @{ Rid = 513;  MemberOf = @() }
    'FIN-Staff'       = @{ Rid = 1105; MemberOf = @('FIN-All') }
    'FIN-All'         = @{ Rid = 1106; MemberOf = @() }
    'FIN-Managers'    = @{ Rid = 1107; MemberOf = @() }
    'FIN-Contractors' = @{ Rid = 1108; MemberOf = @() }
}

function Test-FakeDown {
    if ($env:FAC_DOWN -eq '1') { throw 'Unable to contact the server. This may be because the server does not exist, it is currently down, or it does not have the Active Directory Web Services running.' }
}

function Get-GroupDn([string]$Name) { "CN=$Name,OU=Groups,$script:Base" }

function Get-FakeOverrideFor([string]$Sam) {
    if (-not $env:FAC_OVERRIDE) { return $null }
    $o = $env:FAC_OVERRIDE | ConvertFrom-Json
    $p = $o.PSObject.Properties[$Sam]
    if ($p) { return $p.Value }
    return $null
}

function Get-GroupClosure([string[]]$Names) {
    $seen = New-Object System.Collections.Generic.List[string]
    $queue = New-Object System.Collections.Queue
    foreach ($n in $Names) { $queue.Enqueue($n) }
    while ($queue.Count -gt 0) {
        $n = $queue.Dequeue()
        if ($seen.Contains($n) -or -not $script:GroupTable.Contains($n)) { continue }
        $seen.Add($n)
        foreach ($p in $script:GroupTable[$n].MemberOf) { $queue.Enqueue($p) }
    }
    return $seen.ToArray()
}

function New-FakeUser($Sam, $Display, [int]$Rid, [string[]]$MemberOf) {
    $primary = 513
    $extra = @()
    $ov = Get-FakeOverrideFor $Sam
    if ($ov) {
        if ($ov.PSObject.Properties['memberOf']) { $MemberOf = @($ov.memberOf) }
        if ($ov.PSObject.Properties['primaryGroupID']) { $primary = [int]$ov.primaryGroupID }
        if ($ov.PSObject.Properties['extraTokenGroups']) { $extra = @($ov.extraTokenGroups) }
    }
    $primaryName = @($script:GroupTable.Keys | Where-Object { $script:GroupTable[$_].Rid -eq $primary })[0]
    $closure = @(Get-GroupClosure (@($MemberOf) + @($primaryName)))
    $tokenSids = @($closure | ForEach-Object { "$script:DomainSid-$($script:GroupTable[$_].Rid)" }) + $extra
    New-Object PSObject -Property ([ordered]@{
        Name = $Display; DisplayName = $Display; SamAccountName = $Sam; UserPrincipalName = "$Sam@contoso.com"
        DistinguishedName = "CN=$Display ($Sam),OU=Staff,$script:Base"
        SID = (New-Object System.Security.Principal.SecurityIdentifier "$script:DomainSid-$Rid")
        userAccountControl = 512
        memberOf = @($MemberOf | ForEach-Object { Get-GroupDn $_ })
        primaryGroupID = $primary
        tokenGroups = @($tokenSids | ForEach-Object { New-Object System.Security.Principal.SecurityIdentifier $_ })
    })
}

function Get-FakeUsers {
    @(
        (New-FakeUser 'jdoe' 'Jane Doe' 1104 @('FIN-Staff'))
        (New-FakeUser 'nogroups' 'Nora Groups' 1110 @())
        (New-FakeUser 'psmith' 'Pat Smith' 1111 @())
        (New-FakeUser 'psmith2' 'Pat Smith' 1112 @())
    )
}

function Get-ADUser {
    [CmdletBinding()]
    param($Identity, $LDAPFilter, $Filter, $Server, $Credential, $Properties, $ResultSetSize)
    Test-FakeDown
    $all = Get-FakeUsers
    $hit = @()
    if ($Identity) {
        $hit = @($all | Where-Object { $_.DistinguishedName -eq $Identity -or $_.SamAccountName -eq $Identity })
        if ($hit.Count -eq 0) {
            throw (New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException "Cannot find an object with identity '$Identity'.")
        }
    } elseif ($LDAPFilter -match 'sAMAccountName=([^)]+)\)') {
        $v = $Matches[1]
        $hit = @($all | Where-Object { $_.SamAccountName -eq $v -or $_.UserPrincipalName -eq $v })
    } elseif ($LDAPFilter -match 'anr=([^)]+)\)') {
        $v = $Matches[1]
        $hit = @($all | Where-Object { $_.DisplayName -like "*$v*" -or $_.SamAccountName -like "$v*" })
    }
    $hit
}

function Get-ADGroup {
    [CmdletBinding()]
    param($Identity, $Server, $Credential, $Properties)
    Test-FakeDown
    $id = if ($Identity.PSObject.Properties['DistinguishedName']) { [string]$Identity.DistinguishedName } else { [string]$Identity }
    foreach ($name in $script:GroupTable.Keys) {
        $g = $script:GroupTable[$name]
        $sid = "$script:DomainSid-$($g.Rid)"
        if ($id -eq (Get-GroupDn $name) -or $id -eq $sid -or $id -eq $name) {
            return New-Object PSObject -Property ([ordered]@{
                Name = $name; SamAccountName = $name; DistinguishedName = (Get-GroupDn $name)
                SID = (New-Object System.Security.Principal.SecurityIdentifier $sid)
                MemberOf = @($g.MemberOf | ForEach-Object { Get-GroupDn $_ })
                GroupCategory = 'Security'; GroupScope = 'Global'
            })
        }
    }
    throw (New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException "Cannot find an object with identity '$id'.")
}

function Get-ADDomain {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
    Test-FakeDown
    [PSCustomObject]@{
        DNSRoot = 'contoso.com'; NetBIOSName = 'CONTOSO'; PDCEmulator = 'DC01.contoso.com'
        DomainSID = (New-Object System.Security.Principal.SecurityIdentifier $script:DomainSid)
    }
}

Export-ModuleMember -Function Get-ADUser, Get-ADGroup, Get-ADDomain
