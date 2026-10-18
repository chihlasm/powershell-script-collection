# Stand-in for the RSAT ActiveDirectory module: just enough of Get-ADUser, Get-ADGroup and
# Get-ADDomain to run Get-FolderAccessCheck.ps1 end to end. Synthetic data only (contoso.com).
# Adapted from AD-UserQuickCheck\Tests\FakeAD. Behaviour is steered by environment variables:
#   FAC_DOWN      '1' = every cmdlet throws as if the domain controller were unreachable
#   FAC_OVERRIDE  JSON: { "<sam>": { "memberOf": ["<group name>", ...], "primaryGroupID": 513,
#                                     "extraTokenGroups": ["<sid>", ...],
#                                     "lastLogon": "<FILETIME>", "lastLogonDC02": "<FILETIME>" } }
#                 lastLogon is per DC and not replicated: DC01 answers "lastLogon", DC02 answers
#                 "lastLogonDC02". Both default to 0 (never signed in).
#
# Directory (domain SID S-1-5-21-1111111111-2222222222-3333333333):
#   groups  Domain Users (513), FIN-Staff (1105, member of FIN-All), FIN-All (1106),
#           FIN-Managers (1107), FIN-Contractors (1108), Domain Admins (512, adminCount 1),
#           FIN-Admins (1109, member of Domain Admins), FIN-Ops (1113, adminCount 1).
#           Domain Computers (515). Each group carries Members (how many DNs its `member` attribute returns) and AdminCount.
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
    'Domain Users'    = @{ Rid = 513;  MemberOf = @(); Members = 400; AdminCount = 0 }
    'FIN-Staff'       = @{ Rid = 1105; MemberOf = @('FIN-All'); Members = 20; AdminCount = 0 }
    'FIN-All'         = @{ Rid = 1106; MemberOf = @(); Members = 80; AdminCount = 0 }
    'FIN-Managers'    = @{ Rid = 1107; MemberOf = @(); Members = 12; AdminCount = 0 }
    'FIN-Contractors' = @{ Rid = 1108; MemberOf = @(); Members = 7; AdminCount = 0 }
    'Domain Computers' = @{ Rid = 515; MemberOf = @(); Members = 90; AdminCount = 0 }
    'Domain Admins'   = @{ Rid = 512;  MemberOf = @(); Members = 3; AdminCount = 1 }
    'FIN-Admins'      = @{ Rid = 1109; MemberOf = @('Domain Admins'); Members = 5; AdminCount = 0 }
    'FIN-Ops'         = @{ Rid = 1113; MemberOf = @(); Members = 4; AdminCount = 1 }
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
    $logon = 0L; $logon2 = 0L
    $ov = Get-FakeOverrideFor $Sam
    if ($ov) {
        if ($ov.PSObject.Properties['memberOf']) { $MemberOf = @($ov.memberOf) }
        if ($ov.PSObject.Properties['primaryGroupID']) { $primary = [int]$ov.primaryGroupID }
        if ($ov.PSObject.Properties['extraTokenGroups']) { $extra = @($ov.extraTokenGroups) }
        if ($ov.PSObject.Properties['lastLogon']) { $logon = [int64]$ov.lastLogon }
        if ($ov.PSObject.Properties['lastLogonDC02']) { $logon2 = [int64]$ov.lastLogonDC02 }
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
        lastLogon = $logon; lastLogonDC02 = $logon2
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
    foreach ($h in $hit) {
        if ($Server -like 'DC02*') { $h.lastLogon = $h.lastLogonDC02 }
    }
    $hit
}

function Get-ADDomainController {
    [CmdletBinding()]
    param($Filter, $Server, $Credential)
    Test-FakeDown
    foreach ($d in 'DC01.contoso.com', 'DC02.contoso.com') { [PSCustomObject]@{ HostName = $d; Name = ($d -split '\.')[0] } }
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
                member = @(1..$g.Members | ForEach-Object { "CN=Member$_,OU=Staff,$script:Base" })
                adminCount = $g.AdminCount
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

Export-ModuleMember -Function Get-ADUser, Get-ADGroup, Get-ADDomain, Get-ADDomainController
