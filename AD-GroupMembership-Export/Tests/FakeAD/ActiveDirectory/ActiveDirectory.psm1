# Stand-in for the RSAT ActiveDirectory module: just enough of Get-ADDomain, Get-ADGroup,
# Get-ADGroupMember, Get-ADUser and Get-ADComputer to run Export-ADGroupMembership.ps1
# end to end with realistic object shapes and real-world quirks.
$script:DomainSid = 'S-1-5-21-1111-2222-3333'
$script:Base = 'DC=contoso,DC=com'

function New-Sid([int]$Rid) { New-Object System.Security.Principal.SecurityIdentifier ("$script:DomainSid-$Rid") }
function Grp($Name, $Rid, $Scope = 'Global', $Cat = 'Security', $Ou = 'OU=Groups', $ManagedBy = $null) {
    [PSCustomObject]@{ Name = $Name; SamAccountName = $Name; DistinguishedName = "CN=$Name,$Ou,$script:Base"
        GroupCategory = $Cat; GroupScope = $Scope; SID = (New-Sid $Rid); objectClass = 'group'
        Description = "Group $Name"; Created = (Get-Date); Modified = (Get-Date); ManagedBy = $ManagedBy; mail = $null; info = $null }
}
function Usr($Sam, $Rid, $PrimaryRid = 513, $Enabled = $true, $Dept = 'IT') {
    [PSCustomObject]@{ Name = $Sam; SamAccountName = $Sam; DistinguishedName = "CN=$Sam,OU=Staff,$script:Base"
        objectClass = 'user'; SID = (New-Sid $Rid); primaryGroupID = $PrimaryRid; DisplayName = "User $Sam"
        UserPrincipalName = "$Sam@contoso.com"; EmailAddress = $null; Department = $Dept; Title = 'Tech'
        Enabled = $Enabled; LastLogonDate = (Get-Date).AddDays(-3); PasswordLastSet = (Get-Date).AddDays(-40) }
}

$script:Groups = @(
    (Grp 'Domain Users' 513 'Global' 'Security' 'CN=Users')
    (Grp 'RDS-Users' 1105 'Global' 'Security' 'OU=Groups' 'CN=Doe\, Jane,OU=Staff,DC=contoso,DC=com')
    (Grp 'HR-Staff' 1106)
    (Grp 'HR-Share-RW' 1107 'DomainLocal')
    (Grp 'Cycle-A' 1108)
    (Grp 'Cycle-B' 1109)
    (Grp 'Kiosks' 1110)
    (Grp 'Old-Empty' 1111 'Universal' 'Distribution')
    (Grp 'App-Admins' 1112 'DomainLocal')
)
$script:Users = @(
    (Usr 'alice' 2001 1105)          # primary group RDS-Users (the observed quirk)
    (Usr 'bob' 2002)
    (Usr 'carol' 2003 513 $false)    # disabled
    (Usr 'dave' 2004)
    (Usr 'erin' 2005 1105)
)
$fsp = [PSCustomObject]@{ Name = 'S-1-5-21-9999-8888-7777-1234'; SamAccountName = $null; objectClass = 'foreignSecurityPrincipal'
    DistinguishedName = "CN=S-1-5-21-9999-8888-7777-1234,CN=ForeignSecurityPrincipals,$script:Base"; SID = $null }
$ghost = [PSCustomObject]@{ Name = 'ghost'; SamAccountName = 'ghost'; objectClass = 'user'
    DistinguishedName = "CN=ghost,OU=Gone,$script:Base"; SID = (New-Sid 2999) }   # Get-ADUser will fail for this one
$gmsa = [PSCustomObject]@{ Name = 'svc-app$'; SamAccountName = 'svc-app$'; objectClass = 'msDS-GroupManagedServiceAccount'
    DistinguishedName = "CN=svc-app,CN=Managed Service Accounts,$script:Base"; SID = (New-Sid 3001) }
$pc = [PSCustomObject]@{ Name = 'KIOSK01'; SamAccountName = 'KIOSK01$'; objectClass = 'computer'
    DistinguishedName = "CN=KIOSK01,OU=PCs,$script:Base"; SID = (New-Sid 4001) }

function U($s) { $script:Users | Where-Object SamAccountName -eq $s }
function G($n) { $script:Groups | Where-Object Name -eq $n }
$script:Members = @{
    'RDS-Users'   = @((U 'alice'), (U 'erin'), (U 'bob'))      # alice/erin returned although primary (quirk)
    'HR-Staff'    = @((U 'bob'), (U 'carol'), (U 'dave'), (G 'Cycle-A'))
    'HR-Share-RW' = @((U 'bob'), (U 'dave'), $fsp, (G 'HR-Staff'))
    'Cycle-A'     = @((G 'Cycle-B'), (U 'erin'))
    'Cycle-B'     = @((G 'Cycle-A'), $ghost)
    'Kiosks'      = @($pc)
    'Old-Empty'   = @()
    'App-Admins'  = @($gmsa, (U 'dave'))
    'Domain Users'= @((U 'bob'), (U 'carol'), (U 'dave'))
}

function Get-ADDomain {
    [CmdletBinding()] param($Server, $Credential)
    [PSCustomObject]@{ DomainSID = (New-Object System.Security.Principal.SecurityIdentifier $script:DomainSid)
        DNSRoot = 'contoso.com'; NetBIOSName = 'CONTOSO'; DistinguishedName = $script:Base }
}
function Get-ADGroup {
    [CmdletBinding()] param($Filter, $Properties, $SearchBase, $Server, $Credential, [Parameter(Position = 0)]$Identity)
    if ($Identity) { return G $Identity }
    $script:Groups
}
function Get-ADGroupMember {
    [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Server, $Credential, [switch]$Recursive)
    $name = ($script:Groups | Where-Object DistinguishedName -eq $Identity).Name
    @($script:Members[$name])
}
function Get-ADUser {
    [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Filter, $Properties, $Server, $Credential)
    if ($Filter) {
        if ($Filter -match 'primaryGroupID -eq (\d+)') { $rid = [int]$Matches[1]; return @($script:Users | Where-Object { $_.primaryGroupID -eq $rid }) }
        return $script:Users
    }
    $u = $script:Users | Where-Object DistinguishedName -eq $Identity
    if (-not $u) { throw "Cannot find an object with identity: '$Identity'" }
    $u
}
function Get-ADComputer {
    [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Properties, $Server, $Credential)
    [PSCustomObject]@{ DisplayName = $null; Enabled = $true; LastLogonDate = (Get-Date) }
}
Export-ModuleMember -Function Get-ADDomain, Get-ADGroup, Get-ADGroupMember, Get-ADUser, Get-ADComputer
