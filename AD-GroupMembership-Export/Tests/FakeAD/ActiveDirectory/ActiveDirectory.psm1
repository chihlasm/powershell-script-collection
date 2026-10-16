# Stand-in for the RSAT ActiveDirectory module: just enough of Get-ADDomain, Get-ADGroup,
# Get-ADGroupMember, Get-ADUser and Get-ADComputer to run Export-ADGroupMembership.ps1
# end to end with realistic object shapes and real-world quirks.
$script:DomainSid = 'S-1-5-21-1111-2222-3333'
$script:Base = 'DC=contoso,DC=com'

function New-Sid([int]$Rid) { New-Object System.Security.Principal.SecurityIdentifier ("$script:DomainSid-$Rid") }
function Grp($Name, $Rid, $Scope = 'Global', $Cat = 'Security', $Ou = 'OU=Groups', $ManagedBy = $null) {
    [PSCustomObject]@{ Name = $Name; SamAccountName = $Name; DistinguishedName = "CN=$Name,$Ou,$script:Base"
        GroupCategory = $Cat; GroupScope = $Scope; SID = (New-Sid $Rid); objectClass = 'group'
        Description = "Group $Name"; Created = [datetime]'2020-01-02 03:04:05'; Modified = [datetime]'2024-06-07 08:09:10'; ManagedBy = $ManagedBy; mail = $null; info = $null
        MemberOf = @() }
}
function Usr($Sam, $Rid, $PrimaryRid = 513, $Enabled = $true, $Dept = 'IT', $Office = $null) {
    [PSCustomObject]@{ Name = $Sam; SamAccountName = $Sam; DistinguishedName = "CN=$Sam,OU=Staff,$script:Base"
        objectClass = 'user'; SID = (New-Sid $Rid); primaryGroupID = $PrimaryRid; DisplayName = "User $Sam"
        UserPrincipalName = "$Sam@contoso.com"; EmailAddress = $null; Department = $Dept; Title = 'Tech'; Office = $Office
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
    (Grp 'Administrators' 544 'DomainLocal' 'Security' 'CN=Builtin')   # protected built-in; SID fixed below
    (Grp 'IT-Admins' 1120)
)
# Chain-01 contains Chain-02 ... contains Chain-10: a 10-deep chain.
$script:Groups += @(1..10 | ForEach-Object { Grp ('Chain-{0:D2}' -f $_) (1200 + $_) })
($script:Groups | Where-Object Name -eq 'Administrators').SID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$script:Users = @(
    (Usr 'alice' 2001 1105 $true 'IT' 'Berlin HQ')          # primary group RDS-Users (the observed quirk)
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
    'IT-Admins'   = @((G 'HR-Staff'))
    'Administrators' = @((G 'IT-Admins'))
    'Chain-10'    = @((U 'dave'))
}
for ($i = 1; $i -le 9; $i++) { $script:Members[('Chain-{0:D2}' -f $i)] = @((G ('Chain-{0:D2}' -f ($i + 1)))) }
# memberOf is the back-link of member: derive it so both views of the directory agree.
foreach ($parentName in @($script:Members.Keys)) {
    $parent = G $parentName
    foreach ($m in $script:Members[$parentName]) {
        if ($m -and $m.objectClass -eq 'group') { $m.MemberOf = @($m.MemberOf) + @($parent.DistinguishedName) }
    }
}

function Get-ADDomain {
    [CmdletBinding()] param($Server, $Credential)
    [PSCustomObject]@{ DomainSID = (New-Object System.Security.Principal.SecurityIdentifier $script:DomainSid)
        DNSRoot = 'contoso.com'; NetBIOSName = 'CONTOSO'; DistinguishedName = $script:Base }
}
function Get-ADGroup {
    [CmdletBinding()] param($Filter, $Properties, $SearchBase, $Server, $Credential, [Parameter(Position = 0)]$Identity)
    if ($Identity) {
        $g = $script:Groups | Where-Object { $_.DistinguishedName -eq $Identity -or $_.Name -eq $Identity }
        if (-not $g) { throw "Cannot find an object with identity: '$Identity'" }
        return $g
    }
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
