# Stand-in for the RSAT ActiveDirectory module: just enough of Get-ADUser, Get-ADDomain,
# Get-ADDomainController and the two password-policy cmdlets to run Get-ADUserQuickCheck.ps1
# end to end. Behaviour is steered by environment variables so one module serves every scenario:
#   UQC_DOWN      comma list of DC names that throw as if unreachable
#   UQC_OVERRIDE  JSON: { "<sam>": { "<attribute>": value }, "<sam>@<DC prefix>": { ... } }
#                 changes attributes for that user everywhere, or on that one DC only
# Times are generated relative to "now" so the fixtures never go stale.

# The real cmdlets throw this type when an identity does not exist; the script keys off its name.
if (-not ('Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException' -as [type])) {
    Add-Type -WarningAction SilentlyContinue -TypeDefinition 'namespace Microsoft.ActiveDirectory.Management { public class ADIdentityNotFoundException : System.Exception { public ADIdentityNotFoundException(string m) : base(m) {} } }'
}

$script:Domain = 'contoso.com'
$script:Base = 'DC=contoso,DC=com'
$script:Dcs = @('DC01.contoso.com', 'DC02.contoso.com', 'DC03.contoso.com')

function FakeFileTime([double]$DaysAgo) { (Get-Date).AddDays(-$DaysAgo).ToFileTime() }

function New-FakeUser($Sam, $Display, $Extra = @{}) {
    $o = [ordered]@{
        Name = $Display; DisplayName = $Display; SamAccountName = $Sam; UserPrincipalName = "$Sam@contoso.com"
        DistinguishedName = "CN=$Display,OU=Staff,$script:Base"; mail = "$Sam@contoso.com"; Department = 'Sales'; Title = 'Rep'
        Manager = "CN=Boss Person,OU=Staff,$script:Base"; whenCreated = (Get-Date).AddDays(-400); whenChanged = (Get-Date).AddDays(-2)
        userAccountControl = 512; 'msDS-User-Account-Control-Computed' = 0
        lockoutTime = 0; accountExpires = [int64]0; pwdLastSet = (FakeFileTime 30)
        'msDS-UserPasswordExpiryTimeComputed' = (Get-Date).AddDays(60).ToFileTime()
        lastLogonTimestamp = (FakeFileTime 3); badPwdCount = 0; badPasswordTime = 0; lastLogon = (FakeFileTime 1)
        logonHours = $null; userWorkstations = $null; memberOf = @('CN=A', 'CN=B'); primaryGroupID = 513
        tokenGroups = @(1..25 | ForEach-Object { "S-1-5-21-1-2-3-$_" })
    }
    foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
    New-Object PSObject -Property $o
}

function Set-FakeOverride($User, [string]$Key) {
    if (-not $env:UQC_OVERRIDE) { return }
    $o = $env:UQC_OVERRIDE | ConvertFrom-Json
    $p = $o.PSObject.Properties[$Key]
    if ($p) { foreach ($a in $p.Value.PSObject.Properties) { $User | Add-Member -NotePropertyName $a.Name -NotePropertyValue $a.Value -Force } }
}

function Get-FakeUsers {
    $list = @(
        (New-FakeUser 'jdoe' 'Jane Doe')
        (New-FakeUser 'locked' 'Larry Locked' @{ 'msDS-User-Account-Control-Computed' = 0x10; lockoutTime = (FakeFileTime 0.003); badPwdCount = 5 })
        (New-FakeUser 'psmith' 'Pat Smith')
        (New-FakeUser 'psmith2' 'Pat Smith' @{ DistinguishedName = "CN=Pat Smith (2),OU=Staff,$script:Base" })
        (New-FakeUser 'wsuser' 'Wendy Station' @{ userWorkstations = 'PC-001,PC-002' })
    )
    foreach ($u in $list) { Set-FakeOverride $u $u.SamAccountName }
    $list
}

function Test-FakeDown([string]$Server) {
    if ($Server -and $env:UQC_DOWN) {
        foreach ($d in ($env:UQC_DOWN -split ',')) { if ($Server -like "$($d.Trim())*") { throw "Unable to contact the server '$Server'." } }
    }
}

# Per-DC values for the non-replicated attributes, so DCs genuinely disagree.
function Apply-DcView($User, [string]$Server) {
    $c = $User.PSObject.Copy()
    if ($User.SamAccountName -eq 'jdoe') {
        switch -Wildcard ($Server) {
            'DC01*' { $c.lastLogon = (FakeFileTime 5); $c.badPwdCount = 1 }
            'DC02*' { $c.lastLogon = (FakeFileTime 0.5); $c.badPwdCount = 0 }
            'DC03*' { $c.lastLogon = (FakeFileTime 9); $c.badPwdCount = 3 }
        }
    }
    Set-FakeOverride $c ("{0}@{1}" -f $User.SamAccountName, ($Server -split '\.')[0])
    $c
}

function Get-ADUser {
    [CmdletBinding()]
    param($Identity, $LDAPFilter, $Filter, $Server, $Credential, $Properties, $ResultSetSize)
    Test-FakeDown $Server
    $all = Get-FakeUsers
    $hit = @()
    if ($Identity) {
        $hit = @($all | Where-Object { $_.DistinguishedName -eq $Identity -or $_.SamAccountName -eq $Identity })
        if ($hit.Count -eq 0 -and $Identity -like 'CN=Boss*') { return [PSCustomObject]@{ Name = 'Boss Person'; DisplayName = 'Boss Person' } }
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
    foreach ($h in $hit) { Apply-DcView $h $Server }
}

function Get-ADDomainController {
    [CmdletBinding()]
    param($Filter, $Server, $Credential)
    foreach ($d in $script:Dcs) { [PSCustomObject]@{ HostName = $d; Name = ($d -split '\.')[0] } }
}

function Get-ADDomain {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
    [PSCustomObject]@{ DNSRoot = $script:Domain; PDCEmulator = 'DC01.contoso.com' }
}

function Get-ADUserResultantPasswordPolicy {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
    $null
}

function Get-ADDefaultDomainPasswordPolicy {
    [CmdletBinding()]
    param($Identity, $Server, $Credential)
    [PSCustomObject]@{ LockoutThreshold = 5; LockoutDuration = (New-TimeSpan -Minutes 30); LockoutObservationWindow = (New-TimeSpan -Minutes 30); MaxPasswordAge = (New-TimeSpan -Days 90) }
}

Export-ModuleMember -Function Get-ADUser, Get-ADDomainController, Get-ADDomain, Get-ADUserResultantPasswordPolicy, Get-ADDefaultDomainPasswordPolicy
