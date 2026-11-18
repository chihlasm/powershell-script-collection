#Requires -Version 5.1
<#
    The server list for Server Event Timeline: computers read from Active Directory, the
    suggestions shown while typing, the notes beside each server, reading a server list file,
    and the background AD and DNS lookups. Dot-sourced by ServerEventTimeline.Core.ps1, so the
    window, the engine and the tests all get it. Nothing here touches the UI.

    REFERENCES
      lastLogonTimestamp is only updated when the stored value is older than
      msDS-LogonTimeSyncInterval (14 days by default, less a random 0-5), so "days since
      sign-in" is accurate to about two weeks:
        https://learn.microsoft.com/windows/win32/adschema/a-lastlogontimestamp
      Get-ADComputer / Get-ADDomainController / Get-ADDomain (-Server, -Credential, -Filter, -Properties):
        https://learn.microsoft.com/powershell/module/activedirectory/get-adcomputer
        https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontroller
        https://learn.microsoft.com/powershell/module/activedirectory/get-addomain
      An IP address in a remote command uses NTLM: WinRM then needs HTTPS or TrustedHosts and
      an explicit -Credential, so a trusted DNS name is searched instead where there is one:
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting#how-to-use-an-ip-address-in-a-remote-command
#>

$script:ServerListFilePath = $PSCommandPath

function ConvertTo-DirectoryEntry {
    <# One computer account from Get-ADComputer, in the shape the server list uses. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Computer, [string[]]$DomainControllers, [datetime]$Now = [datetime]::UtcNow)

    $name = [string]$Computer.Name
    $dns = if ([string]$Computer.DNSHostName) { [string]$Computer.DNSHostName } else { $name }
    $os = [string]$Computer.OperatingSystem
    $dcs = @($DomainControllers | Where-Object { $_ })
    $isDc = $false
    foreach ($dc in $dcs) {
        $dcShort = ([string]$dc).Split('.')[0]
        if ([string]::Equals($dc, $dns, 'OrdinalIgnoreCase') -or [string]::Equals($dcShort, $name, 'OrdinalIgnoreCase')) { $isDc = $true; break }
    }

    # 0, absent and Int64.MaxValue all mean "never signed in" (see REFERENCES).
    $days = $null
    $raw = $Computer.lastLogonTimestamp
    if ($null -ne $raw) {
        $ticks = [int64]$raw
        if ($ticks -gt 0 -and $ticks -lt [int64]::MaxValue) {
            $days = [int][math]::Floor(($Now.ToUniversalTime() - [datetime]::FromFileTimeUtc($ticks)).TotalDays)
        }
    }

    $dn = [string]$Computer.DistinguishedName
    $comma = $dn.IndexOf(',')
    # A comma escaped as "\," belongs to the name, not the path.
    while ($comma -gt 0 -and $dn[$comma - 1] -eq '\') { $comma = $dn.IndexOf(',', $comma + 1) }
    $ou = if ($comma -ge 0) { $dn.Substring($comma + 1) } else { '' }

    [PSCustomObject]@{
        Name              = $name
        DnsName           = $dns
        OS                = $os
        Enabled           = [bool]$Computer.Enabled
        IsServer          = $os -like '*Server*'
        IsDC              = $isDc
        DaysSinceLogon    = $days
        DistinguishedName = $dn
        OU                = $ou
    }
}

function Find-ServerSuggestions {
    <#
        What to suggest while typing: enabled servers from AD whose name starts with the text,
        then those containing it, then servers searched before (from the Recent lists).
    #>
    [CmdletBinding()]
    param([object[]]$Directory, [string[]]$Recent, [AllowEmptyString()][string]$Text, [int]$Max = 8)

    $t = ([string]$Text).Trim()
    if (-not $t) { return @() }
    $ci = [StringComparison]::OrdinalIgnoreCase
    $starts = New-Object System.Collections.Generic.List[object]
    $contains = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Directory | Where-Object { $_ -and $_.Enabled -and $_.IsServer } | Sort-Object DnsName)) {
        if ($e.Name.StartsWith($t, $ci) -or $e.DnsName.StartsWith($t, $ci)) { $starts.Add($e) }
        elseif ($e.DnsName.IndexOf($t, $ci) -ge 0) { $contains.Add($e) }
    }

    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in ([object[]]$starts.ToArray() + [object[]]$contains.ToArray())) {
        if ($out.Count -ge $Max) { break }
        [void]$seen.Add($e.DnsName); [void]$seen.Add($e.Name)
        $out.Add([PSCustomObject]@{ Name = $e.DnsName; Detail = $e.OS })
    }
    foreach ($list in @($Recent | Where-Object { $_ })) {
        foreach ($n in @(ConvertTo-ServerList -Text $list)) {
            if ($out.Count -ge $Max) { break }
            if ($n.IndexOf($t, $ci) -lt 0) { continue }
            if ($seen.Contains($n) -or $seen.Contains($n.Split('.')[0])) { continue }
            [void]$seen.Add($n)
            $out.Add([PSCustomObject]@{ Name = $n; Detail = 'searched before' })
        }
    }
    return $out.ToArray()
}

function Test-IpAddress {
    <# True for an IPv4 or IPv6 address ("10.0.4.21", "fe80::1"); a bare number like "5" is not one. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $t = ([string]$Text).Trim()
    if (-not $t) { return $false }
    # IPAddress.TryParse accepts "5" as 0.0.0.5; only dotted IPv4 or IPv6 count here.
    if ($t -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and $t -notmatch ':') { return $false }
    $ip = $null
    return [System.Net.IPAddress]::TryParse($t, [ref]$ip)
}

function New-ServerListItem {
    <# One row of the server list. Any name for this computer becomes its own name. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [string[]]$LocalNames)
    $n = $Name.Trim()
    $isLocal = $false
    if ($LocalNames -and (Test-IsLocalComputer -Name $n -LocalNames $LocalNames)) { $n = $LocalNames[0]; $isLocal = $true }
    [PSCustomObject]@{
        Name       = $n
        Display    = $n
        Note       = ''
        NoteKind   = 'Info'
        IsIp       = (-not $isLocal) -and (Test-IpAddress -Text $n)
        IsLocal    = $isLocal
        SearchName = $n
        Lookup     = 'Pending'
    }
}

function Add-ServerListItems {
    <#
        Adds names to the list (pasted text with commas, spaces or new lines becomes several
        names; a DOMAIN\ prefix is dropped) and returns the names actually added. A name
        already in the list, in any case, is skipped.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Items, [string[]]$Names, [string[]]$LocalNames)
    $added = New-Object System.Collections.Generic.List[string]
    foreach ($text in @($Names | Where-Object { $_ })) {
        foreach ($raw in @(ConvertTo-ServerList -Text $text)) {
            $clean = $raw.Trim()
            $slash = $clean.LastIndexOf('\')
            if ($slash -ge 0) { $clean = $clean.Substring($slash + 1) }
            if (-not $clean) { continue }
            $item = New-ServerListItem -Name $clean -LocalNames $LocalNames
            $exists = @($Items | Where-Object { [string]::Equals($_.Name, $item.Name, 'OrdinalIgnoreCase') }).Count -gt 0
            if ($exists) { continue }
            [void]$Items.Add($item)
            $added.Add($item.Name)
        }
    }
    return $added.ToArray()
}

function Find-DirectoryEntry {
    <# The AD entry for a name (short or DNS name, any case), or $null. #>
    [CmdletBinding()]
    param([object[]]$Directory, [string]$Name)
    foreach ($e in @($Directory | Where-Object { $_ })) {
        if ([string]::Equals($e.DnsName, $Name, 'OrdinalIgnoreCase')) { return $e }
    }
    if ($Name.IndexOf('.') -lt 0) {
        foreach ($e in @($Directory | Where-Object { $_ })) {
            if ([string]::Equals($e.Name, $Name, 'OrdinalIgnoreCase')) { return $e }
        }
    }
    return $null
}

function Update-ServerListNote {
    <#
        Fills in the note beside a server (and, for an IP whose name looks back up to the same
        IP, the name that is searched instead - see REFERENCES). -Lookup is a DNS result from
        Receive-NameLookups, or $null while it is still running.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Item, [object[]]$Directory, [string]$LoadedDomain, $Lookup)

    $set = { param($note, $kind) $Item.Note = $note; $Item.NoteKind = $kind }
    if ($Item.IsLocal) { & $set 'this computer' 'Info'; $Item.Lookup = 'Done'; return }

    if ($Item.IsIp) {
        $Item.Display = $Item.Name; $Item.SearchName = $Item.Name
        if ($null -eq $Lookup) { & $set '' 'Info'; $Item.Lookup = 'Pending'; return }
        $Item.Lookup = 'Done'
        if (-not [string]$Lookup.PtrName) { & $set 'IP · no name found' 'Info'; return }
        if (-not $Lookup.ForwardMatches) { & $set "IP · name doesn't match" 'Warn'; return }
        $Item.Display = '{0} → {1}' -f $Item.Name, $Lookup.PtrName
        $Item.SearchName = [string]$Lookup.PtrName
        $entry = Find-DirectoryEntry -Directory $Directory -Name $Lookup.PtrName
        if ($entry -and $entry.IsDC) { & $set 'domain controller' 'Info' } else { & $set '' 'Info' }
        return
    }

    if ($null -ne $Lookup) { $Item.Lookup = 'Done' }
    $loaded = @($Directory | Where-Object { $_ }).Count -gt 0
    $entry = Find-DirectoryEntry -Directory $Directory -Name $Item.Name
    if ($entry) {
        if ($entry.IsDC) { & $set 'domain controller' 'Info' }
        elseif (-not $entry.Enabled) { & $set 'disabled in AD' 'Warn' }
        else { & $set $entry.OS 'Info' }
        return
    }
    $dot = $Item.Name.IndexOf('.')
    $inLoadedDomain = ($dot -lt 0) -or ($LoadedDomain -and [string]::Equals($Item.Name.Substring($dot + 1), $LoadedDomain, 'OrdinalIgnoreCase'))
    if ($loaded -and $inLoadedDomain) { & $set 'not in AD' 'Warn' } else { & $set '' 'Info' }
}

function Get-ServerSearchText {
    <# The server text ConvertFrom-TimelineInputs reads: each row's search name, comma-separated. #>
    [CmdletBinding()]
    param([object[]]$Items)
    return (@($Items | Where-Object { $_ } | ForEach-Object { $_.SearchName }) -join ', ')
}

$script:ServerNameColumns = @('Name', 'ComputerName', 'DNSHostName', 'HostName', 'Server', 'IPAddress')

function Select-ServerNameColumn {
    <# The CSV column that holds server names: the first known header, in a fixed order; '' if none. #>
    [CmdletBinding()]
    param([string[]]$Headers)
    foreach ($want in $script:ServerNameColumns) {
        foreach ($h in @($Headers)) { if ([string]::Equals($h, $want, 'OrdinalIgnoreCase')) { return $h } }
    }
    return ''
}

function Read-ServerListFile {
    <#
        Server names from a .txt (one per line; blank lines and lines starting with # are
        skipped) or a .csv (the -Column given, else a known header such as Name or DNSHostName).
        When no column can be chosen, NeedsColumn is set and Headers lists the choices.
        A DOMAIN\ prefix is dropped.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$Column)

    $clean = {
        param($v)
        $t = ([string]$v).Trim()
        $slash = $t.LastIndexOf('\')
        if ($slash -ge 0) { $t = $t.Substring($slash + 1) }
        $t
    }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq '.txt') {
        $names = @(Get-Content -LiteralPath $Path -ErrorAction Stop | ForEach-Object { & $clean $_ } |
                Where-Object { $_ -and -not $_.StartsWith('#') })
        return [PSCustomObject]@{ Names = $names; Column = ''; Headers = @(); NeedsColumn = $false }
    }
    if ($ext -ne '.csv') { throw "Choose a .txt or .csv file (one server per line, or a CSV with a column of names)." }

    $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    $headers = if ($rows.Count -gt 0) { @($rows[0].PSObject.Properties.Name) } else { @() }
    $col = if ($Column) { $Column } else { Select-ServerNameColumn -Headers $headers }
    if (-not $col) { return [PSCustomObject]@{ Names = @(); Column = ''; Headers = $headers; NeedsColumn = $true } }
    $names = @($rows | ForEach-Object { & $clean $_.$col } | Where-Object { $_ })
    return [PSCustomObject]@{ Names = $names; Column = $col; Headers = $headers; NeedsColumn = $false }
}

# Reads every computer account from AD in a background runspace (see REFERENCES for the
# cmdlets). -Server and -Credential are passed only when given: no -Server means the domain
# this computer is joined to. Every account is read, not only servers, so "not in AD" means
# the account really doesn't exist; suggestions show only enabled servers.
$script:DefaultDirectoryLoader = {
    param($ListPath, $Server, $Credential)
    . $ListPath
    Import-Module ActiveDirectory -ErrorAction Stop
    $common = @{ ErrorAction = 'Stop' }
    if ($Server) { $common.Server = $Server }
    if ($Credential) { $common.Credential = $Credential }
    $domain = Get-ADDomain @common
    $dcs = @(Get-ADDomainController -Filter * @common | ForEach-Object { if ($_.HostName) { $_.HostName } else { $_.Name } })
    $now = [datetime]::UtcNow
    $entries = @(Get-ADComputer -Filter * -Properties DNSHostName, OperatingSystem, lastLogonTimestamp, DistinguishedName, Enabled @common |
            ForEach-Object { ConvertTo-DirectoryEntry -Computer $_ -DomainControllers $dcs -Now $now })
    @{ Domain = [string]$domain.DNSRoot; Entries = $entries }
}

# Reverse lookup for an IP, then a forward lookup of that name: the name is only trusted when
# it gives back the same IP (a stale PTR record must never search the wrong server). For a
# name, just whether DNS knows it.
$script:DefaultNameLookup = {
    param($Names)
    foreach ($n in @($Names)) {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($n, [ref]$ip) -and ($n -match '^\d{1,3}(\.\d{1,3}){3}$' -or $n -match ':')) {
            $ptr = ''; $match = $false
            try { $ptr = [string][System.Net.Dns]::GetHostEntry($ip).HostName } catch { $ptr = '' }
            if ($ptr -and $ptr -ne $n) {
                try { $match = @([System.Net.Dns]::GetHostAddresses($ptr) | Where-Object { $_.Equals($ip) }).Count -gt 0 } catch { $match = $false }
            }
            else { $ptr = '' }
            @{ Name = $n; IsIp = $true; PtrName = $ptr; ForwardMatches = $match }
        }
        else {
            $ok = $false
            try { $ok = @([System.Net.Dns]::GetHostAddresses($n)).Count -gt 0 } catch { $ok = $false }
            @{ Name = $n; IsIp = $false; Resolves = $ok }
        }
    }
}

function Start-BackgroundScript {
    # One script in a runspace of its own; the window's heartbeat collects it, never waits.
    param([Parameter(Mandatory)][scriptblock]$Script, [hashtable]$Parameters)
    $ps = [System.Management.Automation.PowerShell]::Create()
    [void]$ps.AddScript($Script.ToString())
    foreach ($k in $Parameters.Keys) { [void]$ps.AddParameter($k, $Parameters[$k]) }
    [PSCustomObject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
}

function Receive-BackgroundScript {
    # $null while running; otherwise Ok, Output (the script's last output) and Error.
    param([Parameter(Mandatory)]$Job)
    if (-not $Job.Handle.IsCompleted) { return $null }
    $ps = $Job.PowerShell
    try {
        $out = @($ps.EndInvoke($Job.Handle))
        if ($ps.Streams.Error.Count -gt 0 -and $out.Count -eq 0) {
            return [PSCustomObject]@{ Ok = $false; Output = $null; All = @(); Error = [string]$ps.Streams.Error[0].Exception.Message }
        }
        return [PSCustomObject]@{ Ok = $true; Output = $(if ($out.Count) { $out[-1] } else { $null }); All = $out; Error = '' }
    }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        return [PSCustomObject]@{ Ok = $false; Output = $null; All = @(); Error = [string]$ex.Message }
    }
    finally { $ps.Dispose() }
}

function Start-DirectoryLoad {
    <#
        Starts reading the computer accounts of a domain in the background. -Server is a domain
        or DC name ('' = this computer's domain). -Generation comes back with the result, so a
        load started before the domain or account changed can be thrown away.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Server, [pscredential]$Credential, [int]$Generation, [scriptblock]$Loader = $script:DefaultDirectoryLoader)
    $job = Start-BackgroundScript -Script $Loader -Parameters @{ ListPath = $script:ServerListFilePath; Server = $Server; Credential = $Credential }
    $job | Add-Member -NotePropertyName Generation -NotePropertyValue $Generation
    $job | Add-Member -NotePropertyName Target -NotePropertyValue $Server
    $job
}

function Receive-DirectoryLoad {
    <# $null while still loading; then Generation, Ok, Domain, Entries and Error. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Job)
    $r = Receive-BackgroundScript -Job $Job
    if ($null -eq $r) { return $null }
    $domain = ''; $entries = @()
    if ($r.Ok -and $r.Output) { $domain = [string]$r.Output.Domain; $entries = @($r.Output.Entries | Where-Object { $_ }) }
    [PSCustomObject]@{ Generation = $Job.Generation; Ok = $r.Ok; Domain = $domain; Entries = $entries; Error = $r.Error }
}

function Start-NameLookups {
    <# Starts DNS lookups for some names and IPs in the background. #>
    [CmdletBinding()]
    param([string[]]$Names, [scriptblock]$Lookup = $script:DefaultNameLookup)
    Start-BackgroundScript -Script $Lookup -Parameters @{ Names = @($Names) }
}

function Receive-NameLookups {
    <# $null while still looking up; then a hashtable of results keyed by name. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Job)
    $r = Receive-BackgroundScript -Job $Job
    if ($null -eq $r) { return $null }
    $map = @{}
    foreach ($o in @($r.All | Where-Object { $_ })) { $map[[string]$o.Name] = [PSCustomObject]$o }
    return $map
}

function Get-DirectoryServerCount {
    <# How many enabled servers the loaded directory holds (what suggestions draw from). #>
    [CmdletBinding()]
    param([object[]]$Directory)
    return @($Directory | Where-Object { $_ -and $_.Enabled -and $_.IsServer }).Count
}

function Get-DomainLineText {
    <# The "Suggestions from:" line under the server card's header. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Loading', 'Loaded', 'Failed', 'NoDomain')][string]$State,
        [string]$Domain, [int]$Count, [string]$ErrorText)
    $name = if ($Domain) { $Domain } else { "this computer's domain" }
    switch ($State) {
        'Loading' { "Loading servers from $name..." }
        'Loaded' { 'Suggestions from: {0} ({1} {2})' -f $name, $Count, $(if ($Count -eq 1) { 'server' } else { 'servers' }) }
        'Failed' { "Couldn't read ${name}: $ErrorText" }
        'NoDomain' { 'Suggestions from: no domain' }
    }
}

function Test-StaleDirectoryResult {
    <# True when a finished load belongs to an older domain or account choice (ignore it). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [int]$CurrentGeneration)
    return [int]$Result.Generation -ne $CurrentGeneration
}
