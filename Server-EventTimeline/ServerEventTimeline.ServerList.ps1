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
