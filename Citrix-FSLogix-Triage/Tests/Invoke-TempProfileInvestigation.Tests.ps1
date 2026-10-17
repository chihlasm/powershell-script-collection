<#
    Tests for Invoke-TempProfileInvestigation.ps1 (SQ-003, Pester 5, run under pwsh).

    "Why did this user get a temporary profile?" One user, one session host (or a Citrix
    Delivery Controller that finds the host). Every external call is mocked: Get-SmbOpenFile,
    Get-SmbShare, New-CimSession, Get-CimInstance, Get-WinEvent, Invoke-Command, Test-Connection,
    Get-BrokerSession, Resolve-DnsName, Set-Clipboard. "jdoe", "CTX07", "CTX04", "FS01",
    "CTX-DDC01", contoso, the SIDs and the IP addresses are synthetic. Nothing here touches a
    real host, file server, Delivery Controller, or the clipboard.

    THE CONTRACT THESE TESTS PIN (the implementation must match; see each Describe)

      Script-level functions (all defined by the script, all mockable after dot-sourcing it with
      -UserName x -ComputerName x -LoadFunctionsOnly):
        Get-TempProfileUserSid -UserName 'CONTOSO\jdoe'                      -> SID string (wraps NTAccount.Translate)
        Resolve-TempProfileClientName -Address '10.20.30.44'                 -> name, or $null when DNS has none
        Get-TempProfileLockFact -UserName -Sid -VhdLocations -CcdLocations   -> Lock fact (collector, three-state)
        Read-TempProfileLogLines -Path                                       -> string[] (UTF-16LE with BOM aware)
        ConvertFrom-TempProfileLog -Lines -UserName -Sid -Reference          -> @{ LocalProfile; ShareAccess; UnknownCodes }
        Get-TempProfileLogFact -ComputerName -UserName -Sid -EventLookbackHours -> same shape, reads the host
        Get-TempProfileCrashFact -ComputerName -EventLookbackHours           -> ServiceCrash fact
        Get-TempProfileLoadedProfileFact -ComputerName -Sid                  -> TempProfileNow fact (Win32_UserProfile)
        Get-FSLogixReference                                                 -> reference table (psd1, else built-in fallback)
        Import-CitrixBrokerSdk                                               -> $true / $false (copy of the HealthCollector one)
        Get-TempProfileVerdict -Facts                                        -> pure ranker, no I/O
        Get-TempProfileExitCode -Verdict                                     -> 2 / 1 / 1 / 0
        Write-TempProfileConsole -Result, ConvertTo-TempProfileTicketNote -Result -EvidencePaths
        Invoke-TempProfileInvestigation -UserName ... [-ComputerName | -DeliveryController]
            -EventLookbackHours -OutputPath -TicketNumber -NoClipboard -FullDetail -Quiet
            -> the result object (always; carries ExitCode and TicketNote). The script body is
               only: dot-source the companions, parse params, call this, then
               "if ($PassThru) { return $r }; exit $r.ExitCode".

      Facts (input of Get-TempProfileVerdict), one [pscustomobject] with:
        UserName, ComputerName
        HostReach     State Reached|Unreachable            Reason
        Lock          State Held|NotHeld|CouldNotCheck     Reason Detail FileServer FileName ClientComputer ClientAddress ClientResolved
        Service       State Running|Stopped|NotInstalled|CouldNotCheck   Reason Detail
        ServiceCrash  State Crashed|None|CouldNotCheck     Reason Time EventId
        FslogixConfig State On|Off|NotConfigured|CouldNotCheck   Reason Detail
        ShareAccess   State Denied|NoDenial|CouldNotCheck  Reason Line Time
        Storage       State AllUnreachable|SomeUnreachable|Reachable|CouldNotCheck   Reason Kind(CloudCache|ProfileShare) Unreachable Total
        LocalProfile  State Found|None|CouldNotCheck       Reason Line Time Code
        Disk          State Fail|Warn|Pass|CouldNotCheck   Reason Detail
        UnknownCodes  array of @{ Code; Text }
        TempProfileNow State Temporary|LoadedNormal|NotSignedIn|CouldNotCheck
        Sessions      array of @{ Machine; State }  (Citrix sessions of the user; State Active|Disconnected)

      Verdict object: Verdict, Status (Fail|Warn|Pass), Summary (the cause sentence), NextStep,
        TopCause, Causes (all 7, sorted by Rank), OtherCauses (Confirmed/Possible besides the top),
        Evidence (string[] of evidence-only lines).
      Cause: Id, Title, State (Confirmed|Possible|RuledOut|CouldNotCheck), Evidence (string[]),
        NextStep, Rank. Ids in rank order: lock-held, frxsvc, fslogix-off, share-denied, storage,
        local-profile, disk-full (Rank 1..7).

      Reference table (FSLogixReference.psd1 and the script's $script:FSLogixReferenceFallback):
        @{ StatusCodes = @{ '<n>' = @{ Text; Url } }
           ReasonCodes = @{ '<n>' = @{ Meaning; Text; Url } }     Meaning 'LocalProfileExists' is the one rule 16 uses
           ErrorCodes  = @{ '<n>' = @{ Meaning; Text; Url } } }

    Run:  pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Citrix-FSLogix-Triage\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Invoke-TempProfileInvestigation.ps1'
    $script:TriagePath = Join-Path $script:Root 'Invoke-CitrixFSLogixTriage.ps1'
    $script:RepoRoot = Split-Path -Parent $script:Root
    $script:Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
    $script:OtherSid = 'S-1-5-21-1111111111-2222222222-3333333333-1106'

    # Modules and snap-ins that may be absent: stubs with the REAL parameter names. Where the
    # real cmdlet is installed (SmbShare here) the real one is mocked and a separate test checks
    # the names this suite relies on against Get-Command.
    $script:StubsAdded = @()
    function Add-StubIfMissing([string]$Name, [scriptblock]$Body) {
        if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$Name" -Value $Body
            $script:StubsAdded += $Name
        }
    }
    Add-StubIfMissing 'Get-SmbOpenFile' { [CmdletBinding()] param([uint64[]]$FileId, [uint64[]]$SessionId, [string[]]$ClientComputerName, [string[]]$ClientUserName, [string[]]$ScopeName, $CimSession) }
    Add-StubIfMissing 'Get-SmbShare' { [CmdletBinding()] param([string[]]$Name, [string[]]$ScopeName, $CimSession) }
    # Citrix Broker SDK (Citrix.Broker.Admin.V2). Parameters per the Citrix developer docs:
    # https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2407/Broker/Get-BrokerSession.html
    Add-StubIfMissing 'Get-BrokerSession' { [CmdletBinding()] param([string]$AdminAddress, [string]$UserName, [string]$HostedMachineName, [string]$SessionState, [int]$MaxRecordCount) }

    . $script:TriagePath -LoadFunctionsOnly
    . (Join-Path $script:Root 'CaseKit.ps1')
    . $script:ScriptPath -UserName '__pester__' -ComputerName '__pester__' -LoadFunctionsOnly

    function New-RegKey {
        param([string]$SubKey, [hashtable]$Values, [switch]$Missing)
        $label = if ($SubKey -like 'SOFTWARE\Policies\*') { 'Policies path (not documented for profile settings)' } else { 'Profile settings' }
        if ($Missing) { return [PSCustomObject]@{ Label = $label; Path = "HKLM:\$SubKey"; Found = $false; Error = '' } }
        $ordered = [ordered]@{}
        foreach ($k in $Values.Keys) { $ordered[$k] = $Values[$k] }
        [PSCustomObject]@{ Label = $label; Path = "HKLM:\$SubKey"; Found = $true; Error = ''; Values = [PSCustomObject]$ordered }
    }

    # The REAL Invoke-CitrixFSLogixTriage run against a pretend host, so the host evidence the
    # new script has to read has exactly the shape the triage produces.
    # Cloud Cache scenarios: two SMB providers; smb2 is the one that is down in CloudCacheSomeDown.
    $script:CcdTwoProviders = 'type=smb,connectionString=\\smb1\profiles;type=smb,connectionString=\\smb2\profiles'
    function Test-ScenarioShareUp([string]$Path) {
        switch ($script:Scn) {
            'CloudCacheAllDown' { $false }
            'CloudCacheSomeDown' { $Path -notlike '\\smb2*' }
            default { $true }
        }
    }
    function Set-TriageScenario {
        param([ValidateSet('Healthy', 'DiskWarn', 'DiskFail', 'Unreachable', 'FSLogixOff', 'NotConfigured', 'ServiceStopped', 'CloudCacheAllDown', 'CloudCacheSomeDown')][string]$Name)
        $script:Scn = $Name
        Mock Test-Connection { if (-not $script:Scn) { throw 'unmocked Test-Connection' }; $script:Scn -ne 'Unreachable' }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_Service' } {
            if (-not $script:Scn) { throw 'unmocked Get-CimInstance' }
            if ($script:Scn -eq 'Unreachable') { throw 'The WinRM client cannot process the request.' }
            $frxState = if ($script:Scn -eq 'ServiceStopped') { 'Stopped' } else { 'Running' }
            @(
                [PSCustomObject]@{ Name = 'frxsvc'; DisplayName = 'FSLogix Apps Services'; State = $frxState; StartMode = 'Auto' }
                [PSCustomObject]@{ Name = 'frxccds'; DisplayName = 'FSLogix Cloud Caching Service'; State = 'Running'; StartMode = 'Auto' }
            )
        }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' } {
            if (-not $script:Scn) { throw 'unmocked Get-CimInstance' }
            switch ($script:Scn) {
                'Unreachable' { throw 'The WinRM client cannot process the request.' }
                'DiskWarn' { [PSCustomObject]@{ DeviceID = 'C:'; Size = 60GB; FreeSpace = 8GB } }
                'DiskFail' { [PSCustomObject]@{ DeviceID = 'C:'; Size = 200GB; FreeSpace = 3GB } }
                default { [PSCustomObject]@{ DeviceID = 'C:'; Size = 200GB; FreeSpace = 120GB } }
            }
        }
        Mock Get-WinEvent {
            if (-not $script:Scn) { throw 'unmocked Get-WinEvent' }
            if ($script:Scn -eq 'Unreachable') { throw 'The RPC server is unavailable.' }
            throw 'No events were found that match the specified selection criteria.'
        }
        Mock Get-FSLogixRegistrySnapshot {
            if (-not $script:Scn) { throw 'unmocked Get-FSLogixRegistrySnapshot' }
            if ($script:Scn -eq 'Unreachable') { throw 'The RPC server is unavailable.' }
            $values = switch ($script:Scn) {
                'FSLogixOff' { @{ Enabled = '0'; VHDLocations = '\\files\profiles' } }
                'NotConfigured' { @{ Enabled = '1' } }
                'CloudCacheAllDown' { @{ Enabled = '1'; CCDLocations = $script:CcdTwoProviders } }
                'CloudCacheSomeDown' { @{ Enabled = '1'; CCDLocations = $script:CcdTwoProviders } }
                default { @{ Enabled = '1'; VHDLocations = '\\files\profiles' } }
            }
            @(
                New-RegKey -SubKey 'SOFTWARE\FSLogix\Profiles' -Values $values
                New-RegKey -SubKey 'SOFTWARE\Policies\FSLogix\Profiles' -Missing
            )
        }
        # The triage tests each share from the host (Invoke-Command) and, when that fails, from
        # this PC (Test-Path on the UNC path): both answer from the scenario, never the network.
        Mock Invoke-Command {
            if (-not $script:Scn) { throw 'unmocked Invoke-Command' }
            if ($script:Scn -eq 'Unreachable') { throw 'The WinRM client cannot process the request.' }
            Test-ScenarioShareUp ([string]@($ArgumentList)[0])
        }
        Mock Test-Path -ParameterFilter { "$LiteralPath$Path" -like '\\*' } {
            if (-not $script:Scn) { throw 'unmocked Test-Path on a share' }
            Test-ScenarioShareUp ([string]$LiteralPath)
        }
    }

    # Anything not mocked on purpose must fail loudly, never reach a real machine.
    function Set-CatchAllMocks {
        Mock Test-Connection { throw 'unmocked Test-Connection' }
        Mock Get-CimInstance { throw 'unmocked Get-CimInstance' }
        Mock Get-WinEvent { throw 'unmocked Get-WinEvent' }
        Mock Invoke-Command { throw 'unmocked Invoke-Command' }
        Mock New-CimSession { throw 'unmocked New-CimSession' }
        Mock Remove-CimSession { }
        Mock Get-SmbShare { throw 'unmocked Get-SmbShare' }
        Mock Get-SmbOpenFile { throw 'unmocked Get-SmbOpenFile' }
        Mock Get-BrokerSession { throw 'unmocked Get-BrokerSession' }
        Mock Resolve-DnsName { throw 'unmocked Resolve-DnsName' }
        Mock Get-FSLogixRegistrySnapshot { throw 'unmocked Get-FSLogixRegistrySnapshot' }
        Mock Set-Clipboard { }
        Mock Invoke-WinFormsClipboard { }
        Mock Get-TempProfileHostAddress { throw 'unmocked Get-TempProfileHostAddress (DNS)' }
        Mock ConvertTo-TempProfileAccountName { throw 'unmocked ConvertTo-TempProfileAccountName (SID lookup)' }
    }

    $script:Triage = @{}
    foreach ($name in 'Healthy', 'DiskWarn', 'DiskFail', 'Unreachable', 'FSLogixOff', 'NotConfigured', 'ServiceStopped', 'CloudCacheAllDown', 'CloudCacheSomeDown') {
        Set-TriageScenario $name
        $script:Triage[$name] = Invoke-CitrixFSLogixTriage -ComputerName CTX07 -UserName jdoe -EventLookbackHours 24
    }
    $script:Scn = $null   # from here on the scenario mocks refuse to answer
    Set-CatchAllMocks

    # ---- fact builders -------------------------------------------------------------------
    function New-Obj([hashtable]$Props) { [pscustomobject]$Props }
    function New-Facts {
        param([hashtable]$Override = @{})
        $f = [ordered]@{
            UserName       = 'jdoe'
            ComputerName   = 'CTX07'
            HostReach      = New-Obj @{ State = 'Reached'; Reason = '' }
            Lock           = New-Obj @{ State = 'NotHeld'; Reason = ''; Detail = 'FS01 shows no open profile disk for jdoe'; FileServer = 'FS01'; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true }
            Service        = New-Obj @{ State = 'Running'; Reason = ''; Detail = 'FSLogix Apps Services is running.' }
            ServiceCrash   = New-Obj @{ State = 'None'; Reason = ''; Time = ''; EventId = 0 }
            FslogixConfig  = New-Obj @{ State = 'On'; Reason = ''; Detail = 'FSLogix profile containers are enabled (Enabled = 1).' }
            ShareAccess    = New-Obj @{ State = 'NoDenial'; Reason = ''; Line = ''; Time = '' }
            Storage        = New-Obj @{ State = 'Reachable'; Reason = ''; Kind = 'ProfileShare'; Unreachable = @(); Total = 1 }
            LocalProfile   = New-Obj @{ State = 'None'; Reason = ''; Line = ''; Time = ''; Code = '' }
            Disk           = New-Obj @{ State = 'Pass'; Reason = ''; Detail = 'C: 120 GB free of 200 GB (60 percent).' }
            UnknownCodes   = @()
            TempProfileNow = New-Obj @{ State = 'NotSignedIn'; Reason = '' }
            Sessions       = @()
        }
        foreach ($k in $Override.Keys) { $f[$k] = $Override[$k] }
        [pscustomobject]$f
    }
    function Get-Cause($Verdict, [string]$Id) { @($Verdict.Causes | Where-Object { $_.Id -eq $Id })[0] }
    function Join-Evidence($Cause) { (@($Cause.Evidence) | ForEach-Object { "$_" }) -join "`n" }

    $script:HeldLock = New-Obj @{ State = 'Held'; Reason = ''; Detail = ''; FileServer = 'FS01'; FileName = 'S-1-5-21-1111111111-2222222222-3333333333-1105_jdoe\Profile_jdoe.vhdx'; ClientComputer = 'CTX04'; ClientAddress = '10.20.30.44'; ClientResolved = $true }
    $script:BlindLock = New-Obj @{ State = 'CouldNotCheck'; Reason = 'access denied on FS01; you need to be an administrator of the file server'; Detail = ''; FileServer = 'FS01'; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true }

    # ---- driving the whole script --------------------------------------------------------
    function Set-CleanCollectors {
        Mock Get-TempProfileUserSid { $script:Sid }
        Mock Invoke-CitrixFSLogixTriage { $script:Triage.Healthy }
        Mock Get-TempProfileLockFact { New-Obj @{ State = 'NotHeld'; Reason = ''; Detail = 'FS01 shows no open profile disk for jdoe'; FileServer = 'FS01'; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true } }
        Mock Get-TempProfileLogFact {
            New-Obj @{
                LocalProfile = New-Obj @{ State = 'None'; Reason = ''; Line = ''; Time = ''; Code = '' }
                ShareAccess  = New-Obj @{ State = 'NoDenial'; Reason = ''; Line = ''; Time = '' }
                UnknownCodes = @()
            }
        }
        Mock Get-TempProfileCrashFact { New-Obj @{ State = 'None'; Reason = ''; Time = ''; EventId = 0 } }
        Mock Get-TempProfileLoadedProfileFact { New-Obj @{ State = 'NotSignedIn'; Reason = '' } }
        Mock Import-CitrixBrokerSdk { $true }
        Mock Get-TempProfileHostAddress { @() }
        Mock Set-Clipboard { }
        Mock Invoke-WinFormsClipboard { }
    }
    # A copy of a triage result whose RawOutput.Events are the given FSLogix events.
    function New-TriageWithEvents([object]$Base, [object[]]$Events) {
        $copy = $Base.PSObject.Copy()
        $raw = $Base.RawOutput.PSObject.Copy()
        $raw.Events = @($Events)
        $copy.RawOutput = $raw
        $copy
    }
    function New-FslogixEvent([string]$Message, [int]$Id = 26) {
        [pscustomobject]@{ LogName = 'Microsoft-FSLogix-Apps/Operational'; TimeCreated = '2026-10-17 10:15:03'; Id = $Id; Level = 'Error'; ProviderName = 'Microsoft-FSLogix-Apps'; Message = $Message; Error = '' }
    }
    function Invoke-Main {
        param([hashtable]$Splat = @{})
        $args2 = @{ UserName = 'jdoe'; NoClipboard = $true }
        if (-not $Splat.ContainsKey('DeliveryController') -and -not $Splat.ContainsKey('ComputerName')) { $args2.ComputerName = 'CTX07' }
        foreach ($k in $Splat.Keys) { $args2[$k] = $Splat[$k] }
        $all = @(Invoke-TempProfileInvestigation @args2 6>&1)
        $result = @($all | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['CheckId'] }) | Select-Object -Last 1
        $lines = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { $_.MessageData.ToString() })
        [pscustomobject]@{ Result = $result; Lines = $lines; Text = ($lines -join "`n") }
    }
    function Get-ConsoleSection([string[]]$Lines, [string]$Header) {
        $at = [array]::IndexOf($Lines, $Header)
        if ($at -lt 0) { return @() }
        $out = @()
        for ($i = $at + 1; $i -lt $Lines.Count; $i++) {
            if ($Lines[$i] -notmatch '^\s+\S') { break }
            $out += $Lines[$i]
        }
        $out
    }
    function New-BrokerSessionMock([string]$Machine, [string]$State) {
        [pscustomobject]@{ UserName = 'CONTOSO\jdoe'; HostedMachineName = $Machine; DNSName = ('{0}.contoso.com' -f $Machine.ToLower()); MachineName = "CONTOSO\$Machine"; SessionState = $State }
    }
}

AfterAll {
    foreach ($n in $script:StubsAdded) { Remove-Item -Path "function:global:$n" -ErrorAction SilentlyContinue }
}

# =============================================================================
# Ranker: Get-TempProfileVerdict (pure, no I/O)
# =============================================================================
Describe 'Get-TempProfileVerdict: headline, ranking, verdict states' {

    It 'AC2_LockByOtherHostIsTopCause: the lock is the top cause, the sentence names CTX04, the evidence lists server, file and client' {
        $v = Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $script:HeldLock })
        $v.Verdict | Should -Be 'CAUSE FOUND'
        $v.TopCause.Id | Should -Be 'lock-held'
        $v.TopCause.Title | Should -Match '(?i)disk held open by another computer'
        $v.Summary | Should -Match 'CTX04'
        $ev = Join-Evidence $v.TopCause
        $ev | Should -Match 'FS01'
        $ev | Should -Match 'Profile_jdoe\.vhdx'
        $ev | Should -Match 'CTX04'
    }

    It 'AC3_LockHolderSessionStateFromCitrix: a Disconnected session on CTX04 is named in the sentence and the next step is a logoff in Director/Studio' {
        $facts = New-Facts @{
            Lock     = $script:HeldLock
            Sessions = @((New-Obj @{ Machine = 'CTX07'; State = 'Active' }), (New-Obj @{ Machine = 'CTX04'; State = 'Disconnected' }))
        }
        $v = Get-TempProfileVerdict -Facts $facts
        $v.Summary | Should -Match '(?i)session on CTX04 is disconnected'
        $v.NextStep | Should -Match '(?i)log.*off'
        $v.NextStep | Should -Match 'Director|Studio'
        $v.NextStep | Should -Match '(?i)sign in again'
    }

    It 'AC5_TwoCausesRankedWithEvidence: a lock and a full disk are both kept; the lock is on top, the disk is an "other" cause with its own evidence' {
        $facts = New-Facts @{
            Lock = $script:HeldLock
            Disk = New-Obj @{ State = 'Fail'; Reason = ''; Detail = 'C: 3 GB free of 200 GB (1.5 percent).' }
        }
        $v = Get-TempProfileVerdict -Facts $facts
        $v.TopCause.Id | Should -Be 'lock-held'
        @($v.OtherCauses | ForEach-Object { $_.Id }) | Should -Contain 'disk-full'
        (Join-Evidence (Get-Cause $v 'disk-full')) | Should -Match '3 GB free'
        (Get-Cause $v 'disk-full').State | Should -Be 'Confirmed'
        (Get-Cause $v 'lock-held').State | Should -Be 'Confirmed'
    }

    It 'AC5_TwoCausesRankedWithEvidence: the fixed rank order is lock, frxsvc, off/not configured, share denied, storage, local profile, disk' {
        $v = Get-TempProfileVerdict -Facts (New-Facts)
        @($v.Causes).Count | Should -Be 7
        @($v.Causes | Sort-Object Rank | ForEach-Object { $_.Id }) | Should -Be @('lock-held', 'frxsvc', 'fslogix-off', 'share-denied', 'storage', 'local-profile', 'disk-full')
        @($v.Causes | Sort-Object Rank | ForEach-Object { $_.Rank }) | Should -Be @(1, 2, 3, 4, 5, 6, 7)
    }

    It 'AC5_TwoCausesRankedWithEvidence: with every rule confirmed the order of confirmation still follows the ranks (no short-circuit)' {
        $facts = New-Facts @{
            Lock          = $script:HeldLock
            Service       = New-Obj @{ State = 'Stopped'; Reason = ''; Detail = 'FSLogix Apps Services is Stopped.' }
            FslogixConfig = New-Obj @{ State = 'Off'; Reason = ''; Detail = 'Enabled = 0' }
            ShareAccess   = New-Obj @{ State = 'Denied'; Reason = ''; Line = 'Access is denied.'; Time = '10:15:03' }
            Storage       = New-Obj @{ State = 'AllUnreachable'; Reason = ''; Kind = 'CloudCache'; Unreachable = @('smb1', 'smb2'); Total = 2 }
            LocalProfile  = New-Obj @{ State = 'Found'; Reason = ''; Line = 'Reason set to 7: x'; Time = '10:14:58'; Code = '7' }
            Disk          = New-Obj @{ State = 'Fail'; Reason = ''; Detail = 'C: 3 GB free' }
        }
        $v = Get-TempProfileVerdict -Facts $facts
        @($v.Causes | Where-Object { $_.State -eq 'Confirmed' }).Count | Should -Be 7
        $v.TopCause.Id | Should -Be 'lock-held'
        @($v.OtherCauses | ForEach-Object { $_.Id }) | Should -Be @('frxsvc', 'fslogix-off', 'share-denied', 'storage', 'local-profile', 'disk-full')
    }

    It 'AC6_NoCauseOnlyWhenEverythingLooked: every check ran and found nothing -> NO CAUSE FOUND, escalate with the ticket note' {
        $v = Get-TempProfileVerdict -Facts (New-Facts)
        $v.Verdict | Should -Be 'NO CAUSE FOUND'
        $v.Status | Should -Be 'Pass'
        @($v.Causes | Where-Object { $_.State -ne 'RuledOut' }).Count | Should -Be 0
        $v.NextStep | Should -Match '(?i)escalate'
        $v.NextStep | Should -Match '(?i)ticket note'
    }

    It 'AC7_CantTellWhenKeyCheckBlind: nothing confirmed and the lock check could not run -> CAN''T TELL, never NO CAUSE FOUND, and the next step names the check and why' {
        $v = Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $script:BlindLock })
        $v.Verdict | Should -Be "CAN'T TELL"
        $v.Verdict | Should -Not -Be 'NO CAUSE FOUND'
        $v.NextStep | Should -Match '(?i)profile disk'
        $v.NextStep | Should -Match 'access denied on FS01; you need to be an administrator of the file server'
    }

    It 'AC7_CantTellWhenKeyCheckBlind: a fact that is missing altogether never fires a rule and counts as a check that could not run' {
        $v = Get-TempProfileVerdict -Facts ([pscustomobject]@{ UserName = 'jdoe'; ComputerName = 'CTX07' })
        @($v.Causes).Count | Should -Be 7
        @($v.Causes | Where-Object { $_.State -eq 'Confirmed' -or $_.State -eq 'Possible' }).Count | Should -Be 0
        $v.Verdict | Should -Be "CAN'T TELL"
    }

    It 'AC7_CantTellWhenKeyCheckBlind: a confirmed cause still wins over a blind check (a confirmed lock is not hidden by a blind disk check)' {
        $facts = New-Facts @{ Lock = $script:HeldLock; Disk = New-Obj @{ State = 'CouldNotCheck'; Reason = 'could not read disk space'; Detail = '' } }
        $v = Get-TempProfileVerdict -Facts $facts
        $v.Verdict | Should -Be 'CAUSE FOUND'
        (Get-Cause $v 'disk-full').State | Should -Be 'CouldNotCheck'
    }

    It 'AC8_HostUnreachable: host unreachable and nothing else known -> CAN''T TELL and the sentence says CTX07 could not be reached' {
        $facts = New-Facts @{
            HostReach     = New-Obj @{ State = 'Unreachable'; Reason = 'CTX07 did not answer a ping.' }
            Lock          = $script:BlindLock
            Service       = New-Obj @{ State = 'CouldNotCheck'; Reason = 'CTX07 could not be reached'; Detail = '' }
            ServiceCrash  = New-Obj @{ State = 'CouldNotCheck'; Reason = 'CTX07 could not be reached'; Time = ''; EventId = 0 }
            FslogixConfig = New-Obj @{ State = 'CouldNotCheck'; Reason = 'CTX07 could not be reached'; Detail = '' }
            ShareAccess   = New-Obj @{ State = 'CouldNotCheck'; Reason = 'CTX07 could not be reached'; Line = ''; Time = '' }
            Storage       = New-Obj @{ State = 'CouldNotCheck'; Reason = 'CTX07 could not be reached'; Kind = 'ProfileShare'; Unreachable = @(); Total = 0 }
            LocalProfile  = New-Obj @{ State = 'CouldNotCheck'; Reason = 'CTX07 could not be reached'; Line = ''; Time = ''; Code = '' }
            Disk          = New-Obj @{ State = 'CouldNotCheck'; Reason = 'CTX07 could not be reached'; Detail = '' }
        }
        $v = Get-TempProfileVerdict -Facts $facts
        $v.Verdict | Should -Be "CAN'T TELL"
        $v.Summary | Should -Match 'CTX07 could not be reached'
    }

    It 'AC9_ExitCodes: Get-TempProfileExitCode maps CAUSE FOUND = 2, POSSIBLE CAUSE = 1, CAN''T TELL = 1, NO CAUSE FOUND = 0' {
        Get-TempProfileExitCode -Verdict 'CAUSE FOUND' | Should -Be 2
        Get-TempProfileExitCode -Verdict 'POSSIBLE CAUSE' | Should -Be 1
        Get-TempProfileExitCode -Verdict "CAN'T TELL" | Should -Be 1
        Get-TempProfileExitCode -Verdict 'NO CAUSE FOUND' | Should -Be 0
    }
}

Describe 'Get-TempProfileVerdict: each other rule, from cited evidence' {

    It 'AC14_FrxsvcStopped: a stopped frxsvc is confirmed as "FSLogix service stopped on CTX07"' {
        $v = Get-TempProfileVerdict -Facts (New-Facts @{ Service = New-Obj @{ State = 'Stopped'; Reason = ''; Detail = 'FSLogix Apps Services is Stopped (start type Auto).' } })
        $c = Get-Cause $v 'frxsvc'
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Match 'FSLogix service stopped on CTX07'
        $v.Verdict | Should -Be 'CAUSE FOUND'
    }

    It 'AC15_FrxsvcCrashed: a Service Control Manager "terminated unexpectedly" event is confirmed as "FSLogix service crashed" with the event time' {
        $facts = New-Facts @{ ServiceCrash = New-Obj @{ State = 'Crashed'; Reason = ''; Time = [datetime]'2026-10-17 09:12:31'; EventId = 7034 } }
        $c = Get-Cause (Get-TempProfileVerdict -Facts $facts) 'frxsvc'
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Match 'FSLogix service crashed'
        (Join-Evidence $c) | Should -Match '09:12:31'
    }

    It 'AC16_LocalProfileExists: a log line mapped to "local profile exists" is confirmed and the line and time are quoted' {
        $facts = New-Facts @{ LocalProfile = New-Obj @{ State = 'Found'; Reason = ''; Line = 'Reason set to 7: Local profile exists'; Time = '10:14:58.060'; Code = '7' } }
        $c = Get-Cause (Get-TempProfileVerdict -Facts $facts) 'local-profile'
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Match '(?i)existing local profile stopped FSLogix'
        (Join-Evidence $c) | Should -Match 'Reason set to 7: Local profile exists'
        (Join-Evidence $c) | Should -Match '10:14:58'
    }

    It 'AC17_ShareAccessDenied: access denied to the profile location is confirmed as "no permission on the profile share"' {
        $facts = New-Facts @{ ShareAccess = New-Obj @{ State = 'Denied'; Reason = ''; Line = 'Access is denied.'; Time = '10:15:03.100' } }
        $c = Get-Cause (Get-TempProfileVerdict -Facts $facts) 'share-denied'
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Match '(?i)no permission on the profile share'
    }

    It 'AC18_CloudCacheUnreachable: all providers unreachable is confirmed, only some is possible' {
        $all = New-Facts @{ Storage = New-Obj @{ State = 'AllUnreachable'; Reason = ''; Kind = 'CloudCache'; Unreachable = @('smb1', 'smb2'); Total = 2 } }
        $c = Get-Cause (Get-TempProfileVerdict -Facts $all) 'storage'
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Match 'Cloud Cache storage unreachable'

        $some = New-Facts @{ Storage = New-Obj @{ State = 'SomeUnreachable'; Reason = ''; Kind = 'CloudCache'; Unreachable = @('smb2'); Total = 2 } }
        $v = Get-TempProfileVerdict -Facts $some
        (Get-Cause $v 'storage').State | Should -Be 'Possible'
        $v.Verdict | Should -Be 'POSSIBLE CAUSE'
        $v.Status | Should -Be 'Warn'
    }

    It 'AC19_FslogixOffOrNotConfigured: Enabled not 1, or no profile location, is confirmed as "FSLogix profiles are off or not configured on CTX07"' {
        foreach ($state in 'Off', 'NotConfigured') {
            $facts = New-Facts @{ FslogixConfig = New-Obj @{ State = $state; Reason = ''; Detail = 'FSLogix profile containers are switched off (Enabled = 0).' } }
            $c = Get-Cause (Get-TempProfileVerdict -Facts $facts) 'fslogix-off'
            $c.State | Should -Be 'Confirmed' -Because $state
            $c.Title | Should -Match 'FSLogix profiles are off or not configured on CTX07'
        }
    }

    It 'AC20_HostDiskFull: a disk at the triage Fail threshold is confirmed as "the server''s disk is full"; at Warn it is only possible' {
        $fail = New-Facts @{ Disk = New-Obj @{ State = 'Fail'; Reason = ''; Detail = 'C: 3 GB free of 200 GB (1.5 percent).' } }
        $c = Get-Cause (Get-TempProfileVerdict -Facts $fail) 'disk-full'
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Match "(?i)the server's disk is full"

        $warn = New-Facts @{ Disk = New-Obj @{ State = 'Warn'; Reason = ''; Detail = 'C: 8 GB free of 60 GB (13.33 percent).' } }
        $v = Get-TempProfileVerdict -Facts $warn
        (Get-Cause $v 'disk-full').State | Should -Be 'Possible'
        $v.Verdict | Should -Be 'POSSIBLE CAUSE'
    }

    It 'AC21_UnknownFslogixCodeShownVerbatim: an unrecognized reason is shown as evidence and confirms nothing' {
        $facts = New-Facts @{ UnknownCodes = @((New-Obj @{ Code = '99'; Text = 'Something new' })) }
        $v = Get-TempProfileVerdict -Facts $facts
        (@($v.Evidence) -join "`n") | Should -Match 'Unrecognized FSLogix reason 99: Something new'
        @($v.Causes | Where-Object { $_.State -eq 'Confirmed' }).Count | Should -Be 0
        $v.Verdict | Should -Not -Be 'CAUSE FOUND'
    }

    It 'AC22_TempProfileNowEvidence: the Win32_UserProfile temporary flag and "not signed in" are evidence lines and never change the verdict' {
        $base = Get-TempProfileVerdict -Facts (New-Facts)
        $temp = Get-TempProfileVerdict -Facts (New-Facts @{ TempProfileNow = New-Obj @{ State = 'Temporary'; Reason = '' } })
        $none = Get-TempProfileVerdict -Facts (New-Facts @{ TempProfileNow = New-Obj @{ State = 'NotSignedIn'; Reason = '' } })
        (@($temp.Evidence) -join "`n") | Should -Match 'jdoe is on a temporary profile on CTX07 right now'
        (@($none.Evidence) -join "`n") | Should -Match 'jdoe is not signed in to CTX07 now'
        $temp.Verdict | Should -Be $base.Verdict
        $none.Verdict | Should -Be $base.Verdict
    }
}

# =============================================================================
# Lock-holder collector: Get-TempProfileLockFact (never a false all-clear)
# =============================================================================
Describe 'Get-TempProfileLockFact: who holds the profile disk' {
    BeforeAll {
        function Set-SmbScenario {
            param(
                [object[]]$Shares = @([pscustomobject]@{ Name = 'profiles'; Path = 'D:\Profiles' }),
                [object[]]$OpenFiles = @(),
                [string]$OpenFilesError = '',
                [string]$ShareError = '',
                [string]$SessionError = '',
                [string]$ResolveTo = 'CTX04.contoso.com'
            )
            $script:Shares = $Shares; $script:OpenFiles = $OpenFiles; $script:OpenFilesError = $OpenFilesError
            $script:ShareError = $ShareError; $script:SessionError = $SessionError; $script:ResolveTo = $ResolveTo
            Mock New-CimSession { if ($script:SessionError) { throw $script:SessionError }; New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession' }
            Mock Remove-CimSession { }
            Mock Get-SmbShare {
                if ($script:ShareError) { throw $script:ShareError }
                @($script:Shares | Where-Object { -not $Name -or ($Name -contains $_.Name) })
            }
            # Honours -ClientUserName like the real cmdlet, so the path fallback is really needed
            # to find a file opened by a machine account.
            Mock Get-SmbOpenFile {
                if ($script:OpenFilesError) { throw $script:OpenFilesError }
                $files = @($script:OpenFiles)
                if ($ClientUserName) { $files = @($files | Where-Object { $ClientUserName -contains $_.ClientUserName }) }
                $files
            }
            Mock Resolve-TempProfileClientName { $script:ResolveTo }
        }
        function New-OpenFile([string]$RelativePath, [string]$Client = '10.20.30.44', [string]$User = 'CONTOSO\jdoe') {
            [pscustomobject]@{ FileId = 1; SessionId = 2; Path = ('D:\Profiles\' + $RelativePath); ShareRelativePath = $RelativePath; ClientComputerName = $Client; ClientUserName = $User; ScopeName = '*' }
        }
        $script:JdoeVhdx = 'S-1-5-21-1111111111-2222222222-3333333333-1105_jdoe\Profile_jdoe.vhdx'
        function Get-Lock([string[]]$Vhd = @('\\FS01\profiles\%username%'), [string[]]$Ccd = @()) {
            Get-TempProfileLockFact -UserName 'CONTOSO\jdoe' -Sid $script:Sid -VhdLocations $Vhd -CcdLocations $Ccd
        }
    }

    It 'AC2_LockByOtherHostIsTopCause: jdoe''s vhdx open from a client that resolves to CTX04 is Held (one open file, not an array) and ranks first' {
        Set-SmbScenario -OpenFiles (New-OpenFile $script:JdoeVhdx)
        $lock = Get-Lock
        $lock.State | Should -Be 'Held'
        $lock.FileServer | Should -Match '^FS01'
        $lock.FileName | Should -Match 'Profile_jdoe\.vhdx'
        $lock.ClientComputer | Should -Match '^CTX04'
        $lock.ClientResolved | Should -BeTrue
        Should -Invoke Get-SmbShare -ParameterFilter { $Name -contains 'profiles' } -Times 1
        $v = Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $lock })
        $v.TopCause.Id | Should -Be 'lock-held'
        $v.Summary | Should -Match 'CTX04'
    }

    It 'AC2_LockByOtherHostIsTopCause: a file opened by the machine account is still found through the SID folder, and other users'' or non-disk files are ignored' {
        $files = @(
            (New-OpenFile $script:JdoeVhdx -User 'CONTOSO\CTX04$')
            (New-OpenFile 'S-1-5-21-1111111111-2222222222-3333333333-1106_asmith\Profile_asmith.vhdx' -User 'CONTOSO\asmith' -Client '10.20.30.55')
            (New-OpenFile 'S-1-5-21-1111111111-2222222222-3333333333-1105_jdoe\notes.docx' -User 'CONTOSO\jdoe')
        )
        Set-SmbScenario -OpenFiles $files
        $lock = Get-Lock
        $lock.State | Should -Be 'Held'
        $lock.FileName | Should -Match 'Profile_jdoe\.vhdx'
        $lock.FileName | Should -Not -Match 'asmith'
    }

    It 'AC2_LockByOtherHostIsTopCause: a FlipFlop folder name (user first, then SID) is found too' {
        Set-SmbScenario -OpenFiles (New-OpenFile 'jdoe_S-1-5-21-1111111111-2222222222-3333333333-1105\Profile_jdoe.vhd' -User 'CONTOSO\CTX04$')
        (Get-Lock).State | Should -Be 'Held'
    }

    It 'AC4_UnresolvedClientShownAsIp: a client address that does not resolve is still Held and the sentence names the IP with "(name not found in DNS)"' {
        Set-SmbScenario -OpenFiles (New-OpenFile $script:JdoeVhdx) -ResolveTo $null
        $lock = Get-Lock
        $lock.State | Should -Be 'Held'
        $lock.ClientResolved | Should -BeFalse
        $lock.ClientAddress | Should -Be '10.20.30.44'
        $v = Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $lock })
        $v.Verdict | Should -Be 'CAUSE FOUND'
        $v.Summary | Should -Match '10\.20\.30\.44 \(name not found in DNS\)'
    }

    It 'AC10_LockCheckAccessDeniedIsCouldNotCheck: Get-SmbOpenFile access denied is CouldNotCheck with the reason and the required right' {
        Set-SmbScenario -OpenFilesError 'Access is denied.'
        $lock = Get-Lock
        $lock.State | Should -Be 'CouldNotCheck'
        $lock.Reason | Should -Match '(?i)access denied'
        $lock.Reason | Should -Match 'FS01'
        $lock.Reason | Should -Match '(?i)administrator of the file server'
    }

    It 'AC10_LockCheckAccessDeniedIsCouldNotCheck: access denied when opening the session to the file server is CouldNotCheck too' {
        Set-SmbScenario -SessionError 'Access is denied.'
        $lock = Get-Lock
        $lock.State | Should -Be 'CouldNotCheck'
        $lock.Reason | Should -Match '(?i)access denied'
    }

    It 'AC11_ShareNotOnServerIsCouldNotCheck: a share that is not on the server (a DFS namespace) is CouldNotCheck, not ruled out, whether Get-SmbShare returns nothing or throws' {
        foreach ($mode in 'empty', 'throws') {
            if ($mode -eq 'empty') { Set-SmbScenario -Shares @() }
            else { Set-SmbScenario -ShareError "No MSFT_SmbShare objects found with property 'Name' equal to 'profiles'." }
            $lock = Get-Lock -Vhd @('\\files\profiles')
            $lock.State | Should -Be 'CouldNotCheck' -Because $mode
            $lock.Reason | Should -Match '(?i)profile path may be a DFS namespace'
            $lock.Reason | Should -Match '(?i)run against the real file server'
            Should -Invoke Get-SmbOpenFile -Times 0 -Exactly -Because "${mode}: the open-file query must not run against a server that does not host the share"
        }
    }

    It 'AC12_AzureLocationIsCouldNotCheck: type=azure in CCDLocations, or a .file.core.windows.net host, is CouldNotCheck and no SMB query is attempted' {
        Set-SmbScenario
        $viaCcd = Get-Lock -Vhd @() -Ccd @('type=azure,connectionString=DefaultEndpointsProtocol=https;AccountName=contosofs;AccountKey=REDACTED;EndpointSuffix=core.windows.net')
        $viaCcd.State | Should -Be 'CouldNotCheck'
        $viaCcd.Reason | Should -Match '(?i)lock holders on Azure Files are not checked by this version'
        $viaHost = Get-Lock -Vhd @('\\contosofs.file.core.windows.net\profiles')
        $viaHost.State | Should -Be 'CouldNotCheck'
        $viaHost.Reason | Should -Match '(?i)lock holders on Azure Files are not checked by this version'
        Should -Invoke New-CimSession -Times 0 -Exactly
        Should -Invoke Get-SmbShare -Times 0 -Exactly
        Should -Invoke Get-SmbOpenFile -Times 0 -Exactly
    }

    It 'AC13_NoOpenFileIsRuledOut: the share exists and no open disk for jdoe is NotHeld with "FS01 shows no open profile disk for jdoe", which the ranker rules out' {
        Set-SmbScenario -OpenFiles @((New-OpenFile 'S-1-5-21-1111111111-2222222222-3333333333-1106_asmith\Profile_asmith.vhdx' -User 'CONTOSO\asmith'))
        $lock = Get-Lock
        $lock.State | Should -Be 'NotHeld'
        $lock.Detail | Should -Match 'FS01 shows no open profile disk for jdoe'
        $c = Get-Cause (Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $lock })) 'lock-held'
        $c.State | Should -Be 'RuledOut'
        (Join-Evidence $c) | Should -Match 'FS01 shows no open profile disk for jdoe'
    }

    It 'AC2_LockByOtherHostIsTopCause: the search of every open file is narrowed to the share''s scope and says it may be slow; -Quiet keeps it silent' {
        Set-SmbScenario -Shares @([pscustomobject]@{ Name = 'profiles'; ScopeName = 'FS-SOFS'; Path = 'D:\Profiles' }) -OpenFiles (New-OpenFile $script:JdoeVhdx -User 'CONTOSO\CTX04$')
        $out = @(Get-TempProfileLockFact -UserName 'CONTOSO\jdoe' -Sid $script:Sid -VhdLocations @('\\FS01\profiles') 6>&1)
        $lock = @($out | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })[0]
        $lock.State | Should -Be 'Held'
        $info = (@($out | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) | ForEach-Object { "$($_.MessageData)" }) -join "`n"
        $info | Should -Match '^\[INFO\] FS01 shows no profile disk open under jdoe''s own name'
        $info | Should -Match '(?i)can take a while on a busy file server'
        Should -Invoke Get-SmbOpenFile -ParameterFilter { -not $ClientUserName -and $ScopeName -contains 'FS-SOFS' } -Times 1 -Exactly

        $quiet = @(Get-TempProfileLockFact -UserName 'CONTOSO\jdoe' -Sid $script:Sid -VhdLocations @('\\FS01\profiles') -Quiet 6>&1)
        @($quiet | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }).Count | Should -Be 0
    }

    It 'AC2_LockByOtherHostIsTopCause: a share in the default scope (*) is searched without a scope filter' {
        Set-SmbScenario -Shares @([pscustomobject]@{ Name = 'profiles'; ScopeName = '*'; Path = 'D:\Profiles' }) -OpenFiles (New-OpenFile $script:JdoeVhdx -User 'CONTOSO\CTX04$')
        (Get-TempProfileLockFact -UserName 'CONTOSO\jdoe' -Sid $script:Sid -VhdLocations @('\\FS01\profiles') -Quiet).State | Should -Be 'Held'
        Should -Invoke Get-SmbOpenFile -ParameterFilter { -not $ClientUserName -and -not $ScopeName } -Times 1 -Exactly
    }

    It 'checks the cmdlet parameter names it relies on against the real SmbShare cmdlets (mocks can lie)' -Skip:(-not (Get-Command Get-SmbOpenFile -Module SmbShare -ErrorAction SilentlyContinue)) {
        $open = (Get-Command Get-SmbOpenFile -Module SmbShare).Parameters.Keys
        foreach ($p in 'ClientUserName', 'ClientComputerName', 'ScopeName', 'CimSession') { $open | Should -Contain $p }
        $share = (Get-Command Get-SmbShare -Module SmbShare).Parameters.Keys
        foreach ($p in 'Name', 'CimSession') { $share | Should -Contain $p }
    }
}

# =============================================================================
# FSLogix text log: reading and parsing
# =============================================================================
Describe 'FSLogix profile log' {
    BeforeAll {
        # Synthetic table; the numbers are test data. The real codes live in FSLogixReference.psd1.
        $script:Ref = @{
            StatusCodes = @{ '100' = @{ Text = 'test status'; Url = 'https://learn.microsoft.com/fslogix/' } }
            ReasonCodes = @{ '7' = @{ Meaning = 'LocalProfileExists'; Text = 'Local profile exists'; Url = 'https://learn.microsoft.com/fslogix/' } }
            ErrorCodes  = @{}
        }
        function New-LogLines {
            param([string]$Who, [string]$UserSid, [string[]]$Body)
            $t = 0
            $stamp = { param($n) ('[10:14:{0:00}.{1:000}][tid:00000a10.00000b20]' -f 58, $n) }
            $out = @()
            $out += (& $stamp 1) + "[INFO]   ===== Begin Session: LoadProfile: $Who"
            $out += (& $stamp 2) + "[INFO]   User: $UserSid ($Who)"
            $n = 10
            foreach ($b in $Body) { $out += (& $stamp $n) + $b; $n += 10 }
            $out += (& $stamp 900) + "[INFO]   ===== End Session: LoadProfile: $Who"
            $out
        }
        function Get-Parsed([string[]]$Lines) { ConvertFrom-TempProfileLog -Lines $Lines -UserName 'jdoe' -Sid $script:Sid -Reference $script:Ref }
        $script:OtherBlock = New-LogLines -Who 'asmith' -UserSid $script:OtherSid -Body @(
            '[INFO]   Reason set to 7: Local profile exists',
            '[ERROR:00000005]   Access is denied.'
        )
    }

    It 'reads a UTF-16LE file with a byte order mark without the mark or the nulls leaking into the lines' {
        $path = Join-Path $TestDrive 'Profile-test.log'
        $lines = @('[10:14:58.001][tid:00000a10.00000b20][INFO]   ===== Begin Session: LoadProfile: jdoe', '[10:14:58.002][tid:00000a10.00000b20][INFO]   User: S-1-5-21-1 (jdoe)')
        [System.IO.File]::WriteAllLines($path, [string[]]$lines, (New-Object System.Text.UnicodeEncoding($false, $true)))
        $read = @(Read-TempProfileLogLines -Path $path)
        $read.Count | Should -Be 2
        $read[0] | Should -Be $lines[0]
        $read[1] | Should -Be $lines[1]
    }

    It 'AC16_LocalProfileExists: a "Reason set to N" line mapped to LocalProfileExists is Found, quoting the line and time; another user''s block is ignored' {
        $mine = New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Status set to 100: test status', '[INFO]   Reason set to 7: Local profile exists')
        $p = Get-Parsed ($script:OtherBlock + $mine)
        $p.LocalProfile.State | Should -Be 'Found'
        $p.LocalProfile.Line | Should -Match 'Reason set to 7: Local profile exists'
        "$($p.LocalProfile.Time)" | Should -Match '10:14:58'
        $p.ShareAccess.State | Should -Be 'NoDenial' -Because 'the access denied line belongs to asmith''s block'
    }

    It 'AC16_LocalProfileExists: a block with only benign reasons is None, and a log with no block for the user is CouldNotCheck (never a false all-clear)' {
        $benign = New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Status set to 100: test status')
        (Get-Parsed $benign).LocalProfile.State | Should -Be 'None'
        $none = Get-Parsed $script:OtherBlock
        $none.LocalProfile.State | Should -Be 'CouldNotCheck'
        $none.LocalProfile.Reason | Should -Match 'jdoe'
        $none.ShareAccess.State | Should -Be 'CouldNotCheck'
    }

    It 'AC17_ShareAccessDenied: an [ERROR:00000005] access denied line in the user''s block is Denied, quoting the line and time' {
        $mine = New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Status set to 100: test status', '[ERROR:00000005]   Access is denied.')
        $p = Get-Parsed ($script:OtherBlock + $mine)
        $p.ShareAccess.State | Should -Be 'Denied'
        $p.ShareAccess.Line | Should -Match '(?i)access is denied'
        "$($p.ShareAccess.Time)" | Should -Match '10:14:'
    }

    It 'AC21_UnknownFslogixCodeShownVerbatim: "Reason set to 99: Something new" is returned as an unknown code and confirms nothing' {
        $mine = New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Reason set to 99: Something new')
        $p = Get-Parsed $mine
        @($p.UnknownCodes).Count | Should -Be 1
        @($p.UnknownCodes)[0].Code | Should -Be '99'
        @($p.UnknownCodes)[0].Text | Should -Be 'Something new'
        $p.LocalProfile.State | Should -Not -Be 'Found'
        $p.ShareAccess.State | Should -Not -Be 'Denied'
    }

    It 'reads a log FSLogix still has open for writing (the reader shares ReadWrite and Delete)' {
        $path = Join-Path $TestDrive 'Profile-open.log'
        $lines = @('[10:14:58.001][tid:00000a10.00000b20][INFO]   ===== Begin Session: LoadProfile: jdoe')
        [System.IO.File]::WriteAllLines($path, [string[]]$lines, (New-Object System.Text.UnicodeEncoding($false, $true)))
        $writer = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        try {
            $read = @(Read-TempProfileLogLines -Path $path)
        } finally {
            $writer.Dispose()
        }
        $read.Count | Should -Be 1
        $read[0] | Should -Be $lines[0]
    }

    It 'AC17_ShareAccessDenied: an HRESULT-wrapped access denied ([ERROR:80070005]) maps to Win32 error 5 and is Denied' {
        $mine = New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[ERROR:80070005]   Failed to open the virtual disk. Access is denied.')
        $p = Get-Parsed $mine
        $p.ShareAccess.State | Should -Be 'Denied'
        $p.ShareAccess.Line | Should -Match '80070005'
    }

    It 'AC16_LocalProfileExists: a session for OTHERDOM\jdoe (same name, another SID) is ignored when jdoe''s SID is known' {
        $other = New-LogLines -Who 'jdoe' -UserSid $script:OtherSid -Body @('[INFO]   Reason set to 7: Local profile exists', '[ERROR:00000005]   Access is denied.')
        $p = Get-Parsed $other
        $p.LocalProfile.State | Should -Be 'CouldNotCheck'
        $p.ShareAccess.State | Should -Be 'CouldNotCheck'
        $p.SignIns | Should -Be 0
        # Without the SID the name is all there is, so the session is taken.
        (ConvertFrom-TempProfileLog -Lines $other -UserName 'jdoe' -Reference $script:Ref).LocalProfile.State | Should -Be 'Found'
    }

    It 'AC16_LocalProfileExists: only sign-ins that began in the lookback window count: an old "Reason set to 3" before a newer clean sign-in does not confirm a local profile' {
        $ref = Get-FSLogixReference
        $old = @{ Name = 'Profile_20261010.log'; Lines = @(New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Reason set to 3: A local profile for this user exists on this system')) }
        $new = @{ Name = 'Profile-20261017.log'; Lines = @(New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Reason set to 0: The container is attached')) }
        $p = ConvertFrom-TempProfileLog -LogFiles @([pscustomobject]$old, [pscustomobject]$new) -UserName 'CONTOSO\jdoe' -Sid $script:Sid -Reference $ref -Since ([datetime]'2026-10-16 12:00')
        $p.LocalProfile.State | Should -Be 'None'
        $p.SignIns | Should -Be 1
        (@($p.Notes) -join "`n") | Should -Match '1 older sign-in'
        # The same old sign-in inside the window does confirm it, with its date.
        $p2 = ConvertFrom-TempProfileLog -LogFiles @([pscustomobject]$old, [pscustomobject]$new) -UserName 'CONTOSO\jdoe' -Sid $script:Sid -Reference $ref -Since ([datetime]'2026-10-09')
        $p2.LocalProfile.State | Should -Be 'Found'
        "$($p2.LocalProfile.Time)" | Should -Match '^2026-10-10 10:14:58'
    }

    It 'AC16_LocalProfileExists: when the log file name has no date only the latest sign-in is judged' {
        $ref = Get-FSLogixReference
        $lines = @(New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Reason set to 3: A local profile for this user exists on this system')) +
        @(New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Reason set to 0: The container is attached'))
        $p = ConvertFrom-TempProfileLog -LogFiles @([pscustomobject]@{ Name = 'Profile.log'; Lines = $lines }) -UserName 'jdoe' -Sid $script:Sid -Reference $ref -Since (Get-Date).AddHours(-24)
        $p.LocalProfile.State | Should -Be 'None'
        (@($p.Notes) -join "`n") | Should -Match '(?i)only the latest sign-in'
    }

    It 'reads the date from both log file name forms (Profile-yyyyMMdd and Profile_yyyy-MM-dd) and none from other names' {
        (Get-TempProfileLogFileDate -Name 'Profile-20261017.log') | Should -Be ([datetime]'2026-10-17')
        (Get-TempProfileLogFileDate -Name 'Profile_2026-10-17.log') | Should -Be ([datetime]'2026-10-17')
        (Get-TempProfileLogFileDate -Name 'Profile_20261017.log') | Should -Be ([datetime]'2026-10-17')
        Get-TempProfileLogFileDate -Name 'Profile.log' | Should -BeNullOrEmpty
        Get-TempProfileLogFileDate -Name 'Profile-20261399.log' | Should -BeNullOrEmpty
    }

    It 'Select-TempProfileUserLogLines keeps only jdoe''s own sessions (by SID when known), so other users'' lines never leave the host' {
        $mine = New-LogLines -Who 'jdoe' -UserSid $script:Sid -Body @('[INFO]   Reason set to 7: Local profile exists')
        $otherDomain = New-LogLines -Who 'jdoe' -UserSid $script:OtherSid -Body @('[INFO]   Status set to 100: other domain')
        $kept = @(Select-TempProfileUserLogLines -Lines ($script:OtherBlock + $mine + $otherDomain) -Sam 'jdoe' -Sid $script:Sid)
        $kept.Count | Should -Be $mine.Count
        ($kept -join "`n") | Should -Not -Match 'asmith|other domain'
        ($kept -join "`n") | Should -Match 'Reason set to 7'
        @(Select-TempProfileUserLogLines -Lines ($script:OtherBlock + $mine + $otherDomain) -Sam 'jdoe').Count | Should -Be ($mine.Count + $otherDomain.Count) -Because 'without the SID the name decides'
    }
}

Describe 'Get-TempProfileLogFact: reading the log on the session host' {
    BeforeAll {
        $script:LogRoot = Join-Path $TestDrive 'FSLogixLogs'
        $script:ProfileLogs = Join-Path $script:LogRoot 'Profile'
        $null = New-Item -ItemType Directory -Path $script:ProfileLogs -Force
        $script:Utf16 = New-Object System.Text.UnicodeEncoding($false, $true)
        function New-SessionLines([string]$Who, [string]$UserSid, [datetime]$When, [string]$Tid, [string[]]$Body) {
            $t = $When.ToString('HH:mm:ss.fff')
            $out = @("[$t][tid:$Tid][INFO]   ===== Begin Session: LoadProfile: $Who", "[$t][tid:$Tid][INFO]   User: $UserSid ($Who)")
            foreach ($b in $Body) { $out += "[$t][tid:$Tid]$b" }
            $out += "[$t][tid:$Tid][INFO]   ===== End Session: LoadProfile: $Who"
            $out
        }
        function Write-ProfileLog([string]$Name, [string[]]$Lines) {
            $path = Join-Path $script:ProfileLogs $Name
            [System.IO.File]::WriteAllLines($path, [string[]]$Lines, $script:Utf16)
            $path
        }
        $script:Recent = (Get-Date).AddHours(-1)
        $script:Old = (Get-Date).AddDays(-3)
    }
    BeforeEach {
        Get-ChildItem -LiteralPath $script:ProfileLogs | Remove-Item -Force
        # The session host's FSLogix logging settings point at the $TestDrive folder, and the
        # remote call runs the real block here; nothing reaches a real host or registry value.
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -eq 'HKLM:\SOFTWARE\FSLogix\Logging' } { [pscustomobject]@{ LogDir = $script:LogRoot; LoggingEnabled = 1 } }
        Mock Invoke-Command { $script:Shipped = & $ScriptBlock @ArgumentList; $script:Shipped }
    }

    It 'AC16_LocalProfileExists: sends jdoe''s sam and SID to the host, ships back only jdoe''s lines, reads a log FSLogix is writing, and skips sign-ins before the lookback window' {
        $null = Write-ProfileLog ('Profile-{0:yyyyMMdd}.log' -f $script:Old) (New-SessionLines 'jdoe' $script:Sid $script:Old 'a1' @('[INFO]   Reason set to 3: A local profile for this user exists on this system'))
        $today = Write-ProfileLog ('Profile-{0:yyyyMMdd}.log' -f $script:Recent) (
            @(New-SessionLines 'asmith' $script:OtherSid $script:Recent 'b2' @('[INFO]   Reason set to 3: A local profile for this user exists on this system', '[ERROR:00000005]   Access is denied.')) +
            @(New-SessionLines 'jdoe' $script:Sid $script:Recent 'c3' @('[INFO]   Reason set to 0: The container is attached')))
        $writer = New-Object System.IO.FileStream($today, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        try {
            $f = Get-TempProfileLogFact -ComputerName CTX07 -UserName 'CONTOSO\jdoe' -Sid $script:Sid -EventLookbackHours 24
        } finally {
            $writer.Dispose()
        }
        Should -Invoke Invoke-Command -ParameterFilter { $ComputerName -eq 'CTX07' -and $ArgumentList[3] -eq 'jdoe' -and $ArgumentList[4] -eq $script:Sid } -Times 1 -Exactly
        @($script:Shipped.Unreadable).Count | Should -Be 0
        $shipped = (@($script:Shipped.Logs) | ForEach-Object { @($_.Lines) }) -join "`n"
        $shipped | Should -Not -Match 'asmith'
        $shipped | Should -Not -Match ([regex]::Escape($script:OtherSid))
        $f.LocalProfile.State | Should -Be 'None' -Because 'the only "local profile exists" for jdoe began three days ago'
        $f.ShareAccess.State | Should -Be 'NoDenial' -Because 'the access denied line is asmith''s'
    }

    It 'names a log file that could not be read; what the others confirm still counts, and nothing is ruled out on part of the log' {
        $null = Write-ProfileLog ('Profile-{0:yyyyMMdd}.log' -f $script:Recent) (New-SessionLines 'jdoe' $script:Sid $script:Recent 'c3' @('[INFO]   Reason set to 0: The container is attached'))
        $locked = Write-ProfileLog ('Profile_{0:yyyy-MM-dd}.log' -f $script:Recent) @('[00:00:00.000][tid:d4][INFO]   x')
        $hold = New-Object System.IO.FileStream($locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $f = Get-TempProfileLogFact -ComputerName CTX07 -UserName 'CONTOSO\jdoe' -Sid $script:Sid -EventLookbackHours 24
        } finally {
            $hold.Dispose()
        }
        $name = Split-Path -Leaf $locked
        @($script:Shipped.Unreadable) -join ' ' | Should -Match ([regex]::Escape($name))
        $f.LocalProfile.State | Should -Be 'CouldNotCheck'
        $f.LocalProfile.Reason | Should -Match ([regex]::Escape($name))
        $f.ShareAccess.State | Should -Be 'CouldNotCheck'
        (@($f.Notes) -join "`n") | Should -Match ([regex]::Escape($name))

        # A confirmed finding in a readable file is not hidden by the unreadable one.
        $null = Write-ProfileLog ('Profile-{0:yyyyMMdd}.log' -f $script:Recent) (New-SessionLines 'jdoe' $script:Sid $script:Recent 'c3' @('[INFO]   Reason set to 3: A local profile for this user exists on this system'))
        $hold = New-Object System.IO.FileStream($locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $f2 = Get-TempProfileLogFact -ComputerName CTX07 -UserName 'CONTOSO\jdoe' -Sid $script:Sid -EventLookbackHours 24
        } finally {
            $hold.Dispose()
        }
        $f2.LocalProfile.State | Should -Be 'Found'
    }

    It 'every log file unreadable is Could not check, naming the files' {
        $locked = Write-ProfileLog ('Profile-{0:yyyyMMdd}.log' -f $script:Recent) (New-SessionLines 'jdoe' $script:Sid $script:Recent 'c3' @('[INFO]   Reason set to 3: x'))
        $hold = New-Object System.IO.FileStream($locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $f = Get-TempProfileLogFact -ComputerName CTX07 -UserName 'CONTOSO\jdoe' -Sid $script:Sid -EventLookbackHours 24
        } finally {
            $hold.Dispose()
        }
        $f.LocalProfile.State | Should -Be 'CouldNotCheck'
        $f.LocalProfile.Reason | Should -Match ([regex]::Escape((Split-Path -Leaf $locked)))
    }
}

Describe 'Get-TempProfileLoadedProfileFact: Win32_UserProfile' {
    BeforeAll {
        function Set-ProfileScenario([object[]]$Profiles) {
            $script:Profiles = $Profiles
            # Honours -Filter "SID='...'" like the real class, and is the only Get-CimInstance
            # call that may answer (anything else must not happen).
            Mock Get-CimInstance {
                if (-not (($ClassName -eq 'Win32_UserProfile') -or ($Query -match 'Win32_UserProfile'))) { throw 'unexpected CIM class' }
                $all = @($script:Profiles)
                $text = "$Filter $Query"
                if ($text -match "SID\s*=\s*'([^']+)'") { $sid = $Matches[1]; $all = @($all | Where-Object { $_.SID -eq $sid }) }
                $all
            }
        }
    }

    It 'AC22_TempProfileNowEvidence: a loaded profile with the temporary flag for jdoe''s SID is Temporary (another user''s temporary profile is ignored)' {
        Set-ProfileScenario @(
            [pscustomobject]@{ SID = $script:OtherSid; LocalPath = 'C:\Users\TEMP'; Loaded = $true; Status = 1 }
            [pscustomobject]@{ SID = $script:Sid; LocalPath = 'C:\Users\TEMP.CONTOSO'; Loaded = $true; Status = 1 }
        )
        (Get-TempProfileLoadedProfileFact -ComputerName CTX07 -Sid $script:Sid).State | Should -Be 'Temporary'
    }

    It 'AC22_TempProfileNowEvidence: a loaded normal profile is LoadedNormal and no profile at all is NotSignedIn' {
        Set-ProfileScenario @([pscustomobject]@{ SID = $script:Sid; LocalPath = 'C:\Users\jdoe'; Loaded = $true; Status = 0 })
        (Get-TempProfileLoadedProfileFact -ComputerName CTX07 -Sid $script:Sid).State | Should -Be 'LoadedNormal'
        Set-ProfileScenario @([pscustomobject]@{ SID = $script:OtherSid; LocalPath = 'C:\Users\asmith'; Loaded = $true; Status = 0 })
        (Get-TempProfileLoadedProfileFact -ComputerName CTX07 -Sid $script:Sid).State | Should -Be 'NotSignedIn'
    }

    It 'AC22_TempProfileNowEvidence: a CIM failure is CouldNotCheck, not NotSignedIn' {
        Mock Get-CimInstance { throw 'The WinRM client cannot process the request.' }
        $f = Get-TempProfileLoadedProfileFact -ComputerName CTX07 -Sid $script:Sid
        $f.State | Should -Be 'CouldNotCheck'
        $f.Reason | Should -Not -BeNullOrEmpty
    }
}

# =============================================================================
# The whole script (collectors mocked)
# =============================================================================
Describe 'Invoke-TempProfileInvestigation: console, verdicts, exit codes' {
    BeforeEach { Set-CleanCollectors }

    It 'AC1_HeadlineIsVerdictFirst: first line is the headline, then the cause sentence, then "Next step:", all before any evidence section' {
        Mock Get-TempProfileLockFact { $script:HeldLock }
        $c = Invoke-Main
        $l = $c.Lines
        $l[0] | Should -Be 'Temporary profile check for jdoe on CTX07:  CAUSE FOUND'
        $rest = @($l | Select-Object -Skip 1 | Where-Object { $_.Trim() -and $_ -notmatch '^[=\-\s]+$' })
        $rest[0] | Should -Be $c.Result.Summary
        $rest[0] | Should -Match 'CTX04'
        $rest[1] | Should -Be ('Next step: ' + $c.Result.NextStep)
        $nextAt = [array]::IndexOf($l, $rest[1])
        $sectionAt = @(0..($l.Count - 1) | Where-Object { $l[$_] -match '^(Other possible causes|Ruled out|Could not check|Evidence):$' })
        if ($sectionAt.Count -gt 0) { $nextAt | Should -BeLessThan $sectionAt[0] }
        Should -Invoke Get-TempProfileUserSid -ParameterFilter { $UserName -match '^[^\\]+\\jdoe$' } -Times 1 -Because 'a bare user name gets the domain'
    }

    It 'AC2_LockByOtherHostIsTopCause: the result object carries the lock as the top cause' {
        Mock Get-TempProfileLockFact { $script:HeldLock }
        $r = (Invoke-Main @{ Quiet = $true }).Result
        $r.Verdict | Should -Be 'CAUSE FOUND'
        $top = @($r.Causes | Sort-Object Rank | Where-Object { $_.State -eq 'Confirmed' })[0]
        $top.Title | Should -Match '(?i)disk held open by another computer'
    }

    It 'AC3_LockHolderSessionStateFromCitrix: with -DeliveryController the holder''s Citrix session state decides the sentence and next step' {
        Mock Get-TempProfileLockFact { $script:HeldLock }
        Mock Get-BrokerSession { @((New-BrokerSessionMock 'CTX07' 'Active'), (New-BrokerSessionMock 'CTX04' 'Disconnected')) }
        $r = (Invoke-Main @{ DeliveryController = 'CTX-DDC01'; Quiet = $true }).Result
        $r.Summary | Should -Match '(?i)session on CTX04 is disconnected'
        $r.NextStep | Should -Match '(?i)log.*off'
        $r.NextStep | Should -Match 'Director|Studio'
        $r.NextStep | Should -Match '(?i)sign in again'
    }

    It 'AC5_TwoCausesRankedWithEvidence: on the console the disk cause sits under "Other possible causes" with its evidence' {
        Mock Get-TempProfileLockFact { $script:HeldLock }
        Mock Invoke-CitrixFSLogixTriage { $script:Triage.DiskFail }
        $c = Invoke-Main
        $c.Result.Verdict | Should -Be 'CAUSE FOUND'
        $other = (Get-ConsoleSection $c.Lines 'Other possible causes:') -join "`n"
        $other | Should -Match "(?i)disk is full"
        $other | Should -Match 'GB free'
    }

    It 'AC6_NoCauseOnlyWhenEverythingLooked: a healthy host and clean collectors give NO CAUSE FOUND and exit code 0' {
        $r = (Invoke-Main @{ Quiet = $true }).Result
        $r.Verdict | Should -Be 'NO CAUSE FOUND'
        $r.ExitCode | Should -Be 0
        $r.NextStep | Should -Match '(?i)escalate'
        @($r.Causes | Where-Object { $_.State -ne 'RuledOut' }).Count | Should -Be 0
    }

    It 'AC7_CantTellWhenKeyCheckBlind: a blind lock check on an otherwise clean host is CAN''T TELL and the console next step names it' {
        Mock Get-TempProfileLockFact { $script:BlindLock }
        $c = Invoke-Main
        $c.Result.Verdict | Should -Be "CAN'T TELL"
        $c.Lines[0] | Should -Be "Temporary profile check for jdoe on CTX07:  CAN'T TELL"
        $c.Text | Should -Match 'Next step: .*access denied on FS01'
    }

    It 'AC8_HostUnreachable: a host that does not answer (the triage reports warnings, CIM and registry fail) is CAN''T TELL, "CTX07 could not be reached", exit 1' {
        Mock Invoke-CitrixFSLogixTriage { $script:Triage.Unreachable }
        Mock Get-TempProfileLockFact { $script:BlindLock }
        Mock Get-TempProfileLogFact { throw 'The WinRM client cannot process the request.' }
        Mock Get-TempProfileCrashFact { throw 'The WinRM client cannot process the request.' }
        Mock Get-TempProfileLoadedProfileFact { throw 'The WinRM client cannot process the request.' }
        $r = (Invoke-Main @{ Quiet = $true }).Result
        $r.Verdict | Should -Be "CAN'T TELL"
        $r.Summary | Should -Match 'CTX07 could not be reached'
        $r.ExitCode | Should -Be 1
    }

    It 'AC8_HostUnreachable: the same when the triage itself throws' {
        Mock Invoke-CitrixFSLogixTriage { throw 'The RPC server is unavailable.' }
        Mock Get-TempProfileLockFact { $script:BlindLock }
        Mock Get-TempProfileLogFact { throw 'The RPC server is unavailable.' }
        Mock Get-TempProfileCrashFact { throw 'The RPC server is unavailable.' }
        Mock Get-TempProfileLoadedProfileFact { throw 'The RPC server is unavailable.' }
        $r = (Invoke-Main @{ Quiet = $true }).Result
        $r.Verdict | Should -Be "CAN'T TELL"
        $r.Summary | Should -Match 'CTX07 could not be reached'
        $r.ExitCode | Should -Be 1
    }

    It 'AC9_ExitCodes: the result of a full run carries 2 for CAUSE FOUND, 1 for POSSIBLE CAUSE, 1 for CAN''T TELL and 0 for NO CAUSE FOUND' {
        Mock Get-TempProfileLockFact { $script:HeldLock }
        $found = (Invoke-Main @{ Quiet = $true }).Result
        $found.Verdict | Should -Be 'CAUSE FOUND'; $found.ExitCode | Should -Be 2

        Mock Get-TempProfileLockFact { New-Obj @{ State = 'NotHeld'; Reason = ''; Detail = 'FS01 shows no open profile disk for jdoe'; FileServer = 'FS01'; FileName = ''; ClientComputer = ''; ClientAddress = ''; ClientResolved = $true } }
        Mock Invoke-CitrixFSLogixTriage { $script:Triage.DiskWarn }
        $possible = (Invoke-Main @{ Quiet = $true }).Result
        $possible.Verdict | Should -Be 'POSSIBLE CAUSE'; $possible.ExitCode | Should -Be 1

        Mock Invoke-CitrixFSLogixTriage { $script:Triage.Healthy }
        Mock Get-TempProfileLockFact { $script:BlindLock }
        $cant = (Invoke-Main @{ Quiet = $true }).Result
        $cant.Verdict | Should -Be "CAN'T TELL"; $cant.ExitCode | Should -Be 1
    }

    It 'AC10_LockCheckAccessDeniedIsCouldNotCheck: a blind lock check is under "Could not check" on the console and the result, and never under "Ruled out"' {
        Mock Get-TempProfileLockFact { $script:BlindLock }
        $c = Invoke-Main
        $lock = @($c.Result.Causes | Where-Object { $_.Id -eq 'lock-held' })[0]
        $lock.State | Should -Be 'CouldNotCheck'
        ((Get-ConsoleSection $c.Lines 'Could not check:') -join "`n") | Should -Match '(?i)access denied on FS01'
        ((Get-ConsoleSection $c.Lines 'Ruled out:') -join "`n") | Should -Not -Match '(?i)profile disk|access denied|held open'
    }

    It 'AC23_DdcPicksActiveSession: the Active session''s host is investigated, and the Disconnected session on CTX04 is listed as evidence' {
        Mock Get-BrokerSession { @((New-BrokerSessionMock 'CTX04' 'Disconnected'), (New-BrokerSessionMock 'CTX07' 'Active')) }
        $r = (Invoke-Main @{ DeliveryController = 'CTX-DDC01'; Quiet = $true }).Result
        Should -Invoke Invoke-CitrixFSLogixTriage -ParameterFilter { $ComputerName -like 'CTX07*' } -Times 1 -Exactly
        Should -Invoke Invoke-CitrixFSLogixTriage -ParameterFilter { $ComputerName -like 'CTX04*' } -Times 0 -Exactly
        Should -Invoke Get-BrokerSession -ParameterFilter { $AdminAddress -eq 'CTX-DDC01' -and $UserName -match '\\jdoe$' } -Times 1
        $evidence = (@($r.Evidence) | ForEach-Object { "$_" }) -join "`n"
        $evidence | Should -Match 'CTX04'
        $evidence | Should -Match '(?i)disconnected'
    }

    It 'AC24_DdcNoSession: no Citrix session gives the [WARN] message, exit 1, and no host checks' {
        Mock Get-BrokerSession { }
        $c = Invoke-Main @{ DeliveryController = 'CTX-DDC01' }
        $c.Text | Should -Match '\[WARN\] jdoe has no Citrix session the Delivery Controller knows about\. Run again with -ComputerName '
        $c.Result.ExitCode | Should -Be 1
        Should -Invoke Invoke-CitrixFSLogixTriage -Times 0 -Exactly
        Should -Invoke Get-TempProfileLockFact -Times 0 -Exactly
    }

    It 'AC25_BrokerSdkMissing: no Citrix Broker snap-in gives the "run this on a Delivery Controller" message and exit 1' {
        Mock Import-CitrixBrokerSdk { $false }
        $c = Invoke-Main @{ DeliveryController = 'CTX-DDC01' }
        $c.Text | Should -Match ([regex]::Escape('Run this on a Delivery Controller or a PC with Citrix Studio, or use -ComputerName instead'))
        $c.Result.ExitCode | Should -Be 1
        Should -Invoke Get-BrokerSession -Times 0 -Exactly
        Should -Invoke Invoke-CitrixFSLogixTriage -Times 0 -Exactly
    }
}

Describe 'Get-TempProfileCrashFact: Service Control Manager events' {
    BeforeAll {
        function New-ScmEvent([string]$Service, [datetime]$When, [int]$Id = 7034) {
            [pscustomobject]@{
                Id = $Id; TimeCreated = $When; ProviderName = 'Service Control Manager'
                Message = ('The {0} service terminated unexpectedly.  It has done this 1 time(s).' -f $Service)
                Properties = @([pscustomobject]@{ Value = $Service }, [pscustomobject]@{ Value = 1 })
            }
        }
    }

    It 'AC15_FrxsvcCrashed: a 7034 for FSLogix Apps Services in the System log is Crashed with its time; the query asks CTX07''s System log for 7034/7031 in the window' {
        Mock Get-WinEvent { @((New-ScmEvent 'Print Spooler' ([datetime]'2026-10-17 08:00:00')), (New-ScmEvent 'FSLogix Apps Services' ([datetime]'2026-10-17 09:12:31'))) }
        $f = Get-TempProfileCrashFact -ComputerName CTX07 -EventLookbackHours 24
        $f.State | Should -Be 'Crashed'
        $f.EventId | Should -Be 7034
        $f.Time | Should -Be ([datetime]'2026-10-17 09:12:31')
        Should -Invoke Get-WinEvent -ParameterFilter {
            $ComputerName -eq 'CTX07' -and $FilterHashtable.LogName -eq 'System' -and $FilterHashtable.ProviderName -eq 'Service Control Manager' -and
            @($FilterHashtable.Id) -contains 7034 -and $FilterHashtable.StartTime -is [datetime]
        } -Times 1 -Exactly
        $c = Get-Cause (Get-TempProfileVerdict -Facts (New-Facts @{ ServiceCrash = $f })) 'frxsvc'
        $c.State | Should -Be 'Confirmed'
        (Join-Evidence $c) | Should -Match '2026-10-17 09:12:31'
    }

    It 'AC15_FrxsvcCrashed: a 7034 for another service only is None' {
        Mock Get-WinEvent { New-ScmEvent 'Print Spooler' ([datetime]'2026-10-17 08:00:00') }
        (Get-TempProfileCrashFact -ComputerName CTX07).State | Should -Be 'None'
    }

    It 'AC15_FrxsvcCrashed: "No events were found" is None (a clean answer), and the RPC server being unavailable is CouldNotCheck' {
        Mock Get-WinEvent { throw 'No events were found that match the specified selection criteria.' }
        (Get-TempProfileCrashFact -ComputerName CTX07).State | Should -Be 'None'
        Mock Get-WinEvent { throw 'The RPC server is unavailable.' }
        $f = Get-TempProfileCrashFact -ComputerName CTX07
        $f.State | Should -Be 'CouldNotCheck'
        $f.Reason | Should -Match 'RPC server is unavailable'
        (Get-Cause (Get-TempProfileVerdict -Facts (New-Facts @{ ServiceCrash = $f })) 'frxsvc').State | Should -Be 'CouldNotCheck'
    }
}

Describe 'Invoke-TempProfileInvestigation: host causes from the real triage output' {
    BeforeEach { Set-CleanCollectors }

    It 'AC14_FrxsvcStopped: the triage seeing frxsvc Stopped confirms "FSLogix service stopped on CTX07"' {
        Mock Invoke-CitrixFSLogixTriage { $script:Triage.ServiceStopped }
        $r = (Invoke-Main @{ Quiet = $true }).Result
        $c = @($r.Causes | Where-Object { $_.Id -eq 'frxsvc' })[0]
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Be 'FSLogix service stopped on CTX07'
        (@($c.Evidence) -join ' ') | Should -Match '(?i)Stopped'
        $r.Verdict | Should -Be 'CAUSE FOUND'
    }

    It 'AC19_FslogixOffOrNotConfigured: Enabled = 0, and Enabled = 1 with no profile location, both confirm "FSLogix profiles are off or not configured on CTX07"' {
        foreach ($scenario in 'FSLogixOff', 'NotConfigured') {
            $script:UseScenario = $scenario
            Mock Invoke-CitrixFSLogixTriage { $script:Triage[$script:UseScenario] }
            $r = (Invoke-Main @{ Quiet = $true }).Result
            $c = @($r.Causes | Where-Object { $_.Id -eq 'fslogix-off' })[0]
            $c.State | Should -Be 'Confirmed' -Because $scenario
            $c.Title | Should -Be 'FSLogix profiles are off or not configured on CTX07'
        }
    }

    It 'AC18_CloudCacheUnreachable: every Cloud Cache provider unreachable from the host and this PC is confirmed (with the share-test caveat); one of two is possible' {
        Mock Invoke-CitrixFSLogixTriage { $script:Triage.CloudCacheAllDown }
        $all = (Invoke-Main @{ Quiet = $true }).Result
        $c = @($all.Causes | Where-Object { $_.Id -eq 'storage' })[0]
        $c.State | Should -Be 'Confirmed'
        $c.Title | Should -Be 'Cloud Cache storage unreachable'
        $ev = @($c.Evidence) -join "`n"
        $ev | Should -Match '2 of 2 Cloud Cache location'
        $ev | Should -Match '(?i)no access to the share'

        Mock Invoke-CitrixFSLogixTriage { $script:Triage.CloudCacheSomeDown }
        $some = (Invoke-Main @{ Quiet = $true }).Result
        $c = @($some.Causes | Where-Object { $_.Id -eq 'storage' })[0]
        $c.State | Should -Be 'Possible'
        (@($c.Evidence) -join "`n") | Should -Match 'smb2'
        (@($c.Evidence) -join "`n") | Should -Not -Match 'smb1'
    }
}

Describe 'Invoke-TempProfileInvestigation: FSLogix events, user matching, lock holder, Citrix and user names' {
    BeforeEach { Set-CleanCollectors }

    It 'AC17_ShareAccessDenied: an FSLogix event with "Access is denied" on jdoe''s SID profile folder confirms "no permission on the profile share"; one saying the file is locked does not' {
        $denied = New-FslogixEvent ('Failed to open virtual disk \\files\profiles\{0}_jdoe\Profile_jdoe.vhdx. Access is denied.' -f $script:Sid)
        $script:TriageEvents = @($denied)
        Mock Invoke-CitrixFSLogixTriage { New-TriageWithEvents $script:Triage.Healthy $script:TriageEvents }
        $r = (Invoke-Main @{ Quiet = $true }).Result
        $c = @($r.Causes | Where-Object { $_.Id -eq 'share-denied' })[0]
        $c.State | Should -Be 'Confirmed'
        (@($c.Evidence) -join ' ') | Should -Match 'FSLogix event 26'

        $locked = New-FslogixEvent ('Failed to open virtual disk \\files\profiles\{0}_jdoe\Profile_jdoe.vhdx: the file is locked. Access is denied.' -f $script:Sid)
        $script:TriageEvents = @($locked)
        $r = (Invoke-Main @{ Quiet = $true }).Result
        @($r.Causes | Where-Object { $_.Id -eq 'share-denied' })[0].State | Should -Be 'RuledOut'
    }

    It 'AC17_ShareAccessDenied: an access-denied event about CONTOSO\jdoe.smith (or jdoe-admin) confirms nothing for jdoe; one naming CONTOSO\jdoe does' {
        $events = @(
            (New-FslogixEvent 'Access is denied for CONTOSO\jdoe.smith opening \\files\profiles\S-1-5-21-1111111111-2222222222-3333333333-1199_jdoe.smith\Profile_jdoe.smith.vhdx.')
            (New-FslogixEvent 'Access is denied for CONTOSO\jdoe-admin.')
        )
        $script:TriageEvents = $events
        Mock Invoke-CitrixFSLogixTriage { New-TriageWithEvents $script:Triage.Healthy $script:TriageEvents }
        $r = (Invoke-Main @{ UserName = 'CONTOSO\jdoe'; Quiet = $true }).Result
        @($r.Causes | Where-Object { $_.Id -eq 'share-denied' })[0].State | Should -Be 'RuledOut'

        $mine = New-FslogixEvent 'Access is denied for CONTOSO\jdoe.'
        $script:TriageEvents = @($mine)
        $r = (Invoke-Main @{ UserName = 'CONTOSO\jdoe'; Quiet = $true }).Result
        @($r.Causes | Where-Object { $_.Id -eq 'share-denied' })[0].State | Should -Be 'Confirmed'
    }

    It 'Test-TempProfileTextNamesUser matches the SID, DOMAIN\sam and the SID profile folder, never a longer name' {
        Test-TempProfileTextNamesUser -Text "path \\fs\p\$($script:Sid)_jdoe\x" -UserName 'CONTOSO\jdoe' -Sid $script:Sid | Should -BeTrue
        Test-TempProfileTextNamesUser -Text 'user CONTOSO\jdoe.' -UserName 'CONTOSO\jdoe' -Sid $script:Sid | Should -BeTrue
        Test-TempProfileTextNamesUser -Text 'path \\fs\p\S-1-5-21-9-9-9-1105_jdoe\x' -UserName 'CONTOSO\jdoe' | Should -BeTrue -Because 'without the SID the folder name is used'
        Test-TempProfileTextNamesUser -Text 'path \\fs\p\jdoe_S-1-5-21-9-9-9-1105\x' -UserName 'CONTOSO\jdoe' | Should -BeTrue
        foreach ($t in 'CONTOSO\jdoe.smith', 'CONTOSO\jdoe-admin', 'CONTOSO\jdoe2', 'jdoe', 'OTHERDOM\jdoe', "$($script:Sid)0", 'S-1-5-21-9-9-9-1105_jdoe.smith\x') {
            Test-TempProfileTextNamesUser -Text "Access is denied: $t" -UserName 'CONTOSO\jdoe' -Sid $script:Sid | Should -BeFalse -Because $t
        }
    }

    It 'AC4_UnresolvedClientShownAsIp: an unresolved holder address that is one of CTX07''s own addresses is the host itself (Possible), not "another computer"' {
        $own = New-Obj @{ State = 'Held'; Reason = ''; Detail = ''; FileServer = 'FS01'; FileName = 'S-1-5-21-1111111111-2222222222-3333333333-1105_jdoe\Profile_jdoe.vhdx'; ClientComputer = ''; ClientAddress = '10.20.30.47'; ClientResolved = $false }
        $script:OwnLock = $own
        Mock Get-TempProfileLockFact { $script:OwnLock }
        Mock Get-TempProfileHostAddress { @('10.20.30.47', 'fe80::1') }
        $r = (Invoke-Main @{ Quiet = $true }).Result
        Should -Invoke Get-TempProfileHostAddress -ParameterFilter { $ComputerName -eq 'CTX07' } -Times 1 -Exactly
        $c = @($r.Causes | Where-Object { $_.Id -eq 'lock-held' })[0]
        $c.State | Should -Be 'Possible'
        $r.Summary | Should -Match 'CTX07 itself'

        # The ranker alone: no host addresses known -> the address is "elsewhere" and confirmed.
        (Get-Cause (Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $own })) 'lock-held').State | Should -Be 'Confirmed'
        (Get-Cause (Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $own; HostAddresses = @('10.20.30.47') })) 'lock-held').State | Should -Be 'Possible'
    }

    It 'AC3_LockHolderSessionStateFromCitrix: a holder session that is not known to be Disconnected gets "ask jdoe to save their work and sign out", with logging it off as the fallback' {
        $active = Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $script:HeldLock; Sessions = @((New-Obj @{ Machine = 'CTX04'; State = 'Active' })) })
        $active.NextStep | Should -Match "(?i)ask jdoe to save their work and sign out of CTX04, or if they can't, log that session off in Director/Studio"
        $unknown = Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $script:HeldLock })
        $unknown.NextStep | Should -Match "(?i)ask jdoe to save their work and sign out of CTX04, or if they can't, log that session off in Director/Studio"
        $hint = Get-TempProfileVerdict -Facts (New-Facts @{ Lock = $script:BlindLock; LockHint = (New-Obj @{ Line = '[ERROR:00000021] locked'; Time = '10:14:58' }) })
        $hint.NextStep | Should -Match "(?i)save their work and sign out of it, or if they can't, log that session off"
    }

    It 'UPN: -UserName jdoe@contoso.com is jdoe everywhere, and the collectors get CONTOSO\jdoe from the SID' {
        Mock ConvertTo-TempProfileAccountName { 'CONTOSO\jdoe' }
        Mock Get-BrokerSession { @((New-BrokerSessionMock 'CTX07' 'Active')) }
        $r = (Invoke-Main @{ UserName = 'jdoe@contoso.com'; ComputerName = 'CTX07'; DeliveryController = 'CTX-DDC01'; Quiet = $true }).Result
        $r.UserName | Should -Be 'jdoe'
        Should -Invoke Get-TempProfileUserSid -ParameterFilter { $UserName -eq 'jdoe@contoso.com' } -Times 1 -Exactly
        Should -Invoke ConvertTo-TempProfileAccountName -ParameterFilter { $Sid -eq $script:Sid } -Times 1 -Exactly
        Should -Invoke Invoke-CitrixFSLogixTriage -ParameterFilter { $UserName -eq 'jdoe' } -Times 1 -Exactly
        Should -Invoke Get-TempProfileLockFact -ParameterFilter { $UserName -eq 'CONTOSO\jdoe' } -Times 1 -Exactly
        Should -Invoke Get-TempProfileLogFact -ParameterFilter { $UserName -eq 'CONTOSO\jdoe' } -Times 1 -Exactly
        Should -Invoke Get-BrokerSession -ParameterFilter { $UserName -eq 'CONTOSO\jdoe' } -Times 1 -Exactly
    }

    It 'UPN: when the SID cannot be turned back into a name, the collectors get DOMAIN\jdoe with this PC''s domain, never the UPN' {
        Mock ConvertTo-TempProfileAccountName { throw 'The trust relationship failed.' }
        $null = Invoke-Main @{ UserName = 'jdoe@contoso.com'; Quiet = $true }
        Should -Invoke Get-TempProfileLockFact -ParameterFilter { $UserName -match '^[^\\@]+\\jdoe$' } -Times 1 -Exactly
        Should -Invoke Get-TempProfileLogFact -ParameterFilter { $UserName -match '^[^\\@]+\\jdoe$' } -Times 1 -Exactly
        Get-TempProfileSamName 'jdoe@contoso.com' | Should -Be 'jdoe'
        Get-TempProfileSamName 'CONTOSO\jdoe' | Should -Be 'jdoe'
        Get-TempProfileSamName 'svc$' | Should -Be 'svc$'
    }

    It 'with -ComputerName and -DeliveryController, a missing Broker snap-in is a "could not check Citrix sessions" note and the host checks still run' {
        Mock Import-CitrixBrokerSdk { $false }
        $c = Invoke-Main @{ ComputerName = 'CTX07'; DeliveryController = 'CTX-DDC01' }
        Should -Invoke Invoke-CitrixFSLogixTriage -ParameterFilter { $ComputerName -eq 'CTX07' } -Times 1 -Exactly
        Should -Invoke Get-BrokerSession -Times 0 -Exactly
        $c.Result.Verdict | Should -Be 'NO CAUSE FOUND'
        (@($c.Result.Evidence) -join "`n") | Should -Match "(?i)Could not check jdoe's Citrix sessions: the Citrix Broker snap-in"
        $c.Text | Should -Match '\[WARN\] Could not check jdoe''s Citrix sessions'
    }

    It 'with -ComputerName and -DeliveryController, a failed Broker query is a note too and the host checks still run' {
        Mock Get-BrokerSession { throw 'Insufficient administrative privilege' }
        $r = (Invoke-Main @{ ComputerName = 'CTX07'; DeliveryController = 'CTX-DDC01'; Quiet = $true }).Result
        Should -Invoke Invoke-CitrixFSLogixTriage -Times 1 -Exactly
        (@($r.Evidence) -join "`n") | Should -Match "(?i)Could not check jdoe's Citrix sessions: CTX-DDC01 could not be asked \(Insufficient administrative privilege\)"
        $r.Error | Should -Match 'Citrix sessions'
    }
}

Describe 'Invoke-TempProfileInvestigation: ticket note, paste-safe, pass-thru' {
    BeforeEach { Set-CleanCollectors }

    It 'AC27_TicketNoteRespectsGate: the blind lock check is under "Could not check", the clean frxsvc check under "Ruled out", and the Next step equals the console''s' {
        Mock Get-TempProfileLockFact { $script:BlindLock }
        $out = Join-Path $TestDrive 'ac27'
        $null = New-Item -ItemType Directory -Path $out
        $c = Invoke-Main @{ TicketNumber = '482113'; OutputPath = $out }
        $note = $c.Result.TicketNote
        $note | Should -Not -BeNullOrEmpty
        (@($note.CouldNotCheck) -join "`n") | Should -Match '(?i)profile disk|access denied'
        (@($note.RuledOut) -join "`n") | Should -Match '(?i)frxsvc|FSLogix service'
        (@($note.RuledOut) -join "`n") | Should -Not -Match '(?i)profile disk|access denied'
        @($note.NextSteps) | Should -Contain $c.Result.NextStep
        $c.Text | Should -Match ([regex]::Escape('Next step: ' + $c.Result.NextStep))
        $file = @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_482113') -Filter 'Note_*.txt')
        $file.Count | Should -Be 1
        $text = [System.IO.File]::ReadAllText($file[0].FullName)
        $text | Should -Match 'Could not check:'
        $text | Should -Match 'Ruled out:'
    }

    It 'AC28_PasteSafeDropsPaths: the saved note has no VHD(X) path, profile path, UNC path or IP address; the server and user names remain' {
        Mock Get-TempProfileLockFact {
            New-Obj @{ State = 'Held'; Reason = ''; Detail = ''; FileServer = 'FS01'; FileName = 'S-1-5-21-1111111111-2222222222-3333333333-1105_jdoe\Profile_jdoe.vhdx'; ClientComputer = ''; ClientAddress = '10.20.30.44'; ClientResolved = $false }
        }
        Mock Get-TempProfileLogFact {
            New-Obj @{
                # A UNC disk path, a bare SID, an Entra (S-1-12-) SID and local paths with spaces.
                LocalProfile = New-Obj @{ State = 'Found'; Reason = ''; Line = 'Reason set to 7: Local profile exists (\\files\profiles\S-1-5-21-1111111111-2222222222-3333333333-1105_jdoe\Profile_jdoe.vhdx) for S-1-5-21-1111111111-2222222222-3333333333-1105 (Entra S-1-12-1-1111111111-2222222222-3333333333-4444444444), old copy at D:\Profile Disks\jdoe old\Profile_jdoe.vhdx and C:\Users\TEMP.CONTOSO\App Data\x.dat'; Time = '10:14:58.060'; Code = '7' }
                ShareAccess  = New-Obj @{ State = 'NoDenial'; Reason = ''; Line = ''; Time = '' }
                UnknownCodes = @()
            }
        }
        $out = Join-Path $TestDrive 'ac28'
        $null = New-Item -ItemType Directory -Path $out
        $null = Invoke-Main @{ TicketNumber = '482113'; OutputPath = $out }
        $file = @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_482113') -Filter 'Note_*.txt')
        $file.Count | Should -Be 1
        $text = [System.IO.File]::ReadAllText($file[0].FullName)
        $text | Should -Not -Match '\\\\\w'
        $text | Should -Not -Match '(?i)\.vhdx?\b'
        $text | Should -Not -Match '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        $text | Should -Not -Match 'S-1-5-21-\d+-\d+-\d+-\d+_jdoe\\'
        $text | Should -Not -Match 'S-1-\d+(-\d+)+' -Because 'bare SIDs, including Entra S-1-12- SIDs, are removed'
        $text | Should -Not -Match 'Profile Disks|jdoe old|App Data' -Because 'a path with spaces is removed whole'
        $text | Should -Not -Match '(?<![\w])[A-Za-z]:\\'
        $text | Should -Match 'CTX07'
        $text | Should -Match 'jdoe'
    }

    It 'AC28_PasteSafeDropsPaths: a session host given as an IP address is removed from the note, headline included; -FullDetail keeps it' {
        $out = Join-Path $TestDrive 'ac28ip'
        $null = New-Item -ItemType Directory -Path $out
        $c = Invoke-Main @{ ComputerName = '10.20.30.47'; TicketNumber = '482114'; OutputPath = $out }
        $file = @(Get-ChildItem -LiteralPath (Join-Path $out 'Ticket_482114') -Filter 'Note_*.txt')
        $file.Count | Should -Be 1
        $text = [System.IO.File]::ReadAllText($file[0].FullName)
        $text | Should -Not -Match '10\.20\.30\.47'
        $text | Should -Match 'jdoe'
        $c.Result.TicketNote.Headline | Should -Not -Match '10\.20\.30\.47'
        $full = (Invoke-Main @{ ComputerName = '10.20.30.47'; FullDetail = $true; Quiet = $true }).Result
        $full.TicketNote.Headline | Should -Match '10\.20\.30\.47'
    }

    It 'AC28_PasteSafeDropsPaths: Protect-TempProfileNoteText removes spaced disk and local paths and bare SIDs, and keeps names and plain text' {
        $t = Protect-TempProfileNoteText -Text 'jdoe on CTX07: D:\Profile Disks\S-1-5-21-1-2-3-1105_jdoe\Profile_jdoe.vhdx, user S-1-12-1-11-22-33-44, folder C:\Users\TEMP.CONTOSO\App Data\x.dat. Done.'
        $t | Should -Not -Match 'Profile Disks|App Data|S-1-|\.vhdx'
        $t | Should -Match '^jdoe on CTX07: '
        $t | Should -Match '\[SID removed\]'
        $t | Should -Match 'Done\.$'
    }

    It 'AC29_PassThruShape: -Quiet returns the result object with the contracted properties and writes nothing to the host' {
        Mock Get-TempProfileLockFact { $script:HeldLock }
        $all = @(Invoke-TempProfileInvestigation -UserName jdoe -ComputerName CTX07 -NoClipboard -Quiet 6>&1)
        @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }).Count | Should -Be 0
        $r = @($all | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['CheckId'] })[0]
        $r | Should -Not -BeNullOrEmpty
        foreach ($p in 'CheckId', 'Status', 'Verdict', 'Summary', 'Causes', 'Evidence', 'RecommendedNextSteps', 'RawOutput', 'StartedAt', 'FinishedAt', 'Error', 'ExitCode', 'TicketNote') {
            $r.PSObject.Properties.Name | Should -Contain $p
        }
        $r.CheckId | Should -Be 'fslogix.tempprofile'
        $r.Status | Should -BeIn @('Pass', 'Warn', 'Fail')
        @($r.Causes).Count | Should -BeGreaterThan 0
        foreach ($cause in @($r.Causes)) {
            foreach ($p in 'Id', 'Title', 'State', 'Evidence', 'NextStep', 'Rank') { $cause.PSObject.Properties.Name | Should -Contain $p }
            $cause.State | Should -BeIn @('Confirmed', 'Possible', 'RuledOut', 'CouldNotCheck')
        }
        @($r.RecommendedNextSteps).Count | Should -BeGreaterThan 0
    }

    It 'AC29_PassThruShape: the script takes -PassThru, -Quiet, -TicketNumber, -NoClipboard, -FullDetail, -OutputPath, -EventLookbackHours and the aliases' {
        $cmd = Get-Command $script:ScriptPath
        foreach ($p in 'UserName', 'ComputerName', 'DeliveryController', 'EventLookbackHours', 'OutputPath', 'TicketNumber', 'NoClipboard', 'FullDetail', 'PassThru', 'Quiet', 'LoadFunctionsOnly') {
            $cmd.Parameters.Keys | Should -Contain $p
        }
        foreach ($p in 'PassThru', 'Quiet', 'NoClipboard', 'FullDetail') { $cmd.Parameters[$p].SwitchParameter | Should -BeTrue }
        $cmd.Parameters['UserName'].Aliases | Should -Contain 'AffectedUser'
        $cmd.Parameters['ComputerName'].Aliases | Should -Contain 'AffectedDevice'
        $cmd.Parameters['EventLookbackHours'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] } |
            ForEach-Object { $_.MinRange | Should -Be 1; $_.MaxRange | Should -Be 168 }
    }
}

# =============================================================================
# Static checks: safety, reference table, PS 3.0 floor, bundle row
# =============================================================================
Describe 'static checks on the script and its data' {
    BeforeAll {
        $tokens = $null; $errors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        $script:ParseErrors = @($errors)
        $script:Commands = @($script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true))
        $script:CommandNames = @($script:Commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $script:Ps5OnlyCommands = @(
            'Compress-Archive', 'Expand-Archive', 'New-TemporaryFile', 'Get-ItemPropertyValue',
            'Get-Clipboard', 'Set-Clipboard', 'Write-Information', 'Format-Hex', 'ConvertFrom-String',
            'Clear-RecycleBin', 'New-Guid', 'Get-ComputerInfo', 'Get-LocalUser', 'ConvertFrom-SddlString'
        )
        function ConvertTo-Canonical($Value) {
            if ($Value -is [System.Collections.IDictionary]) {
                $o = [ordered]@{}
                foreach ($k in ($Value.Keys | Sort-Object { "$_" })) { $o["$k"] = ConvertTo-Canonical $Value[$k] }
                return $o
            }
            if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return @($Value | ForEach-Object { ConvertTo-Canonical $_ }) }
            return $Value
        }
    }

    It 'AC26_NeverChangesAnything: the script reads (it uses the SMB and Broker lookups) and calls no command that changes a session, file handle, profile, registry value or service' {
        $script:CommandNames | Should -Contain 'Get-SmbOpenFile' -Because 'an empty script would trivially pass this guard'
        $script:CommandNames | Should -Contain 'Get-BrokerSession'
        $forbidden = @(
            'Stop-BrokerSession', 'Disconnect-BrokerSession', 'Close-SmbOpenFile', 'Invoke-CimMethod', 'Invoke-WmiMethod',
            'New-ItemProperty', 'logoff', 'logoff.exe', 'rwinsta', 'rwinsta.exe', 'reset', 'reset.exe', 'shutdown', 'shutdown.exe'
        )
        # Set-Content for the tool's own output; Set-StrictMode and Remove-CimSession change
        # nothing on a target (a local strictness switch; closing this PC's own CIM session).
        $allowed = @('Set-Content', 'Set-StrictMode', 'Remove-CimSession')
        $offenders = @($script:CommandNames | Where-Object {
                ($forbidden -contains $_) -or
                (($_ -match '^(Stop|Restart|Set|Remove|Disconnect|Close|Suspend|Clear|Disable)-') -and ($allowed -notcontains $_))
            })
        $offenders | Should -BeNullOrEmpty
    }

    It 'AC26_NeverChangesAnything: neither the script nor the companions it loads (the triage, CaseKit) call a command or .NET method that changes anything' {
        $files = @($script:ScriptPath, $script:TriagePath, (Join-Path $script:Root 'CaseKit.ps1'))
        $forbidden = @(
            'Stop-BrokerSession', 'Disconnect-BrokerSession', 'Close-SmbOpenFile', 'Invoke-CimMethod', 'Invoke-WmiMethod',
            'New-ItemProperty', 'New-Service', 'Invoke-Expression', 'iex', 'Out-File',
            'logoff', 'logoff.exe', 'rwinsta', 'rwinsta.exe', 'reset', 'reset.exe', 'shutdown', 'shutdown.exe'
        )
        # Set-Content writes the tools' own reports, Set-Clipboard is CaseKit's clipboard helper;
        # Set-StrictMode and Remove-CimSession change nothing on a target.
        $allowed = @('Set-Content', 'Set-Clipboard', 'Set-StrictMode', 'Remove-CimSession')
        $blockedMembers = @('Delete', 'Kill', 'Terminate', 'SetValue', 'DeleteValue', 'CreateSubKey')
        $offenders = New-Object System.Collections.Generic.List[string]
        foreach ($file in $files) {
            $tokens = $null; $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
            $leaf = Split-Path -Leaf $file
            foreach ($cmd in @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true))) {
                $name = $cmd.GetCommandName()
                if (-not $name) { continue }
                if (($forbidden -contains $name) -or
                    (($name -match '^(Stop|Restart|Set|Remove|Disconnect|Close|Suspend|Clear|Disable|Start|Enable|Rename|Move|Register)-') -and ($allowed -notcontains $name))) {
                    $offenders.Add("${leaf} line $($cmd.Extent.StartLineNumber): $name")
                }
            }
            foreach ($call in @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true))) {
                $member = $call.Member.Extent.Text.Trim("'", '"')
                $writableOpen = ($member -eq 'OpenSubKey' -and @($call.Arguments).Count -ge 2 -and $call.Arguments[1].Extent.Text -notmatch '^\$false$')
                if (($blockedMembers -contains $member) -or ($member -like 'DeleteSubKey*') -or $writableOpen) {
                    $offenders.Add("${leaf} line $($call.Extent.StartLineNumber): .$member()")
                }
            }
        }
        @($offenders) | Should -BeNullOrEmpty
    }

    It 'AC30_ReferenceTableCitedAndInParity: every code in FSLogixReference.psd1 has a learn.microsoft.com URL' {
        $path = Join-Path $script:Root 'FSLogixReference.psd1'
        $path | Should -Exist
        $ref = Import-PowerShellDataFile -LiteralPath $path
        $count = 0
        foreach ($section in 'StatusCodes', 'ReasonCodes', 'ErrorCodes') {
            $ref.Keys | Should -Contain $section
            foreach ($code in $ref[$section].Keys) {
                $ref[$section][$code].Url | Should -Match '^https://learn\.microsoft\.com/' -Because "$section $code"
                $count++
            }
        }
        $count | Should -BeGreaterThan 0
        @($ref.ReasonCodes.Values | Where-Object { $_.Meaning -eq 'LocalProfileExists' }).Count | Should -BeGreaterThan 0 -Because 'rule 16 needs a documented code for "local profile exists"'
    }

    It 'AC30_ReferenceTableCitedAndInParity: the script''s built-in fallback table equals the psd1' {
        $ref = Import-PowerShellDataFile -LiteralPath (Join-Path $script:Root 'FSLogixReference.psd1')
        $fallback = $script:FSLogixReferenceFallback
        $fallback | Should -Not -BeNullOrEmpty
        (ConvertTo-Json -InputObject (ConvertTo-Canonical $fallback) -Depth 8) | Should -Be (ConvertTo-Json -InputObject (ConvertTo-Canonical $ref) -Depth 8)
    }

    It 'AC30_ReferenceTableCitedAndInParity: Get-FSLogixReference returns the table (psd1 beside the script, else the fallback)' {
        $t = Get-FSLogixReference
        foreach ($section in 'StatusCodes', 'ReasonCodes', 'ErrorCodes') { $t.Keys | Should -Contain $section }
    }

    It 'AC31_Ps3Floor: parses with no errors and declares #Requires -Version 3.0' {
        $script:ParseErrors | Should -BeNullOrEmpty
        $required = $script:Ast.ScriptRequirements.RequiredPSVersion
        $required | Should -Not -BeNullOrEmpty
        $required | Should -BeLessOrEqual ([version]'3.0')
    }

    It 'AC31_Ps3Floor: no classes, ::new(), .Where()/.ForEach(), using statements, 5.x-only cmdlets, -NoNewline or -Depth' {
        @($script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)).Count | Should -Be 0
        $news = $script:Ast.FindAll({ $n = $args[0]; $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and $n.Member.Extent.Text -eq 'new' }, $true)
        @($news | ForEach-Object { "line $($_.Extent.StartLineNumber)" }) | Should -BeNullOrEmpty
        $m = $script:Ast.FindAll({ $n = $args[0]; $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and -not $n.Static -and ('Where', 'ForEach') -contains $n.Member.Extent.Text }, $true)
        @($m | ForEach-Object { "line $($_.Extent.StartLineNumber)" }) | Should -BeNullOrEmpty
        @($script:Ast.UsingStatements).Count | Should -Be 0
        $offenders = @($script:Commands | Where-Object { $script:Ps5OnlyCommands -contains $_.GetCommandName() })
        @($offenders | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
        $p = $script:Ast.FindAll({ $n = $args[0]; $n -is [System.Management.Automation.Language.CommandParameterAst] -and ('NoNewline', 'Depth') -contains $n.ParameterName }, $true)
        @($p | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }

    It 'AC31_Ps3Floor: loads the psd1 (so it is not dead data) and calls Import-PowerShellDataFile only behind a Get-Command check' {
        $script:CommandNames | Where-Object { $_ -in 'Import-PowerShellDataFile', 'Import-LocalizedData' } | Should -Not -BeNullOrEmpty -Because 'the script must read FSLogixReference.psd1'
        $calls = @($script:Commands | Where-Object { $_.GetCommandName() -eq 'Import-PowerShellDataFile' })
        foreach ($call in $calls) {
            $guard = $null
            $node = $call.Parent
            while ($node) {
                if ($node -is [System.Management.Automation.Language.IfStatementAst]) {
                    foreach ($clause in $node.Clauses) { if ($clause.Item1.Extent.Text -match 'Get-Command') { $guard = $clause.Item1 } }
                }
                $node = $node.Parent
            }
            $guard | Should -Not -BeNullOrEmpty -Because "line $($call.Extent.StartLineNumber): Import-PowerShellDataFile needs a Get-Command guard (PowerShell 5.0+)"
        }
    }

    It 'AC31_Ps3Floor: is pure ASCII, so it needs no BOM to survive Windows PowerShell' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'AC32_BundleRowReplaced: the START HERE table has exactly one temporary-profile row and it names Invoke-TempProfileInvestigation' {
        $readme = Join-Path $script:RepoRoot 'ServiceDesk-Toolkit\README.md'
        $rows = @(Get-Content -LiteralPath $readme | Where-Object { $_ -match '^\s*\|' -and $_ -match '(?i)temp(orary)? profile' })
        $rows.Count | Should -Be 1
        $rows[0] | Should -Match 'Invoke-TempProfileInvestigation'
    }
}
