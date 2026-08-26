#Requires -Version 5.1

<#
.SYNOPSIS
    Verifies that the Entra Connect hybrid checks can actually read what they assume,
    before you rely on them during a lockout investigation.

.DESCRIPTION
    The hybrid section of Diagnose-ADAccountLockout.ps1 rests on a handful of assumptions
    about a live sync server: that a particular event provider is registered, that a
    particular log channel exists under a particular name, and that this account can read
    both of them remotely.

    Every one of those assumptions fails the same way - the query returns nothing - and an
    empty result is indistinguishable from a healthy, quiet server. That is the failure
    mode worth spending a minute to rule out, because it produces a confident wrong answer
    rather than an error.

    This script makes each assumption explicit and reports PASS/WARN/FAIL against a real
    server. It is READ-ONLY: it enumerates providers and log channels and reads at most a
    handful of events. It changes nothing.

    Run it once against your Entra Connect server before the first real investigation, and
    again after any Entra Connect upgrade.

.PARAMETER EntraConnectServer
    The Entra Connect / sync server to test against.

.PARAMETER PtaServer
    Optional. A standalone Pass-through Authentication agent host, if PTA agents run
    somewhere other than the sync server. Microsoft recommends at least three agents, and
    they are commonly not on the sync box.

.PARAMETER OutputPath
    Optional. Folder to write a transcript of the findings to. Defaults to no file output.

.EXAMPLE
    .\Test-EntraConnectReadiness.ps1 -EntraConnectServer AADCONNECT01

.EXAMPLE
    .\Test-EntraConnectReadiness.ps1 -EntraConnectServer AADCONNECT01 -PtaServer PTA-AGENT-02
    Checks the sync server and a standalone PTA agent host.

.NOTES
    Read-only. Requires remote event-log read access, and remote CIM/WinRM for the service
    checks. Enumerating log channels (-ListLog) needs slightly more access than reading
    events; a WARN there is not fatal, because the collector falls back to the documented
    channel name.

    REFERENCES
      Password Hash Sync event table and the "Directory Synchronization" source:
        https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization
      PTA agent Admin log location:
        https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-pass-through-authentication
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EntraConnectServer,

    [string]$PtaServer,

    [string]$OutputPath
)

$script:Lines = [System.Collections.Generic.List[string]]::new()
$script:Fails = 0
$script:Warns = 0

function Write-Check {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
    $script:Lines.Add(("[{0}] {1}" -f $Level, $Message))
    if ($Level -eq 'FAIL') { $script:Fails++ }
    if ($Level -eq 'WARN') { $script:Warns++ }
}

function Test-SyncServer {
    param([string]$Server)

    Write-Host ''
    Write-Host "Sync server: $Server" -ForegroundColor White
    Write-Host ('-' * (13 + $Server.Length)) -ForegroundColor DarkGray

    # 1. Reachability. Everything else is meaningless if this fails.
    try {
        $null = Test-Connection -ComputerName $Server -Count 1 -ErrorAction Stop
        Write-Check PASS "$Server responds to ping."
    } catch {
        Write-Check WARN "$Server did not respond to ping. It may still be reachable if ICMP is blocked."
    }

    # 2. Services, via the same CIM call the collector uses.
    foreach ($svcName in @('ADSync','AzureADConnectAuthenticationAgent','AzureADConnectAgentUpdater')) {
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -ComputerName $Server `
                     -Filter "Name='$svcName'" -ErrorAction Stop
            if ($svc) {
                $lvl = if ($svc.State -eq 'Running') { 'PASS' } else { 'WARN' }
                Write-Check $lvl "Service $svcName is $($svc.State) (StartMode=$($svc.StartMode))."
            } else {
                if ($svcName -eq 'ADSync') {
                    Write-Check FAIL "Service ADSync is not installed on $Server. This is not an Entra Connect sync server."
                } else {
                    Write-Check INFO "Service $svcName is not installed on $Server (expected on a PHS-only server)."
                }
            }
        } catch {
            Write-Check FAIL "Could not query service $svcName on ${Server}: $($_.Exception.Message)"
        }
    }

    # 3. THE key assumption: is the PHS event provider registered, and under this name?
    #    If this fails, the collector reads no PHS events and the heartbeat check would
    #    have reported a stale heartbeat on a healthy server.
    $providerOk = $false
    try {
        $providers = @(Get-WinEvent -ComputerName $Server -ListProvider '*Directory*' -ErrorAction Stop |
                       Select-Object -ExpandProperty Name)
        if ($providers -contains 'Directory Synchronization') {
            Write-Check PASS "Event provider 'Directory Synchronization' is registered on $Server."
            $providerOk = $true
        } elseif ($providers.Count -gt 0) {
            Write-Check FAIL "Event provider 'Directory Synchronization' was NOT found on $Server. Similar providers present: $($providers -join ', '). The PHS event query will return nothing - update the provider name in Diagnose-ADAccountLockout.ps1."
        } else {
            Write-Check FAIL "No '*Directory*' event providers are registered on $Server. The PHS event query will return nothing."
        }
    } catch {
        Write-Check WARN "Could not enumerate event providers on ${Server}: $($_.Exception.Message). The collector will still attempt the query and report an error if the provider is missing."
    }

    # 4. Is password hash sync even ENABLED? Ask before judging its health - a PTA-only
    #    tenant has no heartbeat by design, and warning about it points at a healthy
    #    server. This is the difference between "PHS is broken" and "you don't use PHS".
    #    https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-adsync
    $phsEnabled = $null
    $staging    = $null
    try {
        $cfg = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
            Import-Module ADSync -ErrorAction Stop
            [PSCustomObject]@{
                Phs     = [bool](Get-ADSyncAADCompanyFeature -ErrorAction Stop).PasswordHashSync
                Staging = [bool](Get-ADSyncScheduler -ErrorAction Stop).StagingModeEnabled
            }
        }
        $phsEnabled = $cfg.Phs
        $staging    = $cfg.Staging
        if ($staging) {
            Write-Check WARN "This server is in STAGING MODE, which suppresses password hash sync. The active sync server is elsewhere."
        }
        if ($phsEnabled) {
            Write-Check PASS "Password hash sync is enabled on the tenant."
        } else {
            Write-Check INFO "Password hash sync is NOT enabled on this tenant (PasswordHashSync=False). No heartbeat is expected - sign-in validation happens via Pass-through Authentication or a federation provider."
        }
    } catch {
        Write-Check WARN "Could not read the sync configuration from ${Server}: $($_.Exception.Message). Heartbeat findings below are unhedged as a result."
    }

    # 5. Heartbeat health - only meaningful when PHS is actually in use.
    $phsInUse = ($null -eq $phsEnabled) -or ($phsEnabled -and -not $staging)
    if ($providerOk -and $phsInUse) {
        try {
            $hb = @(Get-WinEvent -ComputerName $Server -FilterHashtable @{
                        LogName      = 'Application'
                        ProviderName = 'Directory Synchronization'
                        Id           = 654
                        StartTime    = (Get-Date).AddHours(-3)
                    } -ErrorAction Stop)
            if ($hb.Count -gt 0) {
                $age = [math]::Round(((Get-Date) - $hb[0].TimeCreated).TotalMinutes, 0)
                Write-Check PASS "Password hash sync heartbeat (654) found, newest is $age minute(s) old. Expected roughly every 30 minutes."
            }
        } catch {
            if ($_.Exception.Message -match 'No events were found') {
                if ($null -eq $phsEnabled) {
                    Write-Check WARN "No password hash sync heartbeat (event 654) in the last three hours on $Server, and PHS enablement could not be confirmed. If this server does run PHS, that is a real finding - check staging mode and the connector account's replication rights."
                } else {
                    Write-Check WARN "Password hash sync is enabled but no heartbeat (event 654) was logged in the last three hours on $Server. Check the connector account's Replicate Directory Changes / Replicate Directory Changes All rights and DC reachability."
                }
            } else {
                Write-Check FAIL "Could not read PHS events from ${Server}: $($_.Exception.Message)"
            }
        }
    }

    Test-PtaChannel -Server $Server -Context 'sync server'
}

function Test-PtaChannel {
    param([string]$Server, [string]$Context)

    # THE other assumption: Microsoft documents this log only as an Event Viewer tree
    # path, never as a Get-WinEvent channel string. The collector discovers it; this
    # confirms what it will find, and reports the real name so it can be pinned if needed.
    $assumed = 'Microsoft-AzureADConnect-AuthenticationAgent/Admin'
    try {
        $logs = @(Get-WinEvent -ComputerName $Server -ListLog '*AuthenticationAgent*' -ErrorAction Stop |
                  Select-Object -ExpandProperty LogName)
        $admin = @($logs | Where-Object { $_ -like '*Admin*' })
        if ($admin.Count -eq 0) {
            Write-Check INFO "No PTA Authentication Agent log channel on $Server ($Context). Expected if no PTA agent is installed here."
        } elseif ($admin -contains $assumed) {
            Write-Check PASS "PTA Admin channel on $Server matches the assumed name: $assumed"
        } else {
            Write-Check WARN "PTA Admin channel on $Server is '$($admin[0])', NOT the assumed '$assumed'. The collector discovers this at runtime so it will still work, but consider updating the documented fallback."
        }
    } catch {
        if ($_.Exception.Message -match 'There is not an event log') {
            Write-Check INFO "No PTA Authentication Agent log channel on $Server ($Context). Expected if no PTA agent is installed here."
        } else {
            Write-Check WARN "Could not enumerate log channels on ${Server}: $($_.Exception.Message). The collector will fall back to the documented channel name."
        }
    }
}

Write-Host ''
Write-Host 'Entra Connect readiness check' -ForegroundColor White
Write-Host 'Read-only. Confirms the hybrid checks can read what they assume.' -ForegroundColor DarkGray

Test-SyncServer -Server $EntraConnectServer

if ($PtaServer) {
    Write-Host ''
    Write-Host "PTA agent host: $PtaServer" -ForegroundColor White
    Write-Host ('-' * (16 + $PtaServer.Length)) -ForegroundColor DarkGray
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -ComputerName $PtaServer `
                 -Filter "Name='AzureADConnectAuthenticationAgent'" -ErrorAction Stop
        if ($svc) {
            $lvl = if ($svc.State -eq 'Running') { 'PASS' } else { 'WARN' }
            Write-Check $lvl "PTA agent service on $PtaServer is $($svc.State)."
        } else {
            Write-Check FAIL "No PTA agent service on $PtaServer."
        }
    } catch {
        Write-Check FAIL "Could not query the PTA agent service on ${PtaServer}: $($_.Exception.Message)"
    }
    Test-PtaChannel -Server $PtaServer -Context 'standalone agent host'
}

Write-Host ''
if ($script:Fails -gt 0) {
    Write-Host "$($script:Fails) check(s) FAILED. The hybrid section may report misleading results until these are resolved." -ForegroundColor Red
} elseif ($script:Warns -gt 0) {
    Write-Host "No failures, $($script:Warns) warning(s). Review them, then the hybrid checks are safe to rely on." -ForegroundColor Yellow
} else {
    Write-Host 'All checks passed. The hybrid section can read everything it assumes.' -ForegroundColor Green
}

if ($OutputPath) {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -ItemType Directory -Path $OutputPath -Force
    }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $file = Join-Path $OutputPath "EntraConnectReadiness_$stamp.txt"
    $script:Lines | Set-Content -LiteralPath $file -Encoding UTF8
    Write-Host "Saved: $file" -ForegroundColor Cyan
}
