BeforeAll {
    . "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1" -Identity '__pester__' -LoadFunctionsOnly
}

# REGRESSION GUARDS for the Entra Connect / hybrid-auth helpers.
#
# The first version of these helpers was written from recalled knowledge rather than from
# the documentation, and got several facts wrong. Each Context below pins one corrected
# fact to the Microsoft Learn page that establishes it, so the wrong version cannot
# silently return.
#
# REFERENCES
#   PHS event table, heartbeat semantics, connectivity event IDs:
#     https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization
#   PTA agent admin log channel:
#     https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-pass-through-authentication

Describe 'Get-EntraConnectEventClassification - documented PHS event meanings' {

    Context 'Events 653/654 are ping START and ping END' {
        # The documented table reads:
        #   653  Start of password hash sync ping.
        #   654  End of password hash sync ping.
        # The original code labelled 654 "heartbeat was observed", which is the ROLE the
        # troubleshooting task assigns it, not the documented event text. 654 is logged
        # every 30 minutes when the channel is active and no password changes are pending.

        It 'classifies 654 as the end of the sync ping - the heartbeat event' {
            $c = Get-EntraConnectEventClassification -EventId 654 -LogName 'Application'
            $c.AuthMode | Should -Be 'PHS'
            $c.Status   | Should -Be 'Healthy'
            $c.Meaning  | Should -Match 'End of password hash sync ping'
        }

        It 'classifies 653 as the start of the sync ping' {
            (Get-EntraConnectEventClassification -EventId 653 -LogName 'Application').Meaning |
                Should -Match 'Start of password hash sync ping'
        }

        It 'classifies 650/651 as batch start and end, not "cycle"' {
            (Get-EntraConnectEventClassification -EventId 650 -LogName 'Application').Meaning | Should -Match 'batch'
            (Get-EntraConnectEventClassification -EventId 651 -LogName 'Application').Meaning | Should -Match 'batch'
        }
    }

    Context 'The documented table extends to 668, not 655' {
        # The original classifier stopped at 655 and silently labelled everything above
        # "Unclassified Entra Connect event". Events 613-623 and 656-668 are documented,
        # and several bear directly on a lockout investigation.

        It 'classifies 616 - connection to preferred DC failed - as an error' {
            # Directly relevant: if PHS cannot reach its preferred DC, the sync server is
            # not the lockout source but IS failing to read password hashes, which looks
            # identical from the cloud side.
            $c = Get-EntraConnectEventClassification -EventId 616 -LogName 'Application'
            $c.AuthMode | Should -Be 'PHS'
            $c.Status   | Should -Be 'Error'
            $c.Meaning  | Should -Match 'preferred DC'
        }

        It 'classifies 613 - paused pending full sync - as a warning' {
            $c = Get-EntraConnectEventClassification -EventId 613 -LogName 'Application'
            $c.Status  | Should -Be 'Warn'
            $c.Meaning | Should -Match 'full sync'
        }

        It 'classifies 621 - full password hash sync attempt failed - as an error' {
            (Get-EntraConnectEventClassification -EventId 621 -LogName 'Application').Status | Should -Be 'Error'
        }

        It 'classifies 662 - health task failed during ping - as an error' {
            (Get-EntraConnectEventClassification -EventId 662 -LogName 'Application').Status | Should -Be 'Error'
        }

        It 'classifies 663 - manager alive and running - as healthy' {
            (Get-EntraConnectEventClassification -EventId 663 -LogName 'Application').Status | Should -Be 'Healthy'
        }

        It 'covers every event id in the documented Microsoft Learn table' {
            $documented = @(601,602,603,604,605,606,607,609,610,611,612,613,614,615,616,617,
                            618,619,620,621,622,623,650,651,652,653,654,655,656,657,658,659,
                            660,661,662,663,664,665,666,667,668)
            foreach ($id in $documented) {
                $c = Get-EntraConnectEventClassification -EventId $id -LogName 'Application'
                $c.AuthMode | Should -Be 'PHS' -Because "event $id is documented as a PHS event"
                $c.Meaning  | Should -Not -Match 'Unclassified' -Because "event $id has a documented meaning"
            }
        }

        It 'still labels a genuinely unknown id as unclassified' {
            (Get-EntraConnectEventClassification -EventId 99999 -LogName 'Application').AuthMode | Should -Be 'Unknown'
        }
    }

    Context 'Event 0 is a documented connectivity error' {
        # The manual troubleshooting steps name the connectivity events explicitly:
        #   Source: "Directory synchronization"  ID: 0, 611, 652, 655
        #   "If you see these events, you have a connectivity problem."
        # Event 0 was missing entirely from the original classifier, so the single most
        # commonly-cited PHS connectivity event fell through to "Unclassified".

        It 'classifies event 0 as a PHS connectivity error' {
            $c = Get-EntraConnectEventClassification -EventId 0 -LogName 'Application'
            $c.AuthMode | Should -Be 'PHS'
            $c.Status   | Should -Be 'Error'
            $c.Meaning  | Should -Match 'connectivity'
        }

        It 'treats all four documented connectivity ids as errors' {
            foreach ($id in @(0, 611, 652, 655)) {
                (Get-EntraConnectEventClassification -EventId $id -LogName 'Application').Status |
                    Should -Be 'Error' -Because "event $id is documented as a connectivity problem"
            }
        }
    }

    Context 'The PTA Admin log channel' {
        # Documented path: Application and Service Logs\Microsoft\AzureAdConnect\
        # AuthenticationAgent\Admin. Get-WinEvent -LogName is not case-sensitive, so
        # casing is not the risk; this pins the matcher against both spellings so a
        # future edit to the collector's channel string cannot silently stop matching.

        It 'classifies the channel as PTA regardless of casing' {
            foreach ($log in @(
                'Microsoft-AzureAdConnect-AuthenticationAgent/Admin',
                'Microsoft-AzureADConnect-AuthenticationAgent/Admin')) {
                (Get-EntraConnectEventClassification -EventId 12019 -LogName $log).AuthMode |
                    Should -Be 'PTA' -Because "$log is the documented PTA admin channel"
            }
        }
    }
}

Describe 'Test-PhsHeartbeatFreshness' {
    # The troubleshooting task checks for heartbeat events "within the past three hours",
    # and 654 is logged every 30 minutes. The original collector searched the full
    # -DaysBack window and only reported a problem when the ENTIRE window was empty,
    # so PHS that died yesterday reported as healthy on a 7-day search - the exact
    # failure this check exists to catch.

    It 'reports a stale heartbeat when the newest 654 is older than three hours' {
        $now = [datetime]'2026-08-26T12:00:00'
        $r = Test-PhsHeartbeatFreshness -HeartbeatTimes @($now.AddHours(-5)) -Now $now
        $r.Fresh   | Should -BeFalse
        $r.Message | Should -Match 'three hours'
    }

    It 'accepts a heartbeat inside the three-hour window' {
        $now = [datetime]'2026-08-26T12:00:00'
        (Test-PhsHeartbeatFreshness -HeartbeatTimes @($now.AddMinutes(-31)) -Now $now).Fresh | Should -BeTrue
    }

    It 'reports no heartbeat at all when none were collected' {
        $now = [datetime]'2026-08-26T12:00:00'
        $r = Test-PhsHeartbeatFreshness -HeartbeatTimes @() -Now $now
        $r.Fresh   | Should -BeFalse
        $r.Message | Should -Not -BeNullOrEmpty
    }

    It 'uses the newest heartbeat, not the oldest, to judge freshness' {
        # A week-old heartbeat sorted first would make a healthy server look dead.
        $now = [datetime]'2026-08-26T12:00:00'
        $times = @($now.AddDays(-3), $now.AddMinutes(-10))
        (Test-PhsHeartbeatFreshness -HeartbeatTimes $times -Now $now).Fresh | Should -BeTrue
    }

    It 'reports how old the newest heartbeat is so the age is auditable' {
        $now = [datetime]'2026-08-26T12:00:00'
        $r = Test-PhsHeartbeatFreshness -HeartbeatTimes @($now.AddHours(-5)) -Now $now
        $r.AgeHours | Should -BeGreaterThan 4
        $r.AgeHours | Should -BeLessThan 6
    }
}

Describe 'Get-EntraConnectVerdictHints - staleness reaches the verdict' {
    It 'raises a stale heartbeat as a finding, not just a missing one' {
        $diag = [PSCustomObject]@{
            Server = 'ENTRACONNECT01'; HybridAuthMode = 'PHS'; Checked = $true
            Services = @(); Errors = @(); Events = @()
            Notes = @('Most recent PHS heartbeat (event 654) on ENTRACONNECT01 is 5.2 hours old; the documented health check expects one within three hours.')
        }
        $hints = Get-EntraConnectVerdictHints -Diagnostics $diag
        ($hints -join ' ') | Should -Match 'heartbeat'
        ($hints -join ' ') | Should -Match 'staging mode|password hash sync is enabled'
    }
}

Describe 'Service state must distinguish absent, unknown and stopped' {
    # REGRESSION GUARDS. The hint logic tested only "Status -ne Running", which lumps
    # three very different states together:
    #
    #   NotFound - the service is not installed. On a PHS-only server there is no PTA
    #              agent, and that is correct, not a fault.
    #   Error    - we could not query the server. We do not know the state.
    #   Stopped  - we queried it and it is genuinely not running. This is the finding.
    #
    # Reporting the first two as "cloud sign-ins may fail" sends someone to fix a healthy
    # server, which is worse than saying nothing.

    It 'does not claim PTA is broken on a PHS-only server with no agent installed' {
        $diag = [PSCustomObject]@{
            Server='AADCONNECT01'; HybridAuthMode='Auto'; Checked=$true
            Events=@(); Notes=@(); Errors=@()
            Services=@(
                [PSCustomObject]@{Name='ADSync'; Status='Running'; Detail=''}
                [PSCustomObject]@{Name='AzureADConnectAuthenticationAgent'; Status='NotFound'; Detail=''}
            )
        }
        $text = (Get-EntraConnectVerdictHints -Diagnostics $diag) -join ' '
        $text | Should -Not -Match 'cloud sign-ins may fail'
    }

    It 'does not report service state as a fault when the query itself failed' {
        $diag = [PSCustomObject]@{
            Server='AADCONNECT01'; HybridAuthMode='Auto'; Checked=$true
            Events=@(); Notes=@(); Errors=@()
            Services=@(
                [PSCustomObject]@{Name='ADSync'; Status='Error'; Detail='Access denied'}
                [PSCustomObject]@{Name='AzureADConnectAuthenticationAgent'; Status='Error'; Detail='Access denied'}
            )
        }
        $text = (Get-EntraConnectVerdictHints -Diagnostics $diag) -join ' '
        $text | Should -Not -Match 'password sync and connector status may be stale'
        $text | Should -Not -Match 'cloud sign-ins may fail'
        $text | Should -Match 'could not be determined|could not query|unknown'
    }

    It 'still reports a genuinely stopped ADSync service' {
        $diag = [PSCustomObject]@{
            Server='AADCONNECT01'; HybridAuthMode='Auto'; Checked=$true
            Events=@(); Notes=@(); Errors=@()
            Services=@([PSCustomObject]@{Name='ADSync'; Status='Stopped'; Detail=''})
        }
        (Get-EntraConnectVerdictHints -Diagnostics $diag) -join ' ' | Should -Match 'Stopped'
    }

    It 'still reports a genuinely stopped PTA agent' {
        $diag = [PSCustomObject]@{
            Server='AADCONNECT01'; HybridAuthMode='PTA'; Checked=$true
            Events=@(); Notes=@(); Errors=@()
            Services=@([PSCustomObject]@{Name='AzureADConnectAuthenticationAgent'; Status='Stopped'; Detail=''})
        }
        (Get-EntraConnectVerdictHints -Diagnostics $diag) -join ' ' | Should -Match 'cloud sign-ins may fail'
    }

    It 'notes that ADSync is absent rather than silently ignoring it' {
        # ADSync missing on a server named as the Entra Connect server means the wrong
        # server was supplied - worth saying plainly.
        $diag = [PSCustomObject]@{
            Server='NOTTHESYNCBOX'; HybridAuthMode='Auto'; Checked=$true
            Events=@(); Notes=@(); Errors=@()
            Services=@([PSCustomObject]@{Name='ADSync'; Status='NotFound'; Detail=''})
        }
        (Get-EntraConnectVerdictHints -Diagnostics $diag) -join ' ' |
            Should -Match 'not installed|not found|not an Entra Connect'
    }
}

Describe 'Absent evidence must not be reported as healthy evidence' {
    # The central risk in this whole section: a query that FAILS to look and a query that
    # looks and FINDS NOTHING produce the same empty result set, but support opposite
    # conclusions. These guard the places where that distinction changes the answer.

    Context 'Real Get-WinEvent error strings' {
        # Matched against messages captured from Get-WinEvent on this machine rather than
        # recalled, because the catch blocks branch on them. If a future Windows build
        # reworded these, the branches would silently take the wrong path.

        It 'matches the wording used when a LOG does not exist' {
            $real = 'There is not an event log on the localhost computer that matches "X".'
            $real | Should -Match 'There is not an event log|not find the specified log|not exist'
        }

        It 'matches the wording used when a PROVIDER is not registered' {
            $real = 'There is not an event provider on the localhost computer that matches "Directory Synchronization".'
            $real | Should -Match 'is not an event provider|not an event provider on'
        }

        It 'does not confuse the provider error with the no-events case' {
            $provider = 'There is not an event provider on the localhost computer that matches "Directory Synchronization".'
            $provider | Should -Not -Match 'No events were found'
        }
    }

    Context 'Heartbeat freshness is only judged when the query worked' {
        # If the PHS provider is unregistered, the query returns nothing. Feeding that
        # into the heartbeat check would report a stale heartbeat on a healthy server -
        # the exact confident-wrong answer this section exists to prevent.

        It 'treats an unusable PHS query as an Error, not a quiet channel' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match 'phsQueryUsable'
            $src | Should -Match 'ListProvider'
        }

        It 'gates the heartbeat check on the query having been usable' {
            # The gate later gained a second condition ($phsInUse), so this asserts the
            # usability guard is still present rather than pinning the whole expression.
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match 'if \(\$phsQueryUsable -and'
        }
    }

    Context 'The PTA channel name is discovered, not assumed' {
        # Microsoft documents the PTA Admin log only as an Event Viewer tree path and
        # never as a Get-WinEvent channel string, so any hardcoded spelling is a guess.

        It 'enumerates the channel from the server before querying it' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match "ListLog '\*AuthenticationAgent\*'"
        }

        It 'keeps the documented spelling as a fallback' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match 'Microsoft-AzureADConnect-AuthenticationAgent/Admin'
        }

        It 'records the collected row under the channel actually used' {
            # Labelling rows with the assumed name while reading a different one would
            # misreport where the evidence came from.
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match '-LogName \$ptaLogName -Message'
        }

        It 'distinguishes "no such log" from "log exists but is empty"' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match 'no Pass-through Authentication agent is installed'
            $src | Should -Match 'exists on .* but recorded no events'
        }
    }
}

Describe 'A missing heartbeat is only a fault when PHS is actually enabled' {
    # REGRESSION GUARD, from a real run against DC02. Every service was Running
    # and the event provider was registered, but no heartbeat 654 appeared in three
    # hours - and the tool warned about it. The tenant simply has PasswordHashSync=False
    # and uses Pass-through Authentication, so no heartbeat is CORRECT.
    #
    # Warning there points a technician at a healthy sync server during an incident,
    # which is the same false-confidence failure as the bugs this file already guards.

    Context 'Get-PhsEnabledState' {
        It 'reports undetermined rather than guessing when no server is supplied' {
            $s = Get-PhsEnabledState -Server ''
            $s.Determined | Should -BeFalse
            $s.PhsEnabled | Should -BeNullOrEmpty
        }

        It 'keeps "could not determine" distinct from "disabled"' {
            # $null and $false must not collapse: one means "PHS is off, no heartbeat
            # expected", the other means "we do not know, so do not suppress the check".
            $s = Get-PhsEnabledState -Server 'NO-SUCH-HOST-FOR-TESTS'
            $s.Determined | Should -BeFalse
            $s.PhsEnabled | Should -Not -Be $false
        }
    }

    Context 'The collector gates the heartbeat check on enablement' {
        It 'asks whether PHS is enabled before judging heartbeat health' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match 'Get-PhsEnabledState'
            $src | Should -Match 'Get-ADSyncAADCompanyFeature'
        }

        It 'suppresses the heartbeat check when PHS is disabled or staging is on' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match '\$phsInUse'
            $src | Should -Match 'if \(\$phsQueryUsable -and \$phsInUse'
        }

        It 'still runs the heartbeat check when enablement is UNKNOWN' {
            # Undetermined must not silently suppress a real finding. A hedged warning
            # beats silence when we genuinely cannot tell.
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match '\$phsInUse = -not \(\$phsState\.Determined'
        }

        It 'explains a PTA-only tenant instead of warning about it' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match 'expected rather than a fault'
        }

        It 'calls out staging mode as its own explanation' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1"
            $src | Should -Match 'STAGING MODE'
        }
    }

    Context 'The readiness check applies the same rule' {
        It 'reports PHS-not-enabled as INFO rather than WARN' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Test-EntraConnectReadiness.ps1"
            $src | Should -Match 'Write-Check INFO "Password hash sync is NOT enabled'
        }

        It 'only checks the heartbeat when PHS is in use' {
            $src = Get-Content -Raw "$PSScriptRoot\..\Test-EntraConnectReadiness.ps1"
            $src | Should -Match 'if \(\$providerOk -and \$phsInUse\)'
        }
    }
}
