BeforeAll {
    . "$PSScriptRoot\..\Get-LockoutCause.ps1" -LoadFunctionsOnly
}

Describe 'Get-LockoutCause' {

    # The classifier turns collected evidence into a RANKED list of likely causes, each
    # with the remediation Microsoft documents for it. Every cause it can emit is drawn
    # from the documented list in "Troubleshooting Account Lockout":
    # https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc773155(v=ws.10)

    Context 'logon type 5 - Windows service' {
        It 'names a service with a stale logon password as the top cause' {
            # "If you configure a service to start with a specific user account and that
            # account's password is changed, the service logon property must be updated
            # with the new password or that service may lock out the account."
            $r = Get-LockoutCause -LogonTypes @(5) -DeviceClass 'Server' -ProcessNames @() -EventIds @(4625)
            $r[0].Cause      | Should -Match 'Service'
            $r[0].Confidence | Should -Be 'High'
            $r[0].Remediation | Should -Match 'services\.msc|Log On tab|service account'
        }
    }

    Context 'logon type 4 - scheduled task' {
        It 'names a scheduled task with expired credentials' {
            # "Scheduled processes may be configured to using credentials that have expired."
            $r = Get-LockoutCause -LogonTypes @(4) -DeviceClass 'Server' -ProcessNames @() -EventIds @(4625)
            $r[0].Cause       | Should -Match 'Scheduled task'
            $r[0].Confidence  | Should -Be 'High'
            $r[0].Remediation | Should -Match 'schtasks|Task Scheduler'
        }
    }

    Context 'logon type 3 - network' {
        It 'suggests mapped drives and stored credentials' {
            # "Persistent drives may have been established with credentials that
            # subsequently expired."
            $r = Get-LockoutCause -LogonTypes @(3) -DeviceClass 'DomainJoinedWorkstation' -ProcessNames @() -EventIds @(4625)
            ($r.Cause -join '; ') | Should -Match 'drive|credential'
            $r[0].Remediation     | Should -Match 'net use|Credential Manager'
        }
    }

    Context 'logon type 10 - RDP' {
        It 'names a disconnected Terminal Server session' {
            # "Disconnected Terminal Server sessions may be running a process that
            # accesses network resources with outdated authentication information."
            $r = Get-LockoutCause -LogonTypes @(10) -DeviceClass 'Server' -ProcessNames @() -EventIds @(4625)
            $r[0].Cause       | Should -Match 'session'
            $r[0].Remediation | Should -Match 'quser|logoff|disconnected'
        }
    }

    Context 'logon type 2 and 7 - console and unlock' {
        It 'points at cached credentials after a password change' {
            $r = Get-LockoutCause -LogonTypes @(2, 7) -DeviceClass 'DomainJoinedWorkstation' -ProcessNames @() -EventIds @(4625)
            ($r.Cause -join '; ') | Should -Match 'cached|password change|lock.*unlock'
        }
    }

    Context 'process name evidence' {
        It 'identifies a browser or mail client as a stored-credential source' {
            $r = Get-LockoutCause -LogonTypes @(3) -DeviceClass 'DomainJoinedWorkstation' `
                                  -ProcessNames @('C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE') -EventIds @(4625)
            ($r.Cause -join '; ') | Should -Match 'Outlook|mail|application'
        }

        It 'flags lsass as uninformative rather than inventing a cause from it' {
            # lsass.exe is the authenticating process on the DC, not the offender. Reading
            # it as "the culprit application" would send the investigator to the wrong box.
            $r = Get-LockoutCause -LogonTypes @(3) -DeviceClass 'Server' `
                                  -ProcessNames @('C:\Windows\System32\lsass.exe') -EventIds @(4625)
            ($r.Cause -join '; ') | Should -Not -Match 'lsass'
        }
    }

    Context 'device class evidence' {
        It 'warns that a network device may be masking the true source' {
            $r = Get-LockoutCause -LogonTypes @(3) -DeviceClass 'NetworkDevice' -ProcessNames @() -EventIds @(4771) -MacVendor 'Fortinet'
            ($r.Cause -join '; ')       | Should -Match 'gateway|NAT|behind'
            ($r.Remediation -join '; ') | Should -Match 'Fortinet|firewall|VPN'
        }

        It 'suggests a mobile device or non-domain endpoint when nothing is domain-joined' {
            $r = Get-LockoutCause -LogonTypes @() -DeviceClass 'NonDomainDevice' -ProcessNames @() -EventIds @(4776)
            ($r.Cause -join '; ') | Should -Match 'mobile|personal|non-domain'
        }
    }

    Context 'event-type evidence' {
        It 'reads a 4776-only source as legacy NTLM authentication' {
            # 4776 with no 4625/4771 means NTLM only - typically an older client, a
            # mapped drive by IP, or an appliance.
            $r = Get-LockoutCause -LogonTypes @() -DeviceClass 'Unknown' -ProcessNames @() -EventIds @(4776)
            ($r.Cause -join '; ') | Should -Match 'NTLM'
        }
    }

    Context 'ranking and output shape' {
        It 'returns causes ranked with the highest confidence first' {
            $r = Get-LockoutCause -LogonTypes @(5, 3) -DeviceClass 'Server' -ProcessNames @() -EventIds @(4625)
            $r[0].Confidence | Should -Be 'High'
        }

        It 'always returns at least one actionable entry, even with no evidence' {
            # An empty result would leave the investigator with nothing. A generic next
            # step is more useful than silence.
            $r = Get-LockoutCause -LogonTypes @() -DeviceClass '' -ProcessNames @() -EventIds @()
            @($r).Count | Should -BeGreaterThan 0
            $r[0].Remediation | Should -Not -BeNullOrEmpty
        }

        It 'gives every cause a remediation and an evidence statement' {
            $r = Get-LockoutCause -LogonTypes @(3, 4, 5) -DeviceClass 'Server' -ProcessNames @() -EventIds @(4625)
            foreach ($c in $r) {
                $c.Cause       | Should -Not -BeNullOrEmpty
                $c.Remediation | Should -Not -BeNullOrEmpty
                $c.Evidence    | Should -Not -BeNullOrEmpty
                $c.Confidence  | Should -BeIn @('High', 'Medium', 'Low')
            }
        }

        It 'does not emit the same cause twice when several signals point at it' {
            $r = Get-LockoutCause -LogonTypes @(3, 3, 3) -DeviceClass 'DomainJoinedWorkstation' `
                                  -ProcessNames @('C:\Windows\System32\svchost.exe','C:\Windows\System32\svchost.exe') -EventIds @(4625, 4625)
            ($r.Cause | Select-Object -Unique).Count | Should -Be @($r).Count
        }
    }
}

Describe 'ConvertFrom-LogonTypeText' {
    # REGRESSION GUARD. The type 3 description contains the words "service account
    # connection". A substring search for 'Service' matched inside it, so a mapped-drive
    # source reported "Windows service running as this account with a stale password" as
    # its top cause at High confidence - sending the technician to services.msc for a
    # problem that lives in net use. Match on the LEADING type name only.

    It 'does not read type 5 (Service) out of the type 3 description' {
        $t = ConvertFrom-LogonTypeText -Text 'Network - mapped drive, file share, or service account connection'
        $t | Should -Be @(3)
        $t | Should -Not -Contain 5
    }

    It 'does not read type 2 (Interactive) out of RemoteInteractive' {
        $t = ConvertFrom-LogonTypeText -Text 'RemoteInteractive - RDP / Terminal Services'
        $t | Should -Be @(10)
        $t | Should -Not -Contain 2
    }

    It 'does not read type 3 (Network) out of NetworkCleartext' {
        $t = ConvertFrom-LogonTypeText -Text 'NetworkCleartext - credentials sent unhashed'
        $t | Should -Be @(8)
        $t | Should -Not -Contain 3
    }

    It 'recovers every type from a multi-entry list' {
        $t = ConvertFrom-LogonTypeText -Text 'Service - a Windows service running as this account; Batch - scheduled task'
        @($t | Sort-Object) | Should -Be @(4, 5)
    }

    It 'returns nothing for empty or unrecognized text rather than guessing' {
        @(ConvertFrom-LogonTypeText -Text '').Count           | Should -Be 0
        @(ConvertFrom-LogonTypeText -Text 'something').Count  | Should -Be 0
    }
}

Describe 'Test-LockoutThresholdTooLow' {
    # Microsoft: "Bad Password Threshold is set too low ... one of the most common
    # misconfiguration issues ... Microsoft recommends that you leave this value at its
    # default value of 10." A low threshold is itself a CAUSE of false lockouts, not
    # merely context.
    # https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc773155(v=ws.10)

    It 'flags a threshold below the recommended value' {
        $r = Test-LockoutThresholdTooLow -Threshold 3
        $r.IsTooLow | Should -BeTrue
        $r.Message  | Should -Match '10'
    }

    It 'accepts the Microsoft-recommended default' {
        (Test-LockoutThresholdTooLow -Threshold 10).IsTooLow | Should -BeFalse
    }

    It 'treats a threshold of 0 as lockout disabled, not as too low' {
        # 0 means the account never locks out - reporting it as "too low" is backwards.
        $r = Test-LockoutThresholdTooLow -Threshold 0
        $r.IsTooLow | Should -BeFalse
        $r.Message  | Should -Match 'disabled|never'
    }
}

Describe 'Format-AccountList' {
    # A source hitting many accounts is the SIGNAL, not a formatting nuisance - but
    # pasting forty usernames into one sentence makes the summary unreadable. Name a few,
    # then count the rest.

    It 'lists a single account plainly' {
        Format-AccountList -Accounts 'jdoe' | Should -Be 'jdoe'
    }

    It 'lists a handful in full' {
        Format-AccountList -Accounts 'alice, bob, carol' | Should -Be 'alice, bob, carol'
    }

    It 'truncates a long list and says how many more there are' {
        $many = (1..40 | ForEach-Object { "user$_" }) -join ', '
        $out  = Format-AccountList -Accounts $many
        $out | Should -Match 'user1'
        $out | Should -Match '\+\s*3[0-9] more'
        $out.Length | Should -BeLessThan 120
    }

    It 'handles an empty account list without inventing one' {
        Format-AccountList -Accounts '' | Should -Match 'unknown|no account'
    }
}

Describe 'Get-MultiAccountFinding' {
    # THE MULTI-USER CASE. One device hitting many accounts is a categorically different
    # problem from one device hitting one account, and it is the reading that most often
    # gets missed - each individual user looks like an isolated ticket.

    It 'flags a source hitting many accounts as a shared or rogue device' {
        $r = Get-MultiAccountFinding -DistinctAccounts 25 -DeviceClass 'Unknown' -SourceKey '10.0.0.99'
        $r          | Should -Not -BeNullOrEmpty
        $r.Cause    | Should -Match 'multiple accounts|many accounts|spray'
        $r.Confidence | Should -Be 'High'
    }

    It 'raises password spraying as a security concern, not just a lockout one' {
        $r = Get-MultiAccountFinding -DistinctAccounts 30 -DeviceClass 'Unknown' -SourceKey '10.0.0.99'
        $r.Remediation | Should -Match 'spray|security|malicious|compromise'
    }

    It 'reads a domain-joined server hitting many accounts as a shared service instead' {
        # A file server or terminal server legitimately authenticates for many users. The
        # same count means something different here, and calling it an attack wastes time.
        $r = Get-MultiAccountFinding -DistinctAccounts 25 -DeviceClass 'Server' -SourceKey 'FS01'
        $r.Cause       | Should -Match 'shared|service|server'
        $r.Remediation | Should -Not -Match 'spray'
    }

    It 'returns nothing for a single-account source' {
        Get-MultiAccountFinding -DistinctAccounts 1 -DeviceClass 'DomainJoinedWorkstation' -SourceKey 'WKS01' | Should -BeNullOrEmpty
    }

    It 'returns nothing for two accounts, which is ordinary shared-workstation noise' {
        Get-MultiAccountFinding -DistinctAccounts 2 -DeviceClass 'DomainJoinedWorkstation' -SourceKey 'WKS01' | Should -BeNullOrEmpty
    }
}

Describe 'Get-CauseSentence' {
    # The one-line answer a technician reads first. Everything else is supporting detail.

    It 'names the device, the account and the cause in one sentence' {
        $s = Get-CauseSentence -Account 'jdoe' -DeviceName 'LAPTOP-3' -SourceKey '10.0.0.50' `
                               -TopCause 'Mapped network drive using a stale password' -FailureCount 14
        $s | Should -Match 'jdoe'
        $s | Should -Match 'LAPTOP-3'
        $s | Should -Match 'Mapped network drive'
        $s | Should -Match '14'
    }

    It 'phrases a multi-account subject as a plural, not a possessive' {
        # "alice, bob, carol (+ 25 more)'s failed authentications" is unreadable.
        $s = Get-CauseSentence -Account 'alice, bob, carol (+ 25 more)' -DeviceName '' -SourceKey '10.0.0.99' `
                               -TopCause 'Possible password spray' -FailureCount 312
        $s | Should -Not -Match "more\)'s"
        $s | Should -Match '312 failed authentications for alice'
    }

    It 'falls back to the IP when no name could be resolved' {
        $s = Get-CauseSentence -Account 'jdoe' -DeviceName '' -SourceKey '10.0.0.99' `
                               -TopCause 'Legacy NTLM authentication' -FailureCount 3
        $s | Should -Match '10\.0\.0\.99'
    }

    It 'does not claim a device when the source was never recorded' {
        $s = Get-CauseSentence -Account 'jdoe' -DeviceName '' -SourceKey '(not recorded)' `
                               -TopCause 'Unknown' -FailureCount 2
        $s | Should -Match 'not recorded|unidentified|no source'
    }
}


Describe 'ConvertTo-HtmlSafe' {
    # Account names, device names and inventory fields are attacker-influenced or at least
    # user-supplied. A machine named <script> must not become script.
    It 'escapes HTML metacharacters' {
        ConvertTo-HtmlSafe -Text '<script>alert(1)</script>' | Should -Not -Match '<script>'
        ConvertTo-HtmlSafe -Text 'a & b'                     | Should -Be 'a &amp; b'
        ConvertTo-HtmlSafe -Text '"quoted"'                  | Should -Match '&quot;'
    }

    It 'returns empty string for null rather than the literal word null' {
        ConvertTo-HtmlSafe -Text $null | Should -Be ''
    }
}

Describe 'New-CaseReportHtml' {
    BeforeAll {
        $script:Rows = @(
            [PSCustomObject]@{ SourceKey='10.0.0.50'; ResolvedName='SQLSRV02'; DeviceClass='Server'
                               FailureCount='47'; DistinctAccounts='1'; Accounts='svc_backup'
                               Cause='Windows service running as this account with a stale password'
                               Confidence='High'; Evidence='Logon type 5 (Service)'
                               Remediation='Open services.msc and update the password.' }
            [PSCustomObject]@{ SourceKey='10.0.0.99'; ResolvedName=''; DeviceClass='Unknown'
                               FailureCount='312'; DistinctAccounts='28'; Accounts='alice, bob, carol'
                               Cause='One device failing against multiple accounts (28) - possible password spray'
                               Confidence='High'; Evidence='28 distinct accounts'
                               Remediation='Treat as a security concern; identify the device.' }
        )
    }

    It 'leads with the top finding as the verdict' {
        $html = New-CaseReportHtml -CauseRows $script:Rows -GeneratedOn '2026-08-20 14:30:00' -Window 7
        $html | Should -Match 'class="verdict'
        $html | Should -Match 'SQLSRV02'
    }

    It 'renders every source and its remediation' {
        $html = New-CaseReportHtml -CauseRows $script:Rows -GeneratedOn '2026-08-20 14:30:00' -Window 7
        $html | Should -Match 'services\.msc'
        $html | Should -Match '10\.0\.0\.99'
        $html | Should -Match 'password spray'
    }

    It 'escapes hostile text rather than emitting it as markup' {
        $evil = @([PSCustomObject]@{ SourceKey='<img src=x onerror=alert(1)>'; ResolvedName=''; DeviceClass='Unknown'
                                     FailureCount='1'; DistinctAccounts='1'; Accounts='x'
                                     Cause='c'; Confidence='Low'; Evidence='e'; Remediation='r' })
        $html = New-CaseReportHtml -CauseRows $evil -GeneratedOn 'now' -Window 7
        $html | Should -Not -Match '<img src=x'
        $html | Should -Match '&lt;img'
    }

    It 'produces a valid standalone page even with no findings' {
        $html = New-CaseReportHtml -CauseRows @() -GeneratedOn 'now' -Window 7
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match '</html>'
        $html | Should -Match 'No sources'
    }

    It 'is self-contained with no external references' {
        # Reports get attached to tickets and opened offline. A CDN link would render
        # the page unstyled on a machine with no internet.
        $html = New-CaseReportHtml -CauseRows $script:Rows -GeneratedOn 'now' -Window 7
        $html | Should -Not -Match 'https?://[^"]*\.(css|js)'
        $html | Should -Match '<style>'
    }
}
