<#
    Tests for Get-ADUserQuickCheck.ps1 (Pester 5, Windows PowerShell 5.1).

    The ActiveDirectory module is replaced by Tests\FakeAD, whose behaviour is steered by the
    UQC_OVERRIDE / UQC_DOWN environment variables (see the .psm1 header), so the real
    collection code runs against realistic object shapes: three DCs whose non-replicated
    attributes disagree, a PDC emulator, two people called "Pat Smith", and so on.

    The expectations come from Microsoft Learn, cited in the script's .NOTES REFERENCES:
    accountExpires 0 / 0x7FFFFFFFFFFFFFFF = never; pwdLastSet 0 = must change at next logon;
    lockoutTime can be non-zero while the account is NOT locked (duration expired), so the
    computed UF_LOCKOUT bit is the authority; lastLogon is per-DC.

    Run:  Invoke-Pester .\AD-UserQuickCheck\Tests
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Get-ADUserQuickCheck.ps1'
    $script:FakeRoot = Join-Path $PSScriptRoot 'FakeAD'
    Import-Module (Join-Path $script:FakeRoot 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global
    . $script:ScriptPath -LoadFunctionsOnly

    function Set-Scenario {
        param([hashtable]$Override = @{}, [string]$Down = '')
        $env:UQC_OVERRIDE = $(if ($Override.Count -gt 0) { ConvertTo-Json -InputObject $Override -Depth 6 -Compress } else { '' })
        $env:UQC_DOWN = $Down
    }
    function Get-FileTimeAt([double]$Days) { (Get-Date).AddDays($Days).ToFileTime() }
    function Get-Reason($Result, [string]$Code) {
        @($Result.Assessment.Reasons | Where-Object { $_.Code -eq $Code })[0]
    }
    function Get-ConsoleText($Result) {
        $records = @(Write-QuickCheckConsole -Result $Result 6>&1)
        (@($records | ForEach-Object { $_.ToString() })) -join "`n"
    }
}

AfterAll {
    Remove-Item Env:\UQC_OVERRIDE, Env:\UQC_DOWN -ErrorAction SilentlyContinue
}

Describe 'interpretation helpers' {

    It 'treats accountExpires 0 as never' {
        (Get-AccountExpiryState -AccountExpires 0).Never | Should -BeTrue
    }
    It 'treats accountExpires 0x7FFFFFFFFFFFFFFF as never (and does not throw)' {
        $s = Get-AccountExpiryState -AccountExpires ([int64]::MaxValue)
        $s.Never | Should -BeTrue
        $s.Expired | Should -BeFalse
        $s.Expires | Should -BeNullOrEmpty
    }
    It 'reads a real accountExpires date as expired or not' {
        (Get-AccountExpiryState -AccountExpires (Get-FileTimeAt -3)).Expired | Should -BeTrue
        (Get-AccountExpiryState -AccountExpires (Get-FileTimeAt 3)).Expired | Should -BeFalse
    }
    It 'ConvertFrom-AdFileTime returns $null for 0, MaxValue and $null' {
        ConvertFrom-AdFileTime -Value 0 | Should -BeNullOrEmpty
        ConvertFrom-AdFileTime -Value ([int64]::MaxValue) | Should -BeNullOrEmpty
        ConvertFrom-AdFileTime -Value $null | Should -BeNullOrEmpty
    }
    It 'pwdLastSet 0 means must change, unless the password is set never to expire' {
        (Get-PasswordState -PwdLastSet 0 -ExpiryComputed 0 -UserAccountControl 512 -ExpiredBit $false).MustChange | Should -BeTrue
        (Get-PasswordState -PwdLastSet 0 -ExpiryComputed ([int64]::MaxValue) -UserAccountControl (512 + 0x10000) -ExpiredBit $false).MustChange | Should -BeFalse
    }
    It 'msDS-UserPasswordExpiryTimeComputed MaxValue means the password never expires' {
        $p = Get-PasswordState -PwdLastSet (Get-FileTimeAt -10) -ExpiryComputed ([int64]::MaxValue) -UserAccountControl 512 -ExpiredBit $false
        $p.NeverExpires | Should -BeTrue
        $p.Expiry | Should -BeNullOrEmpty
    }
    It 'detects sign-in hours restrictions only when some hour is blocked' {
        Test-LogonHoursRestricted -LogonHours $null | Should -BeFalse
        Test-LogonHoursRestricted -LogonHours ([byte[]](, 255 * 21)) | Should -BeFalse
        $partial = [byte[]](, 255 * 21); $partial[5] = 0
        Test-LogonHoursRestricted -LogonHours $partial | Should -BeTrue
    }
    It 'escapes LDAP filter characters' {
        ConvertTo-LdapFilterValue 'a*(b)\c' | Should -Be 'a\2a\28b\29\5cc'
    }
}

Describe 'verdict' {
    BeforeEach { Set-Scenario }
    AfterAll { Set-Scenario }

    It 'a healthy account: YES, exit 0, and the headline names the person' {
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Status | Should -Be 'Ok'
        $r.Assessment.Verdict | Should -Be 'YES'
        $r.ExitCode | Should -Be 0
        (Get-ConsoleText $r) | Should -Match 'Can Jane Doe sign in right now\?\s+YES'
    }

    It 'disabled -> NO, exit 1' {
        Set-Scenario @{ jdoe = @{ userAccountControl = 514 } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Assessment.Verdict | Should -Be 'NO'
        $r.ExitCode | Should -Be 1
        (Get-Reason $r 'Disabled').Level | Should -Be 'Blocker'
        (Get-Reason $r 'Disabled').Action | Should -Not -BeNullOrEmpty
    }

    It 'locked (computed bit set) -> NO and says when it unlocks' {
        $r = Invoke-UserQuickCheck -Identity 'locked'
        $r.Assessment.Verdict | Should -Be 'NO'
        $r.Facts.LockedOut | Should -BeTrue
        # 30 minute domain lockout duration from the fake policy
        $r.Facts.UnlockTime | Should -Be ($r.Facts.LockoutTime + (New-TimeSpan -Minutes 30))
        (Get-Reason $r 'LockedOut').Message | Should -Match 'unlock by itself at'
    }

    It 'locked with a lockout duration of 0 -> says it will NOT unlock by itself' {
        Mock Get-ADUserResultantPasswordPolicy { [PSCustomObject]@{ Name = 'Admins'; LockoutThreshold = 3; LockoutDuration = [TimeSpan]::Zero } }
        $r = Invoke-UserQuickCheck -Identity 'locked'
        $r.Facts.UnlockTime | Should -BeNullOrEmpty
        $r.Facts.LockoutThreshold | Should -Be 3
        $r.Facts.PolicySource | Should -Match 'Admins'
        (Get-Reason $r 'LockedOut').Message | Should -Match 'NOT unlock by itself'
    }

    It 'lockoutTime set but computed bit clear (lockout expired) -> NOT locked' {
        Set-Scenario @{ jdoe = @{ lockoutTime = (Get-FileTimeAt -1) } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.LockoutTime | Should -Not -BeNullOrEmpty
        $r.Facts.LockedOut | Should -BeFalse
        $r.Assessment.Verdict | Should -Be 'YES'
        (Get-Reason $r 'LockedOut') | Should -BeNullOrEmpty
    }

    It 'accountExpires 0 -> never expires' {
        Set-Scenario @{ jdoe = @{ accountExpires = 0 } }
        (Invoke-UserQuickCheck -Identity 'jdoe').Facts.AccountExpiry.Never | Should -BeTrue
    }
    It 'accountExpires 9223372036854775807 -> never expires, still YES' {
        Set-Scenario @{ jdoe = @{ accountExpires = [int64]::MaxValue } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.AccountExpiry.Never | Should -BeTrue
        $r.Assessment.Verdict | Should -Be 'YES'
    }
    It 'account already expired -> NO' {
        Set-Scenario @{ jdoe = @{ accountExpires = (Get-FileTimeAt -2) } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Assessment.Verdict | Should -Be 'NO'
        (Get-Reason $r 'AccountExpired') | Should -Not -BeNullOrEmpty
    }
    It 'account expiring in 3 days -> warning only' {
        Set-Scenario @{ jdoe = @{ accountExpires = (Get-FileTimeAt 3) } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Assessment.Verdict | Should -Be 'YES'
        (Get-Reason $r 'AccountExpiresSoon').Level | Should -Be 'Warning'
    }

    It 'pwdLastSet 0 -> must change at next sign-in -> NO, in those words' {
        Set-Scenario @{ jdoe = @{ pwdLastSet = 0; 'msDS-UserPasswordExpiryTimeComputed' = 0 } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.Password.MustChange | Should -BeTrue
        $r.Assessment.Verdict | Should -Be 'NO'
        (Get-Reason $r 'MustChangePassword').Message | Should -Be 'They must set a new password at next sign-in.'
        (Get-Reason $r 'MustChangePassword').Action | Should -Match 'Outlook or VPN'
        (Get-Reason $r 'PasswordExpired') | Should -BeNullOrEmpty
    }
    It 'password expired (computed bit) -> NO' {
        Set-Scenario @{ jdoe = @{ 'msDS-User-Account-Control-Computed' = 0x800000; 'msDS-UserPasswordExpiryTimeComputed' = (Get-FileTimeAt -2) } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Assessment.Verdict | Should -Be 'NO'
        (Get-Reason $r 'PasswordExpired').Level | Should -Be 'Blocker'
    }
    It 'password expiring in 5 days -> WARN, still YES, with days remaining' {
        Set-Scenario @{ jdoe = @{ 'msDS-UserPasswordExpiryTimeComputed' = (Get-FileTimeAt 5.5) } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Assessment.Verdict | Should -Be 'YES'
        $r.Facts.Password.DaysLeft | Should -Be 5
        (Get-Reason $r 'PasswordExpiresSoon').Level | Should -Be 'Warning'
        (Get-ConsoleText $r) | Should -Match '\[WARN\] Their password expires'
    }
    It 'password expiring in 40 days -> no warning' {
        Set-Scenario @{ jdoe = @{ 'msDS-UserPasswordExpiryTimeComputed' = (Get-FileTimeAt 40) } }
        (Get-Reason (Invoke-UserQuickCheck -Identity 'jdoe') 'PasswordExpiresSoon') | Should -BeNullOrEmpty
    }
    It 'password that never expires (sentinel) -> no warning' {
        Set-Scenario @{ jdoe = @{ userAccountControl = (512 + 0x10000); 'msDS-UserPasswordExpiryTimeComputed' = [int64]::MaxValue } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.Password.NeverExpires | Should -BeTrue
        $r.Assessment.Verdict | Should -Be 'YES'
    }

    It 'userWorkstations set -> PROBABLY NOT and lists the computers' {
        $r = Invoke-UserQuickCheck -Identity 'wsuser'
        $r.Assessment.Verdict | Should -Be 'PROBABLY NOT'
        $r.ExitCode | Should -Be 1
        (Get-Reason $r 'WorkstationRestriction').Message | Should -Match 'PC-001, PC-002'
    }
    It 'sign-in hours restriction -> PROBABLY NOT' {
        $hours = @(1..21 | ForEach-Object { 255 }); $hours[4] = 0
        Set-Scenario @{ jdoe = @{ logonHours = $hours } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Assessment.Verdict | Should -Be 'PROBABLY NOT'
        (Get-Reason $r 'LogonHours').Message | Should -Match 'sign-in hours restrictions'
    }
    It 'smart card required -> PROBABLY NOT' {
        Set-Scenario @{ jdoe = @{ userAccountControl = (512 + 0x40000) } }
        (Invoke-UserQuickCheck -Identity 'jdoe').Assessment.Verdict | Should -Be 'PROBABLY NOT'
    }
    It 'a blocker outranks a restriction: disabled + workstation list -> NO' {
        Set-Scenario @{ wsuser = @{ userAccountControl = 514 } }
        (Invoke-UserQuickCheck -Identity 'wsuser').Assessment.Verdict | Should -Be 'NO'
    }
}

Describe 'per-DC data' {
    BeforeEach { Set-Scenario }
    AfterAll { Set-Scenario }

    It 'picks the newest lastLogon across DCs and names the DC' {
        # fake: DC01 5 days ago, DC02 12 hours ago, DC03 9 days ago
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.LastLogonDC | Should -Be 'DC02.contoso.com'
        ((Get-Date) - $r.Facts.LastLogon).TotalHours | Should -BeLessThan 13
        (Get-QuickCheckDetail -Facts $r.Facts | Where-Object { $_.Item -eq 'Last sign-in (newest)' }).Value | Should -Match 'via DC02'
    }
    It 'reports bad password counts per DC and the highest against the threshold' {
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        (@($r.Facts.DcResults | Where-Object { $_.DC -like 'DC03*' })[0]).BadPwdCount | Should -Be 3
        $msg = (Get-Reason $r 'BadPasswords').Message
        $msg | Should -Match 'DC03\.contoso\.com \(3\)'
        $msg | Should -Match 'highest is 3 of 5'
        # 3 of 5 leaves two more tries: close enough to be worth a WARN
        (Get-Reason $r 'BadPasswords').Level | Should -Be 'Warning'
    }
    It 'a low wrong-password count is information only' {
        Set-Scenario @{ 'jdoe@DC03' = @{ badPwdCount = 1 } }
        (Get-Reason (Invoke-UserQuickCheck -Identity 'jdoe') 'BadPasswords').Level | Should -Be 'Info'
    }
    It 'warns when one more wrong password would lock the account' {
        Set-Scenario @{ 'jdoe@DC03' = @{ badPwdCount = 4 } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        (Get-Reason $r 'BadPasswords').Level | Should -Be 'Warning'
        $r.Assessment.Verdict | Should -Be 'YES'
    }

    It 'one unreachable DC -> WARN naming it, never silently clean' {
        Set-Scenario -Down 'DC03'
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.UnreachableDCs | Should -Contain 'DC03.contoso.com'
        $r.Facts.DcsChecked | Should -Be 2
        $w = Get-Reason $r 'DcUnreachable'
        $w.Level | Should -Be 'Warning'
        $w.Message | Should -Be "Couldn't check DC03.contoso.com - last-logon and bad-password counts may be incomplete."
        (Get-ConsoleText $r) | Should -Match "\[WARN\] Couldn't check DC03"
        (Get-ConsoleText $r) | Should -Match 'COULD NOT CHECK'
        (Get-QuickCheckCsvRow -Result $r).DcsUnreachable | Should -Be 'DC03.contoso.com'
    }
    It 'an unreachable DC cannot supply the last logon' {
        Set-Scenario -Down 'DC02'
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.LastLogonDC | Should -Be 'DC01.contoso.com'
        (Get-Reason $r 'DcUnreachable').Message | Should -Match 'DC02'
    }
    It 'unreachable PDC emulator -> lockout read elsewhere, with a WARN' {
        Set-Scenario -Down 'DC01'
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Status | Should -Be 'Ok'
        $r.Facts.ReadFrom | Should -Not -Be 'DC01.contoso.com'
        (Get-Reason $r 'PdcFallback').Message | Should -Match 'PDC emulator'
    }
    It 'every DC unreachable -> exit 3, not a clean result' {
        Set-Scenario -Down 'DC01,DC02,DC03'
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.ExitCode | Should -Be 3
        $r.Status | Should -Be 'Error'
    }
    It '-DomainController limits which DCs are checked' {
        $r = Invoke-UserQuickCheck -Identity 'jdoe' -DomainController 'DC01.contoso.com', 'DC03.contoso.com'
        $r.Facts.DcsTotal | Should -Be 2
        $r.Facts.LastLogonDC | Should -Be 'DC01.contoso.com'
    }
}

Describe 'groups' {
    BeforeEach { Set-Scenario }
    AfterAll { Set-Scenario }

    It 'counts direct (memberOf + primary group) and effective (tokenGroups)' {
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $r.Facts.DirectGroupCount | Should -Be 3
        $r.Facts.EffectiveGroupCount | Should -Be 25
        (Get-Reason $r 'ManyGroups') | Should -BeNullOrEmpty
    }
    It 'warns (never blocks) when the total group count risks Kerberos token bloat' {
        Set-Scenario @{ jdoe = @{ tokenGroups = @(1..130 | ForEach-Object { "S-1-5-21-1-2-3-$_" }) } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        (Get-Reason $r 'ManyGroups').Level | Should -Be 'Warning'
        $r.Assessment.Verdict | Should -Be 'YES'
    }
}

Describe 'finding the user' {
    BeforeEach { Set-Scenario }
    AfterAll { Set-Scenario }

    It 'accepts sAMAccountName, UPN, DN and DOMAIN\name' {
        foreach ($id in 'jdoe', 'jdoe@contoso.com', 'CN=Jane Doe,OU=Staff,DC=contoso,DC=com', 'CONTOSO\jdoe') {
            (Invoke-UserQuickCheck -Identity $id).Facts.SamAccountName | Should -Be 'jdoe'
        }
    }
    It 'a name matching two people -> exit 2 with both candidates, no guessing' {
        $r = Invoke-UserQuickCheck -Identity 'Pat Smith'
        $r.Status | Should -Be 'Ambiguous'
        $r.ExitCode | Should -Be 2
        @($r.Candidates).Count | Should -Be 2
        $r.Facts | Should -BeNullOrEmpty
        $text = Get-ConsoleText $r
        $text | Should -Match 'psmith2'
        $text | Should -Not -Match 'sign in right now'
    }
    It 'an exact sign-in name wins over a similar one (psmith is not ambiguous with psmith2)' {
        (Invoke-UserQuickCheck -Identity 'psmith').Status | Should -Be 'Ok'
    }
    It 'a name matching nobody -> exit 2' {
        $r = Invoke-UserQuickCheck -Identity 'nobody-here'
        $r.Status | Should -Be 'NotFound'
        $r.ExitCode | Should -Be 2
    }
    It 'a display-name search with exactly one hit is accepted' {
        $r = Invoke-UserQuickCheck -Identity 'Jane Doe'
        $r.Status | Should -Be 'Ok'
        $r.MatchedBy | Should -Be 'name search'
    }
}

Describe 'report files' {
    BeforeEach { Set-Scenario }
    AfterAll { Set-Scenario }

    It 'writes HTML and a one-row CSV named UserQuickCheck_<sam>_<timestamp>' {
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $files = Export-QuickCheckReport -Result $r -OutputPath (Join-Path $TestDrive 'out')
        (Split-Path $files.Html -Leaf) | Should -Match '^UserQuickCheck_jdoe_\d{4}-\d{2}-\d{2}_\d{6}\.html$'
        (Split-Path $files.Csv -Leaf) | Should -Match '^UserQuickCheck_jdoe_\d{4}-\d{2}-\d{2}_\d{6}\.csv$'
        $rows = @(Import-Csv -LiteralPath $files.Csv)
        $rows.Count | Should -Be 1
        $rows[0].Verdict | Should -Be 'YES'
        $rows[0].SamAccountName | Should -Be 'jdoe'
    }
    It 'HTML-encodes directory values' {
        Set-Scenario @{ jdoe = @{ DisplayName = '<script>alert(1)</script>' } }
        $r = Invoke-UserQuickCheck -Identity 'jdoe'
        $html = ConvertTo-QuickCheckHtml -Result $r
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;'
    }
}

Describe 'the script end to end (child process, fake ActiveDirectory module)' {
    BeforeAll {
        $script:Exe = (Get-Process -Id $PID).Path
        function Invoke-Script {
            param([string]$ScriptArgs, [string]$ModulePath)
            $cmd = "`$env:PSModulePath = '$ModulePath;' + `$env:PSModulePath; & '$($script:ScriptPath)' $ScriptArgs; exit `$LASTEXITCODE"
            $out = & $script:Exe -NoProfile -NonInteractive -Command $cmd 2>&1
            [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Text = (@($out | ForEach-Object { "$_" }) -join "`n") }
        }
    }
    BeforeEach { Set-Scenario }
    AfterAll { Set-Scenario }

    It 'exit 0 and the answer comes first' {
        $x = Invoke-Script -ScriptArgs '-Identity jdoe' -ModulePath $script:FakeRoot
        $x.ExitCode | Should -Be 0
        @($x.Text -split "`n" | Where-Object { $_.Trim() })[0] | Should -Match '^Can Jane Doe sign in right now\?\s+YES'
    }
    It 'exit 1 when the account is locked' {
        $x = Invoke-Script -ScriptArgs '-Identity locked' -ModulePath $script:FakeRoot
        $x.ExitCode | Should -Be 1
        $x.Text | Should -Match 'NO'
        $x.Text | Should -Match 'What to do:'
    }
    It 'exit 2 for an ambiguous name' {
        (Invoke-Script -ScriptArgs "-Identity 'Pat Smith'" -ModulePath $script:FakeRoot).ExitCode | Should -Be 2
    }
    It 'exit 3 when the ActiveDirectory module is missing' {
        $empty = Join-Path $TestDrive 'nomodules'
        $null = New-Item -ItemType Directory -Path $empty -Force
        $x = Invoke-Script -ScriptArgs '-Identity jdoe' -ModulePath $empty
        # Only meaningful on machines without RSAT, where the module cannot be found anywhere.
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory | Where-Object { $_.Path -notlike "$($script:FakeRoot)*" })) {
            $x.ExitCode | Should -Be 3
        } else {
            Set-ItResult -Skipped -Because 'real ActiveDirectory module installed on this machine'
        }
    }
    It 'writes the HTML and CSV when -OutputPath is given, and only then' {
        $dir = Join-Path $TestDrive 'e2e-out'
        $null = Invoke-Script -ScriptArgs "-Identity jdoe -OutputPath '$dir'" -ModulePath $script:FakeRoot
        @(Get-ChildItem -LiteralPath $dir -Filter 'UserQuickCheck_jdoe_*.html').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $dir -Filter 'UserQuickCheck_jdoe_*.csv').Count | Should -Be 1
    }
    It 'warns about an unreachable DC on the console' {
        Set-Scenario -Down 'DC03'
        $x = Invoke-Script -ScriptArgs '-Identity jdoe' -ModulePath $script:FakeRoot
        $x.ExitCode | Should -Be 0
        $x.Text | Should -Match "\[WARN\] Couldn't check DC03"
    }
}

# =============================================================================
# SQ-001 Part A: the ticket note (AC18-AC25)
#
# The script is expected to dot-source its own CaseKit.ps1 (copy of TicketNote\CaseKit.ps1)
# and to expose the adapter ConvertTo-UserQuickCheckTicketNote -Result -EvidencePaths
# [-Credential], which maps the result to kit items (the gate decisions live there).
# The clipboard is never touched for real: Set-Clipboard is mocked, or -NoClipboard is used.
# =============================================================================

Describe 'ticket note' {
    BeforeAll {
        # The lines of one note section: after its header, up to the next header or blank line.
        function Get-NoteSection([string[]]$Lines, [string]$Header) {
            $headers = 'Checked:', 'Ruled out:', 'Could not check:', 'Next step:'
            $at = [array]::IndexOf($Lines, $Header)
            if ($at -lt 0) { return @() }
            $out = @()
            for ($i = $at + 1; $i -lt $Lines.Count; $i++) {
                if ($headers -contains $Lines[$i] -or -not $Lines[$i].Trim()) { break }
                $out += $Lines[$i]
            }
            , $out
        }
        function Get-NoteLines([string]$Identity, [string[]]$Evidence = @(), $Credential = $null) {
            $r = Invoke-UserQuickCheck -Identity $Identity
            $splat = @{ Result = $r; EvidencePaths = $Evidence }
            if ($Credential) { $splat['Credential'] = $Credential }
            $note = ConvertTo-UserQuickCheckTicketNote @splat
            [PSCustomObject]@{ Result = $r; Note = $note; Lines = @(ConvertTo-TicketNoteText -Note $note) }
        }
        # Runs the real script in-process (exit only leaves the script) with the fake AD module first.
        function Invoke-ScriptInProcess([hashtable]$Splat) {
            $saved = $env:PSModulePath
            try {
                $env:PSModulePath = "$($script:FakeRoot);$saved"
                $global:LASTEXITCODE = 0
                @(& $script:ScriptPath @Splat *>&1)
            } finally { $env:PSModulePath = $saved }
        }
        $script:ExeNote = (Get-Process -Id $PID).Path
    }
    BeforeEach { Set-Scenario }
    AfterAll { Set-Scenario }

    It 'AC18_UserCheckNoteFindings: expired password -> scope + PROBLEM under Checked, Ruled out, Next step' {
        Set-Scenario @{ jdoe = @{ 'msDS-User-Account-Control-Computed' = 0x800000; 'msDS-UserPasswordExpiryTimeComputed' = (Get-FileTimeAt -2) } }
        $n = Get-NoteLines 'jdoe'
        $checked = Get-NoteSection $n.Lines 'Checked:'
        $checked[0] | Should -Be '- AD account jdoe in contoso.com, on 3 of 3 domain controllers.'
        @($checked | Where-Object { $_ -like '- PROBLEM: Their password expired*' }).Count | Should -Be 1
        $ruled = Get-NoteSection $n.Lines 'Ruled out:'
        $ruled | Should -Contain '- Account is turned on.'
        $next = Get-NoteSection $n.Lines 'Next step:'
        @($next | Where-Object { $_ -like '*Reset their password (Set-ADAccountPassword)*' }).Count | Should -Be 1
    }

    It 'AC19_UserCheckUnreachableDc: a down DC is Could not check, and wrong-password is not Ruled out' {
        Set-Scenario -Down 'DC03'
        $n = Get-NoteLines 'jdoe'
        $could = Get-NoteSection $n.Lines 'Could not check:'
        @($could | Where-Object { $_ -match 'DC03\.contoso\.com' -and $_ -match 'wrong-password' -and $_ -match 'last sign-in' }).Count | Should -BeGreaterThan 0
        $ruled = Get-NoteSection $n.Lines 'Ruled out:'
        @($ruled | Where-Object { $_ -match 'No recent wrong-password attempts' }).Count | Should -Be 0
    }

    It 'AC20_UserCheckPdcFallback: PDC unreadable -> Not locked out is not Ruled out; says status may be out of date' {
        Set-Scenario -Down 'DC01'
        $n = Get-NoteLines 'jdoe'
        $n.Result.Facts.PdcNote | Should -Not -BeNullOrEmpty
        $ruled = Get-NoteSection $n.Lines 'Ruled out:'
        @($ruled | Where-Object { $_ -match 'Not locked out' }).Count | Should -Be 0
        $could = Get-NoteSection $n.Lines 'Could not check:'
        @($could | Where-Object { $_ -match 'lockout status was read from' -and $_ -match 'may be out of date' }).Count | Should -BeGreaterThan 0
    }

    It 'AC21_UserCheckNoReadNoRuledOut: <Case> still produces a note with nothing ruled out' -ForEach @(
        @{ Case = 'Error'; Identity = 'jdoe'; Down = 'DC01,DC02,DC03'; Status = 'Error'; Headline = 'could not read Active Directory' }
        @{ Case = 'NotFound'; Identity = 'nobody-here'; Down = ''; Status = 'NotFound'; Headline = "no user matched 'nobody-here'" }
        @{ Case = 'Ambiguous'; Identity = 'Pat Smith'; Down = ''; Status = 'Ambiguous'; Headline = "'Pat Smith' matches 2 people" }
    ) {
        Set-Scenario -Down $Down
        $n = Get-NoteLines $Identity
        $n.Result.Status | Should -Be $Status
        $n.Lines[0] | Should -BeLike "[[]Ticket note] AD-UserQuickCheck: *$Headline*"
        (Get-NoteSection $n.Lines 'Ruled out:') | Should -Be @('- (none)')
        $could = Get-NoteSection $n.Lines 'Could not check:'
        @($could | Where-Object { $_ -match 'did not run' }).Count | Should -BeGreaterThan 0
    }

    It 'AC22_UserCheckPassThru: -PassThru -Quiet returns the result, does not exit, writes nothing to the host' {
        $cmd = @"
`$env:PSModulePath = '$($script:FakeRoot);' + `$env:PSModulePath
`$all = @(& '$($script:ScriptPath)' -Identity jdoe -PassThru -Quiet *>&1)
`$isResult = { `$_ -is [pscustomobject] -and `$_.PSObject.Properties['Status'] -and `$_.PSObject.Properties['TicketNote'] }
`$res = @(`$all | Where-Object `$isResult)
`$other = @(`$all | Where-Object { -not (& `$isResult) } | ForEach-Object { "`$_" })
`$first = `$res | Select-Object -First 1
'RESULT:' + (ConvertTo-Json -Compress -InputObject @{ Count = `$res.Count; Props = @(`$first.PSObject.Properties.Name); Other = `$other; Status = `$first.Status; Exit = `$first.ExitCode })
'AFTER-MARK'
exit 0
"@
        $out = & $script:ExeNote -NoProfile -NonInteractive -Command $cmd 2>&1
        $text = (@($out | ForEach-Object { "$_" })) -join "`n"
        $text | Should -Match 'AFTER-MARK' -Because 'the script must not call exit under -PassThru'
        $line = @($text -split "`n" | Where-Object { $_ -like 'RESULT:*' })[0]
        $line | Should -Not -BeNullOrEmpty
        $info = ($line -replace '^RESULT:', '') | ConvertFrom-Json
        $info.Count | Should -Be 1
        $info.Status | Should -Be 'Ok'
        foreach ($p in 'Status', 'ExitCode', 'Facts', 'Assessment', 'TicketNote') { @($info.Props) | Should -Contain $p }
        @($info.Other).Count | Should -Be 0
    }

    It 'AC23_UserCheckTicketFolder: -TicketNumber puts the HTML, CSV and note in Ticket_<n> and names them as evidence' {
        $root = Join-Path $TestDrive 'ac23'
        $null = New-Item -ItemType Directory -Path $root
        $null = Invoke-ScriptInProcess @{ Identity = 'jdoe'; TicketNumber = '482113'; OutputPath = $root; NoClipboard = $true }
        $dir = Join-Path $root 'Ticket_482113'
        $html = @(Get-ChildItem -LiteralPath $dir -Filter 'UserQuickCheck_jdoe_*.html' -ErrorAction SilentlyContinue)
        $csv = @(Get-ChildItem -LiteralPath $dir -Filter 'UserQuickCheck_jdoe_*.csv' -ErrorAction SilentlyContinue)
        $note = @(Get-ChildItem -LiteralPath $dir -Filter 'Note_*_AD-UserQuickCheck.txt' -ErrorAction SilentlyContinue)
        $html.Count | Should -Be 1
        $csv.Count | Should -Be 1
        $note.Count | Should -Be 1
        $text = [System.IO.File]::ReadAllText($note[0].FullName)
        $text | Should -Match ([regex]::Escape($html[0].Name))
        $text | Should -Match ([regex]::Escape($csv[0].Name))
    }

    It 'AC24_UserCheckStampScope: Domain from the DN, Changed anything: No, and (as <user>) with -Credential but no secrets' {
        $n = Get-NoteLines 'jdoe'
        $stamp = @($n.Lines | Where-Object { $_ -like 'Domain: *' })[0]
        $stamp | Should -BeLike 'Domain: contoso.com | *'
        $stamp | Should -BeLike '*Changed anything: No'
        $stamp | Should -Not -Match '\(as '

        $secret = 'P@ssw0rd-Secret-123'
        $cred = New-Object System.Management.Automation.PSCredential('CONTOSO\svc-help', (ConvertTo-SecureString $secret -AsPlainText -Force))
        $n2 = Get-NoteLines 'jdoe' -Credential $cred
        $stamp2 = @($n2.Lines | Where-Object { $_ -like 'Domain: *' })[0]
        $stamp2 | Should -Match ([regex]::Escape('(as CONTOSO\svc-help)'))
        $all = $n2.Lines -join "`n"
        $all | Should -Not -Match ([regex]::Escape($secret))
        $all | Should -Not -Match 'PSCredential'
        $all | Should -Not -Match 'System\.Security\.SecureString'
    }

    It 'AC25_NoClipboardSwitches: -NoClipboard and -Quiet skip the clipboard; the default copies exactly once' {
        Mock Set-Clipboard { }
        $null = Invoke-ScriptInProcess @{ Identity = 'jdoe'; NoClipboard = $true }
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        $null = Invoke-ScriptInProcess @{ Identity = 'jdoe'; Quiet = $true }
        Should -Invoke Set-Clipboard -Times 0 -Exactly
        $null = Invoke-ScriptInProcess @{ Identity = 'jdoe' }
        Should -Invoke Set-Clipboard -Times 1 -Exactly
    }
}
