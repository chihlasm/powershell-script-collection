#
# Drift guards for logic that has to be DUPLICATED across the lockout scripts because each
# script is self-contained (no shared module). LockoutReference.psd1 is the single source of
# truth; these tests fail the moment a copy disagrees with it or with its siblings.
#
# Past drift, all fixed and now guarded here:
#   * status-code tables in Diagnose/Forensics missing codes the psd1 (and Export) had
#   * three different "is this 4625 SubStatus zero?" tests ('0x0' / regex / psd1-driven)
#   * the audit-subcategory list in Test-ADAuditPolicy missing Credential Validation (4776)
#   * Forensics rounding retention to 1 place where the other two used 2
#
# Sources: status codes -
#   https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
#   https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
# subcategory GUIDs - https://learn.microsoft.com/windows/win32/secauthz/auditing-constants
#

BeforeAll {
    $script:LockDir = Split-Path -Parent $PSScriptRoot
    $script:RefPath = Join-Path $script:LockDir 'LockoutReference.psd1'
    $script:LockRef     = Import-PowerShellDataFile -LiteralPath $script:RefPath

    function Get-FunctionText {
        param([string]$File, [string]$Name)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:LockDir $File), [ref]$null, [ref]$null)
        $fn = $ast.Find({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $args[0].Name -eq $Name
        }, $true)
        if ($fn) { $fn.Extent.Text -replace "`r`n", "`n" }
    }

    # Dot-sources a script in a child scope and returns the status tables it ended up with.
    # -WithoutReference copies the script somewhere with no LockoutReference.psd1 beside it,
    # which exercises its built-in FALLBACK table.
    function Get-ScriptStatusTables {
        param([string]$File, [switch]$WithoutReference)
        $src = Join-Path $script:LockDir $File
        if ($WithoutReference) {
            $dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $dir | Out-Null
            Copy-Item -LiteralPath $src -Destination $dir
            $src = Join-Path $dir $File
        }
        $needsIdentity = ($File -eq 'Diagnose-ADAccountLockout.ps1')
        & {
            param($s, $needsId)
            $script:StatusCodes = $null
            $script:SuccessStatusCodes = $null
            if ($needsId) { . $s -Identity '__pester__' -LoadFunctionsOnly } else { . $s -LoadFunctionsOnly }
            @{ Codes = $script:StatusCodes; Success = $script:SuccessStatusCodes }
        } $src $needsIdentity
    }

    $script:StatusScripts = @('Export-ADAuthSourceEvidence.ps1', 'Diagnose-ADAccountLockout.ps1', 'Invoke-ADLockoutForensics.ps1')
}

Describe 'Status code tables: LockoutReference.psd1 is the single source' {
    It 'psd1 documents the codes that Diagnose/Forensics used to lack' {
        foreach ($c in '0x00000000', '0xC0000192', '0xC0000371', '0xC0000413', '0xC000005E', '0xC000015B') {
            $script:LockRef.StatusCodes.ContainsKey($c) | Should -BeTrue -Because "$c is in the Learn Winlogon table"
        }
    }

    foreach ($file in @('Export-ADAuthSourceEvidence.ps1', 'Diagnose-ADAccountLockout.ps1', 'Invoke-ADLockoutForensics.ps1')) {
        It "$file uses the psd1 tables when the file is beside it" -TestCases @{ File = $file } {
            $t = Get-ScriptStatusTables -File $File
            $t.Codes.Count | Should -Be $script:LockRef.StatusCodes.Count
            foreach ($k in $script:LockRef.StatusCodes.Keys) { $t.Codes[$k] | Should -Be $script:LockRef.StatusCodes[$k] }
            @($t.Success) | Should -Be @($script:LockRef.SuccessStatusCodes)
        }

        It "$file's built-in FALLBACK table is identical to the psd1 (no drift)" -TestCases @{ File = $file } {
            $t = Get-ScriptStatusTables -File $File -WithoutReference
            $t.Codes   | Should -Not -BeNullOrEmpty
            $t.Codes.Count | Should -Be $script:LockRef.StatusCodes.Count -Because 'the fallback must carry every code the psd1 does'
            foreach ($k in $script:LockRef.StatusCodes.Keys) {
                $t.Codes.ContainsKey($k) | Should -BeTrue -Because "fallback is missing $k"
                $t.Codes[$k] | Should -BeExactly $script:LockRef.StatusCodes[$k]
            }
            @($t.Success) | Should -Be @($script:LockRef.SuccessStatusCodes)
        }
    }
}

Describe 'Status helper functions are identical across scripts' {
    It 'Get-StatusMeaning and Test-IsFailureStatus have the same text in Export, Diagnose and Forensics' {
        foreach ($fn in 'Get-StatusMeaning', 'Test-IsFailureStatus') {
            $ref = Get-FunctionText -File 'Export-ADAuthSourceEvidence.ps1' -Name $fn
            $ref | Should -Not -BeNullOrEmpty
            foreach ($f in 'Diagnose-ADAccountLockout.ps1', 'Invoke-ADLockoutForensics.ps1') {
                Get-FunctionText -File $f -Name $fn | Should -BeExactly $ref -Because "$fn drifted in $f"
            }
        }
    }

    It 'ConvertFrom-AdFileTime has the same text in Diagnose, Forensics and Watch' {
        $ref = Get-FunctionText -File 'Diagnose-ADAccountLockout.ps1' -Name 'ConvertFrom-AdFileTime'
        $ref | Should -Not -BeNullOrEmpty
        foreach ($f in 'Invoke-ADLockoutForensics.ps1', 'Watch-ADLockoutActivity.ps1') {
            Get-FunctionText -File $f -Name 'ConvertFrom-AdFileTime' | Should -BeExactly $ref
        }
    }

    It 'Test-IsFailureStatus gives the same answer in all three scripts for every rendering of zero' {
        foreach ($f in $script:StatusScripts) {
            $answers = & {
                param($s, $needsId)
                if ($needsId) { . $s -Identity '__pester__' -LoadFunctionsOnly } else { . $s -LoadFunctionsOnly }
                foreach ($c in '0x0', '0x00000000', '0', '', '0X0', '0xC0000234', '0x18') { Test-IsFailureStatus -Code $c }
            } (Join-Path $script:LockDir $f) ($f -eq 'Diagnose-ADAccountLockout.ps1')
            ($answers -join ',') | Should -Be 'False,False,False,False,False,True,True' -Because $f
        }
    }
}

Describe 'Never sentinels (LockoutReference.psd1 NeverSentinels)' {
    It 'every sentinel in the psd1 is treated as "never" by the guard in each script' {
        foreach ($f in 'Diagnose-ADAccountLockout.ps1', 'Invoke-ADLockoutForensics.ps1', 'Watch-ADLockoutActivity.ps1') {
            $out = & {
                param($s, $needsId, $sentinels)
                if ($needsId) { . $s -Identity '__pester__' -LoadFunctionsOnly } else { . $s -LoadFunctionsOnly }
                foreach ($n in $sentinels) { if ($null -eq (ConvertFrom-AdFileTime -Value ([int64]$n))) { 'never' } else { 'DATE' } }
            } (Join-Path $script:LockDir $f) ($f -eq 'Diagnose-ADAccountLockout.ps1') $script:LockRef.NeverSentinels
            (@($out) | Select-Object -Unique) | Should -Be 'never' -Because $f
        }
    }
    It 'the psd1 sentinel list is exactly 0 and Int64.MaxValue' {
        @($script:LockRef.NeverSentinels | ForEach-Object { [int64]$_ }) | Should -Be @([int64]0, [int64]::MaxValue)
    }
}

Describe 'Audit subcategory lists match the psd1' {
    It 'Test-ADAuditPolicy checks exactly the psd1 subcategories (name, GUID, needs, event)' {
        $mine = & { . (Join-Path $script:LockDir 'Test-ADAuditPolicy.ps1') -LoadFunctionsOnly; $script:LockoutSubcategories }
        @($mine).Count | Should -Be @($script:LockRef.AuditSubcategories).Count
        foreach ($r in $script:LockRef.AuditSubcategories) {
            $m = @($mine | Where-Object { $_.Name -eq $r.Name })
            $m.Count     | Should -Be 1 -Because "$($r.Name) must be checked"
            $m[0].Guid   | Should -Be $r.Guid
            $m[0].Needs  | Should -Be $r.Needs
            $r.Events    | Should -Contain $m[0].EventId
        }
    }

    It 'Invoke-ADLockoutForensics checks exactly the psd1 subcategories (name, GUID, needs)' {
        $mine = & {
            . (Join-Path $script:LockDir 'Invoke-ADLockoutForensics.ps1') -LoadFunctionsOnly
            @{ Subs = $script:AuditSubcategories; NeedsFailure = $script:NeedsFailure; NeedsSuccess = $script:NeedsSuccess }
        }
        $mine.Subs.Count | Should -Be @($script:LockRef.AuditSubcategories).Count
        foreach ($r in $script:LockRef.AuditSubcategories) {
            $mine.Subs.Contains($r.Name) | Should -BeTrue -Because "$($r.Name) must be checked"
            $mine.Subs[$r.Name].Guid | Should -Be $r.Guid
            if ($r.Needs -eq 'Failure') { $mine.NeedsFailure | Should -Contain $r.Name }
            else                        { $mine.NeedsSuccess | Should -Contain $r.Name }
        }
    }

    It 'all five lockout subcategory GUIDs are the ones on the Learn Auditing Constants page' {
        # https://learn.microsoft.com/windows/win32/secauthz/auditing-constants
        $expected = @{
            'User Account Management'         = '{0CCE9235-69AE-11D9-BED3-505054503030}'  # Audit_AccountManagement_UserAccount
            'Logon'                           = '{0CCE9215-69AE-11D9-BED3-505054503030}'  # Audit_Logon_Logon
            'Account Lockout'                 = '{0CCE9217-69AE-11D9-BED3-505054503030}'  # Audit_Logon_AccountLockout
            'Credential Validation'           = '{0CCE923F-69AE-11D9-BED3-505054503030}'  # Audit_AccountLogon_CredentialValidation
            'Kerberos Authentication Service' = '{0CCE9242-69AE-11D9-BED3-505054503030}'  # Audit_AccountLogon_KerbCredentialValidation
        }
        foreach ($k in $expected.Keys) {
            (@($script:LockRef.AuditSubcategories | Where-Object { $_.Name -eq $k }))[0].Guid | Should -Be $expected[$k]
        }
    }
}

Describe 'Security-log health helpers report the same numbers for the same log' {
    BeforeAll {
        # One fake log, served to all three implementations through a stub Get-WinEvent.
        $script:OldestAge = 12.3
        function Invoke-WithFakeLog {
            param([string]$File, [scriptblock]$Call)
            & {
                param($s, $needsId, $call, $age)
                function Get-WinEvent {
                    param($ListLog, $ComputerName, $LogName, $MaxEvents, [switch]$Oldest, $Credential, $FilterHashtable, $ErrorAction)
                    if ($ListLog) {
                        [pscustomobject]@{ MaximumSizeInBytes = 134217728; FileSize = 52428800; LogMode = 'Circular'
                                           RecordCount = 100; LogFilePath = 'C:\Windows\System32\winevt\Logs\Security.evtx' }
                    } else {
                        [pscustomobject]@{ TimeCreated = (Get-Date).AddDays(-$age) }
                    }
                }
                function Get-CimInstance { [pscustomobject]@{ FreeSpace = 50GB } }
                function Invoke-Command {
                    param($ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction)
                    [pscustomobject]@{
                        AuditPolCsv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting"
                        SCENoApplyLegacyAuditPolicy = 1
                    }
                }
                . $s -LoadFunctionsOnly
                & $call
            } (Join-Path $script:LockDir $File) $false $Call $script:OldestAge
        }
    }

    It 'Forensics Get-DCLogHealth, Set-DCSecurityLogRetention Get-DCLogStatus and Test-ADAuditPolicy Get-DCAuditPolicy agree' {
        $health = Invoke-WithFakeLog -File 'Invoke-ADLockoutForensics.ps1' -Call { Get-DCLogHealth -ComputerName 'DC01' -ForestName 'a.local' -RequestedDays 7 }
        $status = Invoke-WithFakeLog -File 'Set-DCSecurityLogRetention.ps1' -Call { Get-DCLogStatus -DcName 'DC01' -TargetDays 7 }
        $audit  = Invoke-WithFakeLog -File 'Test-ADAuditPolicy.ps1' -Call { Get-DCAuditPolicy -DcName 'DC01' }

        $health.Reachable | Should -BeTrue
        $status.Reachable | Should -BeTrue
        $audit.Reachable  | Should -BeTrue

        $health.MaxSizeMB     | Should -Be $status.CurrentMaxMB
        $health.MaxSizeMB     | Should -Be $audit.LogMaxMB
        $health.CurrentSizeMB | Should -Be $status.CurrentUsedMB
        $health.LogMode       | Should -Be $status.LogMode
        $health.CoverageDays  | Should -Be $status.RetentionDays -Because 'both round the oldest-event age to 2 places'
        $health.CoverageDays  | Should -Be $audit.RetentionDays
        $health.CoverageDays  | Should -Be 12.3
    }
}

Describe 'LockoutReference.psd1 is only searched beside each script' {
    It 'no script still probes a sibling AD-LockoutDiagnostics folder (the tools live together now)' {
        foreach ($f in Get-ChildItem -LiteralPath $script:LockDir -Filter '*.ps1') {
            (Get-Content -LiteralPath $f.FullName -Raw) |
                Should -Not -Match "Split-Path\s+\`$PSScriptRoot\s+-Parent\)\s+'AD-LockoutDiagnostics" -Because $f.Name
        }
    }
}
