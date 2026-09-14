BeforeAll {
    . "$PSScriptRoot\..\Export-DriveMapEvidence.ps1" -LoadFunctionsOnly
}

Describe 'Compare-MountState' {
    # A letter recorded in HKCU\Network but absent from the live mount list means the
    # persistent mount exists and reconnect is FAILING - the share was unreachable at
    # logon. That is a different root cause, and a different fix, from Group Policy
    # failing to apply. Collapsing them sends the technician to the wrong place.
    It 'identifies a failing reconnect when the mount is in the registry but not live' {
        $result = Compare-MountState `
            -PersistentMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' }) `
            -LiveMounts @()
        $row = $result | Where-Object { $_.DriveLetter -eq 'X' }
        $row.Finding | Should -Be 'ReconnectFailing'
    }

    It 'identifies a transient mount when live but not persisted' {
        $result = Compare-MountState `
            -PersistentMounts @() `
            -LiveMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' })
        ($result | Where-Object { $_.DriveLetter -eq 'X' }).Finding | Should -Be 'TransientMount'
    }

    It 'reports consistent when present in both' {
        $result = Compare-MountState `
            -PersistentMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' }) `
            -LiveMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' })
        ($result | Where-Object { $_.DriveLetter -eq 'X' }).Finding | Should -Be 'Consistent'
    }

    It 'returns nothing when both sides are empty' {
        Compare-MountState -PersistentMounts @() -LiveMounts @() | Should -BeNullOrEmpty
    }
}

Describe 'Select-DriveLetterReference' {
    # Microsoft's own scenario guide documents the case this catches: every Group Policy
    # event healthy, GPP trace showing the drive mapped successfully, and the drive still
    # gone - because a logon script in an unrelated GPO ran 'net use z: /delete'.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected

    It 'classifies net use /delete as a Delete operation' {
        $r = Select-DriveLetterReference -Text "net use x: /delete" -DriveLetter 'X'
        $r.Operation | Should -Be 'Delete'
    }

    It 'classifies a mapping command as a Map operation' {
        $r = Select-DriveLetterReference -Text "net use x: \\server\share /persistent:yes" -DriveLetter 'X'
        $r.Operation | Should -Be 'Map'
    }

    It 'is case insensitive about the drive letter' {
        (Select-DriveLetterReference -Text "NET USE X: /DELETE" -DriveLetter 'x').Operation | Should -Be 'Delete'
    }

    It 'reports the line number of each match' {
        $text = "rem header`r`nnet use x: /delete`r`nexit"
        (Select-DriveLetterReference -Text $text -DriveLetter 'X').LineNumber | Should -Be 2
    }

    It 'does not match a different drive letter' {
        Select-DriveLetterReference -Text "net use z: /delete" -DriveLetter 'X' | Should -BeNullOrEmpty
    }

    It 'matches PowerShell Remove-PSDrive as a Delete operation' {
        (Select-DriveLetterReference -Text "Remove-PSDrive -Name X" -DriveLetter 'X').Operation | Should -Be 'Delete'
    }
}

Describe 'New-EvidenceManifest' {
    # The manifest is what makes a bundle collected by someone else interpretable without
    # asking them what they ran. An item that could not be collected must never be
    # silently absent - absence would read as "nothing was there".
    It 'separates collected, empty and failed collectors' {
        $manifest = New-EvidenceManifest -Results @{
            PersistentMounts = [PSCustomObject]@{ State = 'Found';           Data = @(1) }
            GppEvents        = [PSCustomObject]@{ State = 'EmptyButValid';   Data = @() }
            TraceFiles       = [PSCustomObject]@{ State = 'CouldNotCollect'; Reason = 'Tracing disabled' }
        }
        $manifest.Collected | Should -Contain 'PersistentMounts'
        $manifest.Empty     | Should -Contain 'GppEvents'
        $manifest.Failed    | Should -Contain 'TraceFiles'
    }

    It 'records the reason a collector could not run' {
        $manifest = New-EvidenceManifest -Results @{
            TraceFiles = [PSCustomObject]@{ State = 'CouldNotCollect'; Reason = 'Tracing disabled' }
        }
        ($manifest.Failed -join ' ') | Should -Match 'Tracing disabled'
    }
}
