BeforeAll {
    $script:Ref = Import-PowerShellDataFile -Path "$PSScriptRoot\..\DriveMapReference.psd1"
}

Describe 'GPP event reference (verified against Microsoft Learn)' {
    # GPP preference-item events are written to the APPLICATION log under source
    # 'Group Policy Drive Maps' - NOT to Microsoft-Windows-GroupPolicy/Operational.
    # Conflating the two streams means querying the wrong log and finding nothing,
    # which is indistinguishable from a healthy machine.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events

    It 'reads GPP preference events from the Application log' {
        $script:Ref.GppLogName | Should -Be 'Application'
    }

    It 'uses the documented Drive Maps event source' {
        $script:Ref.GppLogSource | Should -Be 'Group Policy Drive Maps'
    }

    It 'maps 4098 to a general item failure, not a targeting failure' {
        $script:Ref.GppEvents[4098].Category | Should -Be 'ItemFailed'
    }

    # 4105/4106/8212 mean the GPO did not apply TO THIS USER (targeting), which is a
    # different root cause and a different fix from 4098 (the item tried and errored).
    # Merging them hides which of the two is happening.
    It 'classifies 4105, 4106 and 8212 as targeting failures' {
        foreach ($id in 4105, 4106, 8212) {
            $script:Ref.GppEvents[$id].Category | Should -Be 'TargetingFailed'
        }
    }

    It 'records 4096 as a successful apply and 4101 as a successful removal' {
        $script:Ref.GppEvents[4096].Category | Should -Be 'Applied'
        $script:Ref.GppEvents[4101].Category | Should -Be 'Removed'
    }

    It 'records 8194 as a CSE-level failure' {
        $script:Ref.GppEvents[8194].Category | Should -Be 'CseFailed'
    }
}

Describe 'Registry path reference (verified against Microsoft Learn)' {
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
    It 'uses the documented EnableLinkedConnections policy key' {
        $script:Ref.RegistryPaths.EnableLinkedConnections |
            Should -Be 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    }

    It 'points persistent mount lookups at HKCU\Network' {
        $script:Ref.RegistryPaths.PersistentMounts | Should -Be 'HKCU:\Network'
    }

    # The Drive Maps CSE is registered at HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581924(v=ws.11)
    It 'uses the correct Winlogon\GPExtensions path for Drive Maps CSE registration' {
        $script:Ref.RegistryPaths.DriveMapsCse |
            Should -Be 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{5794DAFD-BE60-433f-88A2-1A31939AC01F}'
    }
}

Describe 'Group Policy operational event reference' {
    It 'includes the CSE start and completion events' {
        $script:Ref.GpOperationalEvents.Keys | Should -Contain 4016
        $script:Ref.GpOperationalEvents.Keys | Should -Contain 5016
        $script:Ref.GpOperationalEvents.Keys | Should -Contain 7016
    }
}

Describe 'Drive Maps CSE GUID (verified against Microsoft Learn)' {
    # The client-side extension unique identifier for the Group Policy Drive Map
    # preference extension is {5794DAFD-BE60-433f-88A2-1A31939AC01F}.
    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581924(v=ws.11)
    It 'uses the official Drive Maps CSE GUID' {
        $script:Ref.RegistryPaths.DriveMapsCse | Should -Match '\{5794DAFD-BE60-433f-88A2-1A31939AC01F\}'
    }
}
