@{
    # Group Policy Preferences events are written to the Application log. Informational
    # events are ONLY logged when the 'Logging and tracing' policy is enabled, so an
    # empty Application log means "not recorded", never "no failures".
    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
    GppLogName   = 'Application'
    GppLogSource = 'Group Policy Drive Maps'

    GppEvents = @{
        4096 = @{ Severity = 'Success'; Category = 'Applied';         Meaning = 'Preference item applied successfully' }
        4098 = @{ Severity = 'Warning'; Category = 'ItemFailed';      Meaning = 'Item did not apply - failed with an error code' }
        4101 = @{ Severity = 'Success'; Category = 'Removed';         Meaning = 'Preference item was successfully removed' }
        4105 = @{ Severity = 'Warning'; Category = 'TargetingFailed'; Meaning = 'Did not apply because a targeting item failed' }
        4106 = @{ Severity = 'Warning'; Category = 'TargetingFailed'; Meaning = 'Did not apply because its targeting item failed' }
        8194 = @{ Severity = 'Warning'; Category = 'CseFailed';       Meaning = 'Client-side extension could not process settings for the GPO' }
        8212 = @{ Severity = 'Warning'; Category = 'TargetingFailed'; Meaning = 'Did not apply because a targeting item failed' }
    }

    # The Group Policy engine's own CSE-processing events, in a DIFFERENT channel:
    # Microsoft-Windows-GroupPolicy/Operational. These say whether the Drive Maps CSE
    # ran at all; the GppEvents above say whether an individual drive item applied.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
    GpOperationalLogName = 'Microsoft-Windows-GroupPolicy/Operational'
    GpOperationalEvents = @{
        4001 = 'Group Policy processing started'
        4016 = 'CSE processing started'
        5016 = 'CSE processing completed successfully'
        5017 = 'Organizational unit resolved'
        5312 = 'List of applicable GPOs'
        7016 = 'CSE processing completed with an error'
    }

    RegistryPaths = @{
        # Persistent (reconnect-at-logon) mounts. A letter present here but absent from
        # the live mount list means reconnect is failing - a different root cause from
        # policy failing to apply.
        PersistentMounts = 'HKCU:\Network'

        # Historical mount points - what the user has had mapped previously.
        MountPoints2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'

        # With UAC on, logon creates two linked sessions and drive mappings are
        # per-session symbolic links. EnableLinkedConnections=1 writes them to both.
        # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
        EnableLinkedConnections = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

        # GPP logging and tracing policy.
        # https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
        GppTracing = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Group Policy'

        # Drive Maps CSE registration. NoBackgroundPolicy=1 means the CSE is never
        # called during background refresh - half of the every-other-logon mechanism.
        # https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon
        DriveMapsCse = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\{5794DAFD-BE60-433f-88A2-1A31939AC01F}'
    }
}
