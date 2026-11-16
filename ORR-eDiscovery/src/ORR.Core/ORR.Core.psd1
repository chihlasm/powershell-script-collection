@{
    RootModule        = 'ORR.Core.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '6f0c1c7e-3d0b-4a58-9d0e-2b7a4c1e9f31'
    Author            = 'VC3'
    CompanyName       = 'VC3'
    Copyright         = '(c) VC3. Internal use.'
    Description       = 'Open records request (ORR) logic for Microsoft Purview eDiscovery: client configuration, spec validation and KQL building. No UI code.'

    # Windows PowerShell 5.1 and PowerShell 7 on Windows.
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    # Microsoft.Graph.Authentication and Microsoft.Graph.Security are deliberately NOT listed
    # in RequiredModules: that would stop the module loading before the tool can explain what
    # is missing and offer to install it. They are checked at run time instead.

    FunctionsToExport = @(
        'Import-OrrClientConfig'
        'Test-OrrSpec'
        'Test-OrrKql'
        'New-OrrKqlQuery'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @('eDiscovery', 'Purview', 'OpenRecords')
        }
    }
}
