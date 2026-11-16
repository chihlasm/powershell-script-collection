#Requires -Version 5.1
<#
.SYNOPSIS
    Placeholder for the headless ORR runner. Not built yet.

.DESCRIPTION
    A later phase will add an unattended runner that signs in with a certificate (app-only)
    and drives the same ORR.Core module as the GUI. Nothing is implemented here: the script
    explains that and exits with code 2 without signing in or contacting any tenant.

    Before this is built, note what Microsoft documents about app-only eDiscovery:
    it only works for cases with premium features enabled (E5 or an equivalent add-on), and
    it needs a service principal set up in Purview with the ExchangeOnlineManagement module.

.PARAMETER SpecPath
    Path to an ORR spec JSON file. Accepted so the future command line is stable; unused.

.PARAMETER ConfigPath
    Path to clients.json. Accepted so the future command line is stable; unused.

.EXAMPLE
    .\ORR-Runner.ps1 -SpecPath .\spec.json
    Prints that the runner is not implemented and exits with code 2.

.NOTES
    REFERENCES
    https://learn.microsoft.com/graph/security-ediscovery-appauthsetup
    https://learn.microsoft.com/purview/edisc-ref-api-guide
#>
[CmdletBinding()]
param(
    [string]$SpecPath,
    [string]$ConfigPath
)

Write-Host '[INFO] ORR-Runner.ps1 is a placeholder. The headless runner has not been built yet.' -ForegroundColor Cyan
Write-Host '[INFO] Use the GUI (ORR-GUI.ps1) once it is available. Nothing was run.' -ForegroundColor Cyan
exit 2
