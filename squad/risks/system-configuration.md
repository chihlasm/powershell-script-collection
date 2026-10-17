# Risk profile: changes to machine or network configuration

Applies to code that changes operating-system settings on a workstation, session host or
server: software install/uninstall (Install-*, Migrate-AdobeProducts,
CitrixWorkspaceApp_Remediation), registry, services, scheduled tasks (Schedule-Reboot),
printers (Set-PrinterDefaults), network settings (Network-Troubleshooting-Palette), and
device consoles (Juniper-ConsoleSetup). These often run on multi-user Citrix/RDS hosts,
where a bad change hits every logged-on user.

- Every change can be reverted, and the previous value is captured before changing it
  (registry value, service start type, installed version) and written to the log.
- The user sees exactly what will change, on which machine, before it happens, and confirms;
  `-WhatIf` is supported, and prompts are bypassed only with `-Force`.
- A change that could cut off the user's own connectivity (the adapter they are using, the
  firewall rule allowing remote access, a reboot of the host they are connected to) is
  detected and warned about explicitly. Reboots of multi-session hosts check for logged-on
  users first.
- Installers run silently with logging (`msiexec /l*v` or the vendor's equivalent), check the
  exit code (0, 3010 = reboot required, 1641), and report the result with
  `[PASS]/[WARN]/[FAIL]`. Exit codes are verified against vendor or Microsoft documentation
  and cited.
- Registry paths and Group Policy setting names are verified on Microsoft Learn and cited in a
  comment; a wrong path silently does nothing.
- Elevation is required only where needed (`#Requires -RunAsAdministrator`, PowerShell 4.0+),
  and the declared `#Requires -Version` matches what the code uses (`Tests/PSVersionFloor`).
- Code paths are exercised through Pester mocks; nothing in tests changes the real machine
  (no real `Set-ItemProperty`, `Set-Service`, `Restart-Computer`, `msiexec`, `netsh`). Tests
  that genuinely need the machine are tagged `Integration` and excluded from the gate.
- The run report flags these items for Michael to verify on a real (test) machine before
  release.
