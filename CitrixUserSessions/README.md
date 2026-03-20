# CitrixUserSessions

Queries Citrix Virtual Desktop Agent (VDA) sessions and displays which users are logged into which VDA servers, along with their local client machine names.

## Usage

```powershell
# Show all active user sessions across the site
.\CitrixUserSessions.ps1

# Show sessions on a specific VDA
.\CitrixUserSessions.ps1 -VdaMachineName "DOMAIN\VDAMachine01"
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `VdaMachineName` | No | Target VDA machine name. If omitted, queries all sessions in the site. |

## Output

Displays a table with:
- **UserName** — logged-in user
- **VDAServer** — the VDA machine hosting the session
- **LocalMachine** — the client device name

## Requirements

- Citrix Virtual Apps and Desktops PowerShell modules (PSSnapin or Module)
- Run from a Citrix Delivery Controller or a machine with Citrix Studio/SDK installed
