# ORR-eDiscovery

Runs municipal open records requests through Microsoft Purview eDiscovery for VC3 client
tenants.

**Status: phase 1 of 4. Nothing here signs in to a tenant or runs a search yet.** What exists
today is the part that decides whether a request is safe to run and what query it becomes.

| Changes anything? | Not yet. Phase 1 only reads a config file and checks text. |
|---|---|

## What works now

```powershell
Import-Module .\src\ORR.Core\ORR.Core.psd1

# 1. Load your clients (copy config\clients.example.json to config\clients.json first)
$clients = Import-OrrClientConfig -Path .\config\clients.json

# 2. Check a request. Every problem is listed at once, in plain English.
$result = Test-OrrSpec -Json (Get-Content .\spec.json -Raw) -ClientConfig $clients
$result.Errors
$result.Warnings

# 3. See the query that would be sent
$query = New-OrrKqlQuery -Spec $result.Spec -ClientConfig $clients
$query.Kql      # (budget OR "road repair") AND (date>=2023-12-31 AND date<2024-04-02)
$query.Notes    # what the dates mean, in plain English
```

## Layout

| Path | What it is |
|---|---|
| `src/ORR.Core/` | The module: client config, spec validation, query building |
| `src/ORR-Runner.ps1` | Placeholder for a future unattended runner |
| `config/clients.example.json` | Template for the per-client settings |
| `schemas/orr-spec.v1.schema.json` | The format of a request |
| `tests/` | Pester 5 tests |
| `CLAUDE.md` | Conventions, safety rules, and what Microsoft's documentation says |

## Tests

From the repository root:

```powershell
pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\ORR-eDiscovery\tests
```

Full documentation (`docs/README.md`, `docs/SETUP.md`) arrives in phase 4.
