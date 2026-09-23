# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

A collection of standalone PowerShell scripts for Windows Server and Active Directory administration in MSP/enterprise environments. Each folder is a self-contained tool — there are no shared modules, build systems, or test frameworks. Scripts are deployed directly to target machines.

## Verify Against Microsoft Documentation

**Before writing or changing code that depends on a documented Microsoft fact, consult the official documentation and cite it in a code comment.** Do not rely on recalled knowledge for these — they change between OS versions and are the source of the most damaging bugs, because a wrong constant produces a confident, plausible, wrong answer rather than an error.

This applies to:

- **Event IDs and their field/schema layouts** (e.g. 4740's `CallerComputerName`, 4625's `SubStatus` vs `Status`)
- **Status and error codes** (e.g. 4776 `0x0` = *success*, not failure; Kerberos `0x18` = bad password)
- **Whether an event is logged for success, failure, or both** — several security events are written for both outcomes, and the status code is the only discriminator
- **Audit policy subcategory GUIDs** (locale-independent; display names are localized)
- **AD attribute semantics** — especially which attributes replicate (`badPwdCount`, `badPasswordTime`, and `lockoutTime` are per-DC and do **not** replicate) and sentinel values (`0` / `Int64.MaxValue` mean "never", not 1601-01-01)
- **Cmdlet parameters and behavior**, including deprecations and PS 5.1 vs 7.x differences
- **Graph API endpoints, permission scopes, and Entra ID / Entra Connect behavior**
- **Registry paths and Group Policy setting names**

### How to look it up

1. **Microsoft Learn MCP server** — preferred when available. It requires authentication; if it is not authorized in the session, say so rather than guessing, and fall back to:
2. **`WebFetch` against `learn.microsoft.com`** — works without authentication and returns the full page. Confirmed working for `/windows/security/threat-protection/auditing/event-NNNN` pages.
3. **`WebSearch` scoped with `allowed_domains: ["learn.microsoft.com"]`** when the exact URL is unknown.

### Recording what was verified

Cite the source next to the code it justifies, so the next person can re-verify without repeating the research:

```powershell
# Event 4776 is written for BOTH successful and failed NTLM validation. Error Code 0x0
# means success - treating every 4776 as a failure misreports healthy machines as
# attackers.
# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
'0x0' = 'Success'
```

Add a `REFERENCES` block to the script's `.NOTES` listing the pages consulted.

**When documentation contradicts an assumption in existing code, fix the code** — and add a regression test capturing the corrected behavior, so the wrong version cannot silently return.

## Stack Overflow for Troubleshooting

Stack Overflow is available as a **secondary, on-demand** source. Use it when it would actually help. Unlike Microsoft Learn, it is not a required step.

**Good uses:**
- Decoding an unfamiliar error message or symptom (e.g. a cryptic WinRM, CIM, or LDAP exception)
- Known quirks and workarounds the official docs don't cover (PS 5.1 vs 7.x oddities, RSAT module edge cases, serialization/encoding surprises)
- When a first fix attempt failed and you need to see how others solved it

**Not a substitute for Microsoft documentation.** Anything covered by *Verify Against Microsoft Documentation* above (event IDs, status codes, attribute semantics, GUIDs, registry paths) must still be confirmed on learn.microsoft.com. An answer's score, or the fact that it was accepted, does not prove it is correct for the OS version you're targeting. Check its date and the versions it mentions. When a Stack Overflow answer shapes the code, cite it next to that code, the same way as the Learn citations:

```powershell
# Workaround for Get-CimInstance hanging on unreachable hosts - see
# https://stackoverflow.com/a/NNNNNNN
```

### How to look it up

1. **Stack Overflow MCP server** (`so_search`, `get_content`). This is preferred, but it can be blocked by a Cloudflare challenge.
2. **Stack Exchange API** as a fallback. It works without authentication:
   - Search: `https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=votes&q=<terms>&accepted=True&site=stackoverflow`
   - Answer body: `https://api.stackexchange.com/2.3/answers/<id>?site=stackoverflow&filter=withbody`

## Script Conventions

### Parameter and CmdletBinding Style

- Use `[CmdletBinding()]` with typed `param()` blocks
- Include validation attributes: `[ValidateSet()]`, `[ValidateRange()]`, `[Parameter(Mandatory)]`
- Add `-OutputPath` (string, defaults to current directory) for any script that produces file output
- Use `-Force` switch to bypass confirmation prompts on destructive operations

### Help Documentation

Every script must have a comment-based help block with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, and `.NOTES` sections.

### Requirements Declarations

Use runtime `Import-Module` with try/catch instead of `#Requires -Modules` — the `#Requires` directive blocks execution before the script starts if the module isn't in the standard path, which fails on many servers where RSAT cmdlets are available but not formally registered. Do use `#Requires -Version 5.1` and `#Requires -RunAsAdministrator` where appropriate.

### Error Handling

- Wrap remote server connections in individual try/catch blocks so one unreachable server doesn't halt the entire script
- Use `-ErrorAction Stop` for critical operations, `-ErrorAction SilentlyContinue` for optional queries
- Use `continue` in loops to skip failed iterations gracefully

### Logging and Output

- Dual output pattern: color-coded `Write-Host` to console + accumulated lines written to file
- Status prefixes: `[PASS]` (Green), `[WARN]` (Yellow), `[FAIL]` (Red), `[INFO]` (Cyan)
- Timestamp format: `yyyy-MM-dd HH:mm:ss` for logs, `yyyy-MM-dd_HHmmss` for filenames
- Use `[PSCustomObject]@{}` for structured data; export with `Export-Csv -NoTypeInformation -Encoding UTF8`

### Remote Server Targeting

Every cmdlet that queries a remote server (AD, DHCP, DNS, etc.) must use the `-ComputerName` parameter. Never assume the script runs locally on the target server.

### Discovery Over Hardcoding

Query AD for server lists (`Get-DhcpServerInDC`, `Get-ADDomainController -Filter *`, etc.) rather than hardcoding server names.

## Commit Conventions

Use conventional commit prefixes: `feat:`, `fix:`, `docs:`. First line is a brief subject, followed by a blank line and bullet-point details when needed. End with `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`.

## Folder Structure Pattern

Each tool gets its own folder containing the main `.ps1` script and a `README.md`. No nested module structures — keep scripts flat and self-contained with no external dependencies beyond built-in Windows/RSAT PowerShell modules.

## Design Context

### Users
Mixed audience — IT helpdesk staff using it occasionally alongside seasoned sysadmins who run it daily. Helpdesk staff need plain-English labels, clear affordances, and no jargon. Sysadmins need density, efficiency, and precision. The interface must serve both without patronizing either.

Context: internal MSP tooling, run locally as a browser-based GUI over a PowerShell HTTP server. Always used on Windows workstations, often on dual monitors, usually in a task-focused flow (fix this folder's permissions, audit this share).

### Brand Personality
Bold · Trustworthy · Capable

### Aesthetic Direction
Bold modern tooling — confident dark UI with strong typographic hierarchy. Feels like VS Code or Windows Admin Center with personality. NOT generic IT dashboard gray soup. NOT neon cyberpunk. NOT consumer-app friendly-rounded. Opinionated, precise, professional with edge.

Dark default. Light mode available via toggle. Blue accent (current #5dade2 range) is fine but should feel intentional, not generic.

Anti-references: generic Bootstrap admin dashboards, Azure Portal blandness, rounded-everything SaaS UIs.

### Design Principles
1. **Plain English first** — no jargon where a plain word works. "Add Permission" not "Add ACE". "Who owns this?" not "Owner:". Labels must be immediately understood by someone who just started in IT.
2. **Density with breathing room** — pack information efficiently but never feel claustrophobic. Sysadmins need to scan many rows; helpdesk staff need enough space to read carefully.
3. **Drive letters and paths are data, not decoration** — always show where you are. Drive letters, folder names, full paths in context headers. Never leave the user guessing what they're looking at.
4. **Icons as anchors** — use icons to help non-technical users identify action types at a glance, but never as the sole communication (always paired with text labels).
5. **Confidence under the cursor** — every interactive element should feel solid and responsive. Hover states, active states, and loading indicators are mandatory, not optional.
