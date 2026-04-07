# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

A collection of standalone PowerShell scripts for Windows Server and Active Directory administration in MSP/enterprise environments. Each folder is a self-contained tool — there are no shared modules, build systems, or test frameworks. Scripts are deployed directly to target machines.

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
