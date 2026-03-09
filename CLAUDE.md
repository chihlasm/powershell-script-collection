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
