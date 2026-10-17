# STUB (SQ-001 test-first): signatures only. Every function fails with "not implemented"
# until the real kit replaces this file.

function New-TicketNoteItem {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Problem', 'Warning', 'Info', 'Clear', 'NotChecked')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Text,
        [bool]$CouldLook = $false
    )
    throw 'not implemented'
}

function New-TicketNoteStamp {
    param(
        [ValidateSet('Domain', 'Tenant', 'Computer')][string]$ScopeLabel,
        [string]$Scope,
        [string]$RunAs,
        [switch]$Changed,
        [string]$ChangeLogPath,
        [datetime]$Now = (Get-Date),
        [string]$UserName,
        [string]$ComputerName
    )
    throw 'not implemented'
}

function New-TicketNote {
    param(
        [string]$Tool, [string]$Headline, [string]$ScopeLine,
        [object[]]$Items, [string[]]$NextSteps, [object]$Stamp, [string[]]$EvidencePaths
    )
    throw 'not implemented'
}

function ConvertTo-TicketNoteText {
    param([object]$Note, [switch]$PasteSafe)
    throw 'not implemented'
}

function Protect-TicketNoteText {
    param([string]$Line)
    throw 'not implemented'
}

function Resolve-TicketFolder {
    param([string]$TicketNumber, [string]$Root)
    throw 'not implemented'
}

function Get-TicketNoteDefaultRoot {
    throw 'not implemented'
}

function Save-TicketNote {
    param([object]$Note, [string]$Folder, [switch]$PasteSafe)
    throw 'not implemented'
}

function Copy-TicketNoteToClipboard {
    param([string]$Text)
    throw 'not implemented'
}

function Invoke-WinFormsClipboard {
    param([string]$Text)
    throw 'not implemented'
}

function Publish-TicketNote {
    param([object]$Note, [string]$Folder, [switch]$PasteSafe, [switch]$NoClipboard)
    throw 'not implemented'
}
