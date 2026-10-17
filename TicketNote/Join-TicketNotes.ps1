# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    Joins every ticket note in a ticket folder into one combined note, ready to paste into the ticket.
.DESCRIPTION
    The quick-check tools (AD-UserQuickCheck, and others as they adopt the ticket note) save a
    note named Note_<yyyy-MM-dd_HHmmss>_<Tool>.txt into <root>\Ticket_<number> when they are run
    with -TicketNumber. This script reads those notes in time order and writes one file:

        Ticket 482113 - 3 notes
        User reported: S: drive missing
        Tech tried by hand: gpupdate /force

        -----
        [Ticket note] AD-UserQuickCheck: ...
        -----
        [Ticket note] Network-QuickCheck: ...

    It asks "What did the user report?" and "What did you already try by hand?" unless they are
    given as parameters; press Enter to skip either one. The combined note is saved as
    TicketNotes_Combined_<yyyy-MM-dd_HHmmss>.txt in the ticket folder and copied to the
    clipboard. Earlier combined files are never included.

    It changes nothing except writing the combined note file. It only concatenates files that
    are already there; it does not run any tool.
.PARAMETER TicketNumber
    The ticket number the tools were run with: letters, digits, - or _, up to 32 characters,
    starting with a letter or digit. Anything else is refused with a [FAIL] line (exit 2).
.PARAMETER OutputPath
    The folder that holds Ticket_<number>. Use the same -OutputPath you gave the tools. When
    omitted: %USERPROFILE%\Documents\TicketNotes, the tools' default.
.PARAMETER UserReported
    What the user reported, in a few words. Asked for when omitted.
.PARAMETER TechTried
    What you already tried by hand. Asked for when omitted.
.PARAMETER NoClipboard
    Leave the clipboard alone; only write the file. Without it the combined note goes to the
    clipboard, where it can enter clipboard history (Win+V) or the cloud clipboard on Windows
    PowerShell 5.0 and later, and travels over RDP clipboard redirection.
.PARAMETER FullDetail
    Keep IP addresses and share paths in the combined note. By default they are removed
    (paste-safe) from the two answers and from every joined line, including notes a tool saved
    with -FullDetail. Each note's "[Ticket note] ..." first line is the question the tech asked
    and is never changed. Redacting an already paste-safe note changes nothing.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without joining anything (used by the tests).
.EXAMPLE
    .\Join-TicketNotes.ps1 -TicketNumber 482113
    Asks the two questions, then saves and copies the combined note for ticket 482113.
.EXAMPLE
    .\Join-TicketNotes.ps1 -TicketNumber 482113 -UserReported 'S: drive missing' -TechTried 'gpupdate /force' -OutputPath D:\Cases
    No questions; the ticket folder is D:\Cases\Ticket_482113.
.NOTES
    Exit codes: 0 = combined note written, 1 = no ticket notes found, 2 = could not run
    (CaseKit.ps1 missing, an unusable ticket number, the ticket folder or a note could not be
    read, or the file could not be written).

    Needs CaseKit.ps1 in this folder (it ships with it).

    REFERENCES
      Set-Clipboard is 5.0; the kit falls back to the WinForms clipboard on 3.0 / 4.0
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1
      STA is the default apartment since 3.0 (the WinForms clipboard needs it)
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
      Why not clip.exe: $OutputEncoding is ASCII in 5.1, so non-ASCII names are mangled
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1
      Clipboard history / cloud clipboard opt-out formats (set by the kit's WinForms path)
        https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats
#>
[CmdletBinding(DefaultParameterSetName = 'Join')]
param(
    # Checked in the script body (Test-TicketNumber in CaseKit.ps1), not with ValidatePattern,
    # so a mistyped number gets a plain-English [FAIL] line instead of a parameter-binding error.
    [Parameter(Mandatory = $true, ParameterSetName = 'Join', Position = 0)]
    [AllowEmptyString()]
    [string]$TicketNumber,

    [Parameter(ParameterSetName = 'Join')]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'Join')]
    [AllowEmptyString()]
    [string]$UserReported,

    [Parameter(ParameterSetName = 'Join')]
    [AllowEmptyString()]
    [string]$TechTried,

    [Parameter(ParameterSetName = 'Join')]
    [switch]$NoClipboard,

    [Parameter(ParameterSetName = 'Join')]
    [switch]$FullDetail,

    [Parameter(ParameterSetName = 'Load')]
    [switch]$LoadFunctionsOnly
)

$kit = Join-Path $PSScriptRoot 'CaseKit.ps1'
if (Test-Path -LiteralPath $kit) { . $kit } else { $script:CaseKitMissing = $true }

function Get-TicketNoteFile {
    # The tools' notes in time order. Name order is time order: the timestamp comes first.
    # TicketNotes_Combined_* files do not match Note_* and are never joined again.
    param([Parameter(Mandatory = $true)][string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Folder -Filter 'Note_*.txt' -File -ErrorAction Stop | Sort-Object -Property Name)
}

function New-CombinedTicketNote {
    <#
    .SYNOPSIS
        Builds the combined note's lines from the notes' text (pure; no file access).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TicketNumber,
        [string[]]$NoteText = @(),
        [AllowEmptyString()][string]$UserReported,
        [AllowEmptyString()][string]$TechTried,
        [switch]$PasteSafe
    )
    function Format-Answer([string]$Value) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return '(not given)' }
        $v = $Value.Trim()
        if ($PasteSafe) { $v = Protect-TicketNoteText -Line $v }
        return $v
    }
    $count = @($NoteText).Count
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('Ticket {0} - {1} {2}' -f $TicketNumber, $count, $(if ($count -eq 1) { 'note' } else { 'notes' })))
    $lines.Add('User reported: ' + (Format-Answer $UserReported))
    $lines.Add('Tech tried by hand: ' + (Format-Answer $TechTried))
    $lines.Add('')
    foreach ($t in @($NoteText)) {
        $lines.Add('-----')
        foreach ($l in @(([string]$t).TrimEnd() -split "\r?\n")) {
            # A note saved with -FullDetail still has its IPs and share paths; paste-safe means
            # the combined note has none. Protect-TicketNoteText leaves a redacted line as it is.
            # The headline is the question the tech asked and is never changed (as in the kit).
            if ($PasteSafe -and -not $l.StartsWith('[Ticket note] ')) { $l = Protect-TicketNoteText -Line $l }
            $lines.Add($l)
        }
    }
    return $lines.ToArray()
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

if ($script:CaseKitMissing) {
    Write-Host '[FAIL] CaseKit.ps1 is missing from this folder. Copy the whole TicketNote folder, then run this again.' -ForegroundColor Red
    exit 2
}

if (-not (Test-TicketNumber -TicketNumber $TicketNumber)) {
    Write-TicketNoteStatus ("'{0}' is not a usable ticket number. Use the number the tools were run with: letters, digits, - or _ (up to 32 characters, starting with a letter or digit), for example 482113." -f $TicketNumber) 'FAIL'
    exit 2
}

$root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
$folder = Join-Path $root ("Ticket_{0}" -f $TicketNumber)

try {
    $files = @(Get-TicketNoteFile -Folder $folder)
} catch {
    Write-TicketNoteStatus "Could not read the ticket folder ${folder}: $($_.Exception.Message)" 'FAIL'
    exit 2
}
if ($files.Count -eq 0) {
    Write-TicketNoteStatus ("No ticket notes found for ticket {0} in {1}." -f $TicketNumber, $folder) 'WARN'
    Write-TicketNoteStatus 'Run the quick checks with -TicketNumber first (and the same -OutputPath, if you used one).' 'INFO'
    exit 1
}

if (-not $PSBoundParameters.ContainsKey('UserReported')) { $UserReported = Read-Host -Prompt 'What did the user report? (Enter to skip)' }
if (-not $PSBoundParameters.ContainsKey('TechTried')) { $TechTried = Read-Host -Prompt 'What did you already try by hand? (Enter to skip)' }

$utf8 = New-Object System.Text.UTF8Encoding($true)
$texts = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) {
    try {
        $texts.Add([System.IO.File]::ReadAllText($f.FullName, $utf8))
    } catch {
        Write-TicketNoteStatus "Could not read the ticket note $($f.FullName): $($_.Exception.Message)" 'FAIL'
        exit 2
    }
}
$lines = @(New-CombinedTicketNote -TicketNumber $TicketNumber -NoteText $texts.ToArray() -UserReported $UserReported -TechTried $TechTried -PasteSafe:(-not $FullDetail))

try {
    $path = Get-TicketNoteUniquePath -Folder $folder -BaseName ('TicketNotes_Combined_{0}' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    Save-TicketNoteLines -Path $path -Lines $lines
} catch {
    Write-TicketNoteStatus "Could not write the combined note in ${folder}: $($_.Exception.Message)" 'FAIL'
    exit 2
}
Write-TicketNoteStatus ("Combined {0} note(s) for ticket {1}: {2}" -f $files.Count, $TicketNumber, $path) 'INFO'

if (-not $NoClipboard) {
    if (Copy-TicketNoteToClipboard -Text ($lines -join "`r`n")) { Write-TicketNoteStatus 'Combined note copied to the clipboard' 'INFO' }
    else { Write-TicketNoteStatus 'Could not copy the combined note to the clipboard (this session has no clipboard). Open the file above instead.' 'WARN' }
}
exit 0
