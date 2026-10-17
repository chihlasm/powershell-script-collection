# 3.0 so every tool that dot-sources this keeps running on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0).
# Tests\PSVersionFloor.Tests.ps1 and TicketNote\Tests\CaseKit.Tests.ps1 (AC13) guard the floor.
#Requires -Version 3.0

<#
.SYNOPSIS
    CaseKit: builds the four-part ticket note (Checked / Ruled out / Could not check / Next step)
    that the quick-check tools copy to the clipboard and save in the ticket folder.
.DESCRIPTION
    Dot-source this file; it defines functions only and runs nothing.

    THIS FILE IS COPIED. The canonical copy is TicketNote\CaseKit.ps1. Identical copies live in
    every tool folder that writes a ticket note (AD-UserQuickCheck, Network-QuickCheck,
    Citrix-FSLogix-Triage), so each folder still runs on its own. Edit the canonical copy, then
    copy it over the others: Tests\CaseKitParity.Tests.ps1 fails the moment a copy drifts.

    THE GATE. A check only lands under "Ruled out" when the tool says it actually managed to
    look (New-TicketNoteItem -Kind Clear -CouldLook $true). A Clear item without -CouldLook, or
    with -CouldLook $false, goes under "Could not check" instead. A forgotten flag therefore
    errs towards "Could not check" and never towards a false all-clear.

    Every function is pure except the three that write: Save-TicketNote (a file),
    Copy-TicketNoteToClipboard (the clipboard) and Resolve-TicketFolder (a folder).
    Publish-TicketNote calls those and writes the [INFO] / [WARN] console lines.

    Pure ASCII, no ::new(), no classes: Windows PowerShell 3.0 must be able to read it.
.NOTES
    REFERENCES
      Set-Clipboard first shipped in Windows PowerShell 5.0, so it is only used behind a
      Get-Command check, with a WinForms fallback for 3.0 / 4.0
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
        https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1
      powershell.exe defaults to a single-threaded apartment (STA) since 3.0; -Mta changes that
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
      Clipboard.SetText throws ThreadStateException outside STA (MTA hosts), so the call is
      wrapped and a failure is reported, not fatal
        https://learn.microsoft.com/dotnet/api/system.windows.forms.clipboard.settext
      Why not clip.exe: piping to a native program encodes with $OutputEncoding, which is
      ASCIIEncoding in Windows PowerShell 5.1, so a name such as Mueller-with-umlaut is mangled
        https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1
      UTF8Encoding($true) writes the byte order mark, so Notepad and Windows PowerShell read
      non-ASCII names correctly
        https://learn.microsoft.com/dotnet/api/system.text.utf8encoding.-ctor
        https://learn.microsoft.com/dotnet/api/system.io.file.writealllines
#>

# Ticket numbers: a letter or digit first, then letters, digits, - or _, up to 32 characters.
# \z (not $) so a trailing newline cannot slip through. This blocks .., \ and / (path traversal)
# while allowing non-numeric references.
$script:TicketNumberPattern = '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}\z'

$script:TicketNoteGateSuffix = ' (the tool could not confirm it was able to look)'

function Write-TicketNoteStatus {
    # Same [PASS]/[WARN]/[FAIL]/[INFO] console style as the tools. Named apart from the tools'
    # own Write-Status so dot-sourcing the kit never replaces it.
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level = 'INFO'
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Test-TicketNumber {
    # True when the value is a usable ticket number (see $script:TicketNumberPattern).
    param([AllowEmptyString()][AllowNull()][string]$TicketNumber)
    return ([string]$TicketNumber -match $script:TicketNumberPattern)
}

function New-TicketNoteItem {
    <#
    .SYNOPSIS
        One line of a ticket note: a finding (Problem / Warning / Info), a check that came back
        clean (Clear), or a check the tool could not do (NotChecked).
    .DESCRIPTION
        -CouldLook says the tool really managed to look. It defaults to $false, and a Clear item
        only reaches "Ruled out" with -CouldLook $true (see New-TicketNote).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Problem', 'Warning', 'Info', 'Clear', 'NotChecked')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Text,
        [bool]$CouldLook = $false
    )
    return [PSCustomObject]@{ Kind = $Kind; Text = $Text; CouldLook = $CouldLook }
}

function New-TicketNoteStamp {
    <#
    .SYNOPSIS
        Where, by whom, when, and whether anything was changed.
    .DESCRIPTION
        -Changed must name the change log (-ChangeLogPath): a tool that changes things writes each
        change to a log, and the note points at it. The time carries the UTC offset because a
        ticket is often read later, by someone in another time zone.
    #>
    param(
        [ValidateSet('Domain', 'Tenant', 'Computer')][string]$ScopeLabel = 'Computer',
        [string]$Scope,
        [string]$RunAs,
        [switch]$Changed,
        [string]$ChangeLogPath,
        [datetime]$Now = (Get-Date),
        [string]$UserName,
        [string]$ComputerName
    )
    if ($Changed -and [string]::IsNullOrWhiteSpace($ChangeLogPath)) {
        throw 'New-TicketNoteStamp: -Changed needs -ChangeLogPath. A tool that changes things must say where its change log is.'
    }
    if (-not $UserName) {
        $UserName = if ($env:USERDOMAIN) { '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME } else { [string]$env:USERNAME }
    }
    if (-not $ComputerName) { $ComputerName = [string]$env:COMPUTERNAME }
    if (-not $Scope) { $Scope = 'unknown' }
    return [PSCustomObject]@{
        ScopeLabel = $ScopeLabel; Scope = $Scope; RanBy = $UserName; Machine = $ComputerName; RunAs = $RunAs
        Time = $Now; Changed = [bool]$Changed; ChangeLogPath = $(if ($Changed) { $ChangeLogPath } else { '' })
    }
}

function New-TicketNote {
    <#
    .SYNOPSIS
        Sorts the items into the four sections. This function is the gate.
    .DESCRIPTION
        Problem / Warning / Info go under Checked (prefixed PROBLEM: / WARNING: / INFO:, in that
        order). Clear goes under Ruled out only when CouldLook is $true; otherwise it goes under
        Could not check with a suffix saying the tool could not confirm it looked. NotChecked goes
        under Could not check. Next steps are de-duplicated, order kept.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Tool,
        [string]$Headline,
        [string]$ScopeLine,
        [object[]]$Items = @(),
        [string[]]$NextSteps = @(),
        [object]$Stamp,
        [string[]]$EvidencePaths = @()
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $infos = New-Object System.Collections.Generic.List[string]
    $ruledOut = New-Object System.Collections.Generic.List[string]
    $couldNot = New-Object System.Collections.Generic.List[string]

    foreach ($item in @($Items)) {
        if ($null -eq $item -or [string]::IsNullOrWhiteSpace([string]$item.Text)) { continue }
        $text = [string]$item.Text
        switch ([string]$item.Kind) {
            'Problem' { $problems.Add("PROBLEM: $text") }
            'Warning' { $warnings.Add("WARNING: $text") }
            'Info' { $infos.Add("INFO: $text") }
            'Clear' {
                if ($item.CouldLook -eq $true) { $ruledOut.Add($text) }
                else { $couldNot.Add($text + $script:TicketNoteGateSuffix) }
            }
            'NotChecked' { $couldNot.Add($text) }
            default { $couldNot.Add($text) }
        }
    }
    $checked = @($problems.ToArray()) + @($warnings.ToArray()) + @($infos.ToArray())

    $steps = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($NextSteps)) {
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        if (-not $steps.Contains($s)) { $steps.Add($s) }
    }

    $created = if ($Stamp -and $Stamp.Time -is [datetime]) { $Stamp.Time } else { Get-Date }
    return [PSCustomObject]@{
        Tool = $Tool; Headline = $Headline; ScopeLine = $ScopeLine
        Checked = $checked; RuledOut = $ruledOut.ToArray(); CouldNotCheck = $couldNot.ToArray()
        NextSteps = $steps.ToArray(); Stamp = $Stamp
        EvidencePaths = @($EvidencePaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        CreatedAt = $created
    }
}

function Format-TicketNoteStampLine {
    # "Domain: contoso.com | Ran by: CONTOSO\jtech on WS-114 (as X) | 2026-10-17 09:30:12 (UTC+01:00) | Changed anything: No"
    param([object]$Stamp)
    if ($null -eq $Stamp) { return 'Ran by: unknown | Changed anything: unknown' }
    $ranBy = "$($Stamp.RanBy) on $($Stamp.Machine)"
    if ($Stamp.RunAs) { $ranBy += " (as $($Stamp.RunAs))" }
    $when = [datetime]$Stamp.Time
    $off = [TimeZoneInfo]::Local.GetUtcOffset($when)
    $sign = if ($off -lt [TimeSpan]::Zero) { '-' } else { '+' }
    $time = '{0} (UTC{1}{2:00}:{3:00})' -f $when.ToString('yyyy-MM-dd HH:mm:ss'), $sign, [math]::Abs($off.Hours), [math]::Abs($off.Minutes)
    $changed = if ($Stamp.Changed) { "Yes - change log: $($Stamp.ChangeLogPath)" } else { 'No' }
    return ('{0}: {1} | Ran by: {2} | {3} | Changed anything: {4}' -f $Stamp.ScopeLabel, $Stamp.Scope, $ranBy, $time, $changed)
}

function ConvertTo-TicketNoteText {
    <#
    .SYNOPSIS
        Renders a note as lines, ready to paste into the ticket.
    .DESCRIPTION
        Layout: the headline, a blank line, Checked / Ruled out / Could not check / Next step
        (each entry "- <text>", an empty section "- (none)"), a blank line, the stamp line and
        the evidence line. Evidence always shows file names only.

        -PasteSafe runs every line except the headline through Protect-TicketNoteText (IP
        addresses and share paths removed). The headline is the question the tech asked and is
        never changed.
    #>
    param([Parameter(Mandatory = $true)][object]$Note, [switch]$PasteSafe)

    $body = New-Object System.Collections.Generic.List[string]
    function Add-Section([string]$Header, [string[]]$Entries) {
        $body.Add($Header)
        $any = $false
        foreach ($e in @($Entries)) {
            if ([string]::IsNullOrWhiteSpace($e)) { continue }
            $body.Add("- $e"); $any = $true
        }
        if (-not $any) { $body.Add('- (none)') }
    }
    $checked = @()
    if (-not [string]::IsNullOrWhiteSpace($Note.ScopeLine)) { $checked += [string]$Note.ScopeLine }
    $checked += @($Note.Checked)
    Add-Section 'Checked:' $checked
    Add-Section 'Ruled out:' @($Note.RuledOut)
    Add-Section 'Could not check:' @($Note.CouldNotCheck)
    Add-Section 'Next step:' @($Note.NextSteps)
    $body.Add('')
    $body.Add((Format-TicketNoteStampLine -Stamp $Note.Stamp))
    $names = @(@($Note.EvidencePaths) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [System.IO.Path]::GetFileName([string]$_) })
    $body.Add('Evidence: ' + $(if ($names.Count -gt 0) { $names -join ', ' } else { '(none saved)' }))

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('[Ticket note] {0}: {1}' -f $Note.Tool, $Note.Headline))
    $lines.Add('')
    foreach ($l in $body) {
        if ($PasteSafe) { $lines.Add((Protect-TicketNoteText -Line $l)) } else { $lines.Add($l) }
    }
    return $lines.ToArray()
}

function Protect-TicketNoteText {
    <#
    .SYNOPSIS
        Paste-safe redaction of one line: share paths become [share path removed] and IPv4 /
        IPv6 addresses (with or without a port, bracketed or not) become [IP removed].
    .DESCRIPTION
        IPv6 candidates are confirmed with [System.Net.IPAddress]::TryParse, so times such as
        09:30:12 and words that happen to be hex are left alone.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Line)
    if ([string]::IsNullOrEmpty($Line)) { return [string]$Line }
    $text = $Line

    # UNC paths. A quoted path may contain spaces; an unquoted one ends at whitespace.
    # Trailing sentence punctuation is kept outside the redaction.
    $text = [regex]::Replace($text, '(?<q>["''])\\\\[^"''\r\n]+\k<q>', { param($m) $m.Groups['q'].Value + '[share path removed]' + $m.Groups['q'].Value })
    $text = [regex]::Replace($text, '\\\\[^\\/\s"''<>|]+(?:\\[^\s"''<>|]*)?', {
            param($m)
            $v = $m.Value
            $tail = ''
            while ($v.Length -gt 2 -and '.,;:)]'.Contains([string]$v[$v.Length - 1])) { $tail = [string]$v[$v.Length - 1] + $tail; $v = $v.Substring(0, $v.Length - 1) }
            '[share path removed]' + $tail
        })

    # Bracketed IPv6, optionally with a port: [::ffff:10.0.0.5]:445
    $text = [regex]::Replace($text, '\[(?<a>[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.%]*)\](?::\d{1,5})?', {
            param($m)
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($m.Groups['a'].Value, [ref]$ip)) { '[IP removed]' } else { $m.Value }
        })

    # Bare IPv6 (two or more colons, at least one hex digit, optional %scope).
    $text = [regex]::Replace($text, '(?<![\w:.\[])(?=[0-9A-Fa-f:.]*[0-9A-Fa-f])[0-9A-Fa-f:.]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z]+)?(?![\w:\]])', {
            param($m)
            $v = $m.Value
            $tail = ''
            while ($v.Length -gt 0 -and $v.EndsWith('.')) { $tail = '.' + $tail; $v = $v.Substring(0, $v.Length - 1) }
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($v, [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                '[IP removed]' + $tail
            } else { $m.Value }
        })

    # IPv4, optionally with a port: 10.1.2.3 / 10.1.2.3:445
    $text = [regex]::Replace($text, '(?<![\w.])(?<o1>\d{1,3})\.(?<o2>\d{1,3})\.(?<o3>\d{1,3})\.(?<o4>\d{1,3})(?::\d{1,5})?(?![\w]|\.\d)', {
            param($m)
            foreach ($g in 'o1', 'o2', 'o3', 'o4') { if ([int]$m.Groups[$g].Value -gt 255) { return $m.Value } }
            '[IP removed]'
        })
    return $text
}

function Resolve-TicketFolder {
    <#
    .SYNOPSIS
        Returns <Root>\Ticket_<TicketNumber>, creating it if missing. Throws, creating nothing,
        when the ticket number is not usable (see $script:TicketNumberPattern).
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$TicketNumber,
        [Parameter(Mandatory = $true)][string]$Root
    )
    if (-not (Test-TicketNumber -TicketNumber $TicketNumber)) {
        throw ("'{0}' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters, starting with a letter or digit)." -f $TicketNumber)
    }
    $folder = Join-Path $Root ("Ticket_{0}" -f $TicketNumber)
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    }
    return $folder
}

function Get-TicketNoteDefaultRoot {
    # Owner decision D-012: %USERPROFILE%\Documents\TicketNotes. The literal profile path (not
    # the shell's Documents folder) keeps client data out of a OneDrive-redirected Documents.
    if ($env:USERPROFILE) { return (Join-Path $env:USERPROFILE 'Documents\TicketNotes') }
    return (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'TicketNotes')
}

function Get-TicketNoteUniquePath {
    # <Folder>\<BaseName><Extension>, or <BaseName>_2, _3 ... when that name is taken.
    param([Parameter(Mandatory = $true)][string]$Folder, [Parameter(Mandatory = $true)][string]$BaseName, [string]$Extension = '.txt')
    $path = Join-Path $Folder ($BaseName + $Extension)
    $n = 2
    while (Test-Path -LiteralPath $path) {
        $path = Join-Path $Folder ('{0}_{1}{2}' -f $BaseName, $n, $Extension)
        $n++
    }
    return $path
}

function Save-TicketNoteLines {
    # UTF-8 with BOM, so non-ASCII names survive Notepad and Windows PowerShell.
    param([Parameter(Mandatory = $true)][string]$Path, [string[]]$Lines = @())
    [System.IO.File]::WriteAllLines($Path, [string[]]@($Lines), (New-Object System.Text.UTF8Encoding($true)))
}

function Save-TicketNote {
    <#
    .SYNOPSIS
        Writes Note_<yyyy-MM-dd_HHmmss>_<Tool>[_n].txt in -Folder (created if missing) and
        returns its path. Two notes with the same time and tool never overwrite each other.
    #>
    param([Parameter(Mandatory = $true)][object]$Note, [Parameter(Mandatory = $true)][string]$Folder, [switch]$PasteSafe)
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $Folder -Force -ErrorAction Stop
    }
    $when = if ($Note.CreatedAt -is [datetime]) { $Note.CreatedAt } else { Get-Date }
    $tool = ([string]$Note.Tool) -replace '[^\w\.\-]', '_'
    $path = Get-TicketNoteUniquePath -Folder $Folder -BaseName ('Note_{0}_{1}' -f $when.ToString('yyyy-MM-dd_HHmmss'), $tool)
    Save-TicketNoteLines -Path $path -Lines @(ConvertTo-TicketNoteText -Note $Note -PasteSafe:$PasteSafe)
    return $path
}

function Invoke-WinFormsClipboard {
    # The clipboard on Windows PowerShell 3.0 / 4.0, which have no Set-Clipboard. Kept apart so
    # tests can mock it. Throws ThreadStateException in an MTA host (powershell.exe -Mta).
    param([Parameter(Mandatory = $true)][string]$Text)
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    [System.Windows.Forms.Clipboard]::SetText($Text)
}

function Copy-TicketNoteToClipboard {
    <#
    .SYNOPSIS
        Puts the text on the clipboard. Returns $true or $false and never throws.
    .DESCRIPTION
        Set-Clipboard where it exists (5.0 and later), else the WinForms clipboard. If
        Set-Clipboard fails, the WinForms clipboard is tried too. Never clip.exe: piping to a
        native program re-encodes the text with $OutputEncoding (ASCII in 5.1).
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    try {
        if (Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue) {
            try {
                Set-Clipboard -Value $Text -ErrorAction Stop
                return $true
            } catch {
                Write-Verbose "Set-Clipboard failed, trying the WinForms clipboard: $($_.Exception.Message)"
            }
        }
        Invoke-WinFormsClipboard -Text $Text
        return $true
    } catch {
        Write-Verbose "The clipboard is not available in this session: $($_.Exception.Message)"
        return $false
    }
}

function Publish-TicketNote {
    <#
    .SYNOPSIS
        Saves the note (when -Folder is given), copies it to the clipboard (unless
        -NoClipboard) and says so on the console. If neither worked, prints the note so it is
        never lost.
    .OUTPUTS
        [PSCustomObject]@{ NotePath; Copied; Lines }
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Note,
        [string]$Folder,
        [switch]$PasteSafe,
        [switch]$NoClipboard
    )
    $lines = @(ConvertTo-TicketNoteText -Note $Note -PasteSafe:$PasteSafe)
    $notePath = $null
    $copied = $false

    if ($Folder) {
        try {
            $notePath = Save-TicketNote -Note $Note -Folder $Folder -PasteSafe:$PasteSafe
            Write-TicketNoteStatus "Ticket note saved: $notePath" 'INFO'
        } catch {
            Write-TicketNoteStatus "Could not save the ticket note in ${Folder}: $($_.Exception.Message)" 'WARN'
        }
    }
    if (-not $NoClipboard) {
        $copied = Copy-TicketNoteToClipboard -Text ($lines -join "`r`n")
        if ($copied) { Write-TicketNoteStatus 'Ticket note copied to the clipboard' 'INFO' }
        else { Write-TicketNoteStatus 'Could not copy the ticket note to the clipboard (this session has no clipboard).' 'WARN' }
    }
    if (-not $notePath -and -not $copied) {
        Write-Host ''
        Write-TicketNoteStatus 'Ticket note (copy it from here):' 'INFO'
        foreach ($l in $lines) { Write-Host $l }
    }
    return [PSCustomObject]@{ NotePath = $notePath; Copied = $copied; Lines = $lines }
}
