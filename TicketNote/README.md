# TicketNote

**One note for the whole ticket.** The quick checks each leave a short ticket note. This folder joins every note for one ticket into a single note you paste into ConnectWise, and holds the kit the tools use to write their notes.

It changes nothing. The joiner reads the notes in the ticket folder and writes one text file next to them.

## When to use it

- You ran more than one quick check for the same ticket (for example AD-UserQuickCheck, then Network-QuickCheck) and want one note instead of several.
- You are escalating and want the next engineer to see what was checked, what is ruled out, and what could not be checked, in one place.

## The one command

Run the checks with the same `-TicketNumber`, then join them:

```powershell
..\AD-UserQuickCheck\Get-ADUserQuickCheck.ps1 -Identity jdoe -TicketNumber 482113
.\Join-TicketNotes.ps1 -TicketNumber 482113
```

It asks two questions. Press Enter to skip either one:

- *What did the user report?*
- *What did you already try by hand?*

It then saves `TicketNotes_Combined_<date>_<time>.txt` in the ticket folder and copies it to the clipboard:

```
Ticket 482113 - 2 notes
User reported: S: drive missing
Tech tried by hand: gpupdate /force

-----
[Ticket note] AD-UserQuickCheck: Can Jane Doe sign in right now? YES
...
-----
[Ticket note] Network-QuickCheck: ...
```

The notes are in the order they were made. Earlier combined files are never included again.

| Option | What it does |
|---|---|
| `-TicketNumber 482113` | The ticket. Letters, digits, `-` or `_`, up to 32 characters. |
| `-OutputPath D:\Cases` | Where the `Ticket_<number>` folder is. Use the same `-OutputPath` you gave the tools. Default: `%USERPROFILE%\Documents\TicketNotes`. |
| `-UserReported '...'` / `-TechTried '...'` | Answer the two questions up front (no prompts). |
| `-NoClipboard` | Only write the file. |
| `-FullDetail` | Keep IP addresses and share paths. By default they are removed from your two answers and from every joined note (even one a tool saved with `-FullDetail`). Each note's `[Ticket note]` first line is never changed. |

If no notes are found it says `[WARN] No ticket notes found for ticket 482113 in <folder>.`, writes nothing, and exits with code 1. Check the ticket number, and that you used the same `-OutputPath` as the tools.

Exit codes: `0` combined note written, `1` no notes found, `2` could not run (`CaseKit.ps1` missing, a ticket number that does not fit the rules, the ticket folder or a note could not be read, or the file could not be written).

Works on Windows PowerShell 3.0 and later.

## Where the files live

```
Documents\TicketNotes\
  Ticket_482113\
    UserQuickCheck_jdoe_2026-10-17_093012.html
    UserQuickCheck_jdoe_2026-10-17_093012.csv
    Note_2026-10-17_093012_AD-UserQuickCheck.txt
    TicketNotes_Combined_2026-10-17_094500.txt
```

These folders hold client user names and findings. They stay on your machine; nothing is uploaded. Delete the folder when the ticket is closed if your client agreement requires it.

## The clipboard

The note (and the combined note) is copied to the clipboard, which is not private:

- It is copied with the Windows Forms clipboard on every PowerShell version, and marked to stay out of **clipboard history** (Win+V) and the **cloud clipboard** that syncs to the user's other devices (the `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` formats, [Microsoft Learn](https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats)).
- Only if that fails (the Windows Forms clipboard needs PowerShell's default single-threaded apartment, so a window started with `-Mta` cannot use it) is `Set-Clipboard` used instead, on Windows PowerShell 5.0 and later. `Set-Clipboard` cannot opt out, so on that fallback the note can land in clipboard history and the cloud clipboard.
- Either way, in a Remote Desktop session the clipboard is shared with the PC you connected from (**RDP clipboard redirection**).

The note is paste-safe by default (no IP addresses or share paths), but it still names the user. Add `-NoClipboard` to keep it off the clipboard entirely; the file in the ticket folder is still written.

## The kit: CaseKit.ps1

`CaseKit.ps1` builds the four-part note (Checked, Ruled out, Could not check, Next step), the stamp (where, by whom, when, and whether anything was changed), saves it as UTF-8 with BOM, and copies it to the clipboard.

- **This folder holds the master copy.** Each tool that writes a note keeps an identical copy in its own folder, so every folder still runs on its own. After changing `CaseKit.ps1` here, copy it to `AD-UserQuickCheck`, `Network-QuickCheck`, `Citrix-FSLogix-Triage` and `M365-UserQuickCheck`. `Tests\CaseKitParity.Tests.ps1` fails if a copy drifts.
- **"Ruled out" needs proof.** A check is only ruled out when the tool says it really looked (`New-TicketNoteItem -Kind Clear -CouldLook $true`). Without that it goes under "Could not check".
- **Paste-safe.** IP addresses and share paths become `[IP removed]` / `[share path removed]` unless the tool is run with `-FullDetail`. Evidence shows file names only.
- **Clipboard.** The Windows Forms clipboard first, marked to stay out of clipboard history; `Set-Clipboard` (Windows PowerShell 5.0 and later) only when that fails (see [The clipboard](#the-clipboard)). Never `clip.exe`, which mangles names like Müller on Windows PowerShell 5.1. If there is no clipboard (a server with no desktop), the note is saved or printed instead.

## Tests

```powershell
Invoke-Pester .\TicketNote\Tests
Invoke-Pester .\Tests\CaseKitParity.Tests.ps1
```

The tests never touch the real clipboard or your Documents folder.
