# Copy Files to Servers

Copy files or folders into the same folder on many servers at once. There are two ways to run it:

| Script | Use it when |
|--------|-------------|
| `CopyFileToServer-GUI.ps1` | You're working at a desk. You build the server list in a window, fix typos in place, and watch each server's result. |
| `CopyFileToServer.ps1` | You're scripting or automating. It copies one file from the command line. |

## The window (CopyFileToServer-GUI.ps1)

### Prerequisites

- Windows 10 / Windows Server 2016 or later, with Windows PowerShell 5.1 (PowerShell 7 also works)
- Your account needs write access to the destination share on each server. Admin shares such as `C$` need admin rights **on that server**. You don't need to run the tool as administrator locally.
- File sharing (TCP 445) open from your machine to the servers

Nothing to install. It's a single `.ps1` file.

### Usage

```powershell
.\CopyFileToServer-GUI.ps1
```

You can also right-click the file and choose **Run with PowerShell**.

1. **What to copy**: drop files or folders onto the box, or use **Add files** / **Add folder**. A folder is copied with everything in it, so `C:\Tools` lands as `<destination>\Tools`.
2. **Where to put it on each server**: a share and folder, such as `C$\Temp` or `Software\Installers`. Typing `C:\Temp` is changed to `C$\Temp` for you. The box below shows the exact path the files will go to. Missing folders are created.
3. **Options**:
   - **If a file is already there**: *Replace it* (the default), *Replace if mine is newer*, or *Leave it*.
   - **Servers at the same time**: 1, 4, 8 (the default) or 16.
4. **Which servers**: type a name and press **Enter**, or paste a whole list. The list can be one name per line or separated by commas or spaces, and `#` starts a comment. **Import file** reads a `.txt` list, or a `.csv` with a `DNSHostName`, `ComputerName`, `Server`, `HostName` or `Name` column (for example, an export from `Get-ADComputer`). You can also drop a `.txt` or `.csv` file onto the server list.

Then click **Copy to N servers**. You get a summary to confirm before anything is copied.

### Fixing the server list

- **Typo**: double-click the name (or click the pencil), correct it, and press Enter. Esc keeps the old name.
- **Skip a server this time**: untick it. It stays in the list for next time.
- **Remove a server**: click the X on its row.
- **Invalid names** in a paste (such as `srv#9`) aren't added. They stay in the box so you can fix them and press Enter again.
- **Duplicates** are ignored, and you're told which names were already in the list.
- **Save list** writes the list to a text file you can import later or keep with a client's documentation.

The list, destination folder and options are remembered the next time you open the tool.

### Check connection

**Check connection** tests every server in the list without copying anything. For each server it checks three things:

1. The name resolves.
2. The server answers on the file-sharing port (TCP 445), with a 3-second limit so offline servers fail fast.
3. Your account can open the share.

Each server is then marked **Ready** or **Can't connect**, with the reason.

### While copying, and after

Each server shows **Waiting**, then **Copying** (with the file number), then one of these results:

| Status | Meaning |
|--------|---------|
| Done | Everything was copied (or was already there, depending on the option) |
| Some files failed | Some files copied, some didn't. Hover over the message to see every problem. |
| Failed | Nothing was copied. The message gives the reason (server not found, access denied, share doesn't exist, disk full and so on). |
| Stopped / Not started | You clicked **Stop**. Servers that were copying finish the file they're on. Servers that hadn't started are skipped. |

When the run finishes:

- **Retry N** copies again to just the servers that failed or were stopped.
- **Open log** opens the log for the run.
- **Export results** saves one row per server to CSV.

### Files the tool creates

```
CopyFileToServer\
  CopyFileToServer-GUI.ps1
  Logs\    CopyToServers_yyyy-MM-dd_HHmmss.log, one per run ([PASS]/[WARN]/[FAIL] per server)
  State\   settings.json (server list, folder, options), gui-errors.log
```

Delete `State\settings.json` to start with an empty list.

### Tests

```powershell
Invoke-Pester .\Tests
```

The tests need Pester 5 or later. They don't need admin rights or network access. They cover parsing pasted and imported server lists, destination path handling, the plain-English error messages, and real copies to a temporary folder. The copy tests include replace, skip and newer modes, read-only and hidden targets, a locked file, and stopping.

## Command line (CopyFileToServer.ps1)

**Parameters**:

- `-SourceFile <string>` (Required): the file to copy (for example, `"C:\Scripts\script.ps1"`).
- `-DestServers <string[]>` (Required): the server names (for example, `@("Server01", "Server02")`).
- `-DestPath <string>` (Required): the path on each server (for example, `"share\folder"` or `"C$\Scripts"`).

**Examples**:

- `.\CopyFileToServer.ps1 -SourceFile "C:\Temp\file.txt" -DestServers @("Server01", "Server02") -DestPath "Shared\Files"`
- `.\CopyFileToServer.ps1 -SourceFile ".\script.ps1" -DestServers (Get-Content .\servers.txt) -DestPath "C$\Temp"`

It creates the destination folder if it's missing and moves on to the next server when one fails. It needs PowerShell 3.0 or later.
