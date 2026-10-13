# Get-RAMUsage

**Who is using the RAM on this server?**

Shows how much memory each logged-on user is using on a Citrix or RDS server, and which of
their programs are using it. You get a ranked list in the console and an interactive report
in your browser.

It only reads information. Nothing on the server is changed.

---

## When to use it

- "Citrix / the remote desktop is slow" and the server's memory is high
- A server is close to running out of RAM and you need to know **who** or **what** is using it
- One user says "everything is slow for me": check whether their own session is the heavy one
- Comparing two or more servers in the same delivery group to see whether one is overloaded

If the problem is CPU, disk, or errors rather than memory, start with the
[Citrix-FSLogix-HealthCollector](../Citrix-FSLogix-HealthCollector/) instead.

---

## Quick start

Open **Windows PowerShell as Administrator**, `cd` into this folder, then:

```powershell
# The server you're logged on to
.\Get-RAMUsage.ps1

# One or more other servers
.\Get-RAMUsage.ps1 -ComputerName CTXVDA01, CTXVDA02

# Save the report somewhere specific, with a CSV for the ticket
.\Get-RAMUsage.ps1 -ComputerName CTXVDA01 -OutputPath C:\Reports -ExportCSV ram.csv
```

The HTML report opens automatically when it finishes.

---

## Reading the results

### In the console

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Server: CTXVDA01
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Memory: [██████████████████████████████░░░░░░░░░░] 75% (24.00 GB / 32.00 GB)

  User Sessions (2 accounts) - Private Working Set

  1. CONTOSO\jdoe (Session 2)
     Total: 1.17 GB  (38 processes)
       chrome                              800.0 MB   PID: 4120
       OUTLOOK                             400.0 MB   PID: 7788

  2. CONTOSO\asmith (Session 3)
     Total: 300.0 MB  (21 processes)
       EXCEL                               300.0 MB   PID: 9012

  Total User RAM: 1.46 GB
  System/Service: 3.20 GB (142 processes)  - add -IncludeSystemProcesses to itemise
```

- **The bar at the top** is the whole server's memory. It turns yellow at 70% and red at 90%.
- **Users are ranked heaviest first.** A user's total turns yellow at 2 GB and red at 4 GB.
- **System/Service** covers Windows, antivirus, the Citrix services and so on. If that number is
  large, run again with `-IncludeSystemProcesses` to see which of those accounts is using it.

### In the browser report

- **Click a user** to see every process they're running. Click again to collapse it.
- **Click a column header** to sort by RAM, CPU, process count, session or server.
- **Search** filters by user name. Each user's process list has its own search box.
- **Show System Accounts** adds SYSTEM, NETWORK SERVICE and the other service accounts to the table.

The report is a single file with nothing to install, so you can attach it straight to a ticket.

### What "Private Working Set" means

It's the memory a process is using that isn't shared with any other process. It's the same
figure Task Manager shows as *Private Working Set*. Using it means shared memory isn't counted
twice, so the per-user totals add up to something real.

If a server doesn't allow reading the performance counters, the tool falls back to
*commit size*, which reads higher. It prints a `[WARN]` line when this happens.

---

## Options

| Option | What it does | Default |
|---|---|---|
| `-ComputerName` | Server(s) to check. `localhost`, `.` and this computer's own name are all treated as "this machine". | This machine |
| `-OutputPath` | Folder to save the report in. Created if it doesn't exist. | Current folder |
| `-ExportCSV` | Also save a CSV with one row per process. A plain name like `ram.csv` goes in `-OutputPath`. | Off |
| `-ExportHTML` | Exact file path for the HTML report, if you want to choose the name yourself. | `RAMUsage_<date>_<time>.html` |
| `-IncludeSystemProcesses` | List service and system accounts one by one in the console, and show them in the report from the start. | Off |
| `-Top` | How many processes to list per user in the console. `0` lists them all. | 15 |
| `-Credential` | Use a different account for the remote servers. | You |
| `-SkipBrowserOpen` | Don't open the report when finished. | Off |

---

## Requirements

- **Windows PowerShell 5.1** (PowerShell 7 also works)
- **Run as Administrator.** Windows only reveals who owns each process to an elevated session.
- **For other servers:**
  - PowerShell remoting (WinRM) enabled on the target
  - Admin rights on the target

---

## If something goes wrong

| You see | What it means / what to do |
|---|---|
| `The 'IncludeUserName' parameter requires elevated user rights` | Close PowerShell and reopen it with **Run as administrator**. |
| `Could not retrieve processes from <server>` | WinRM is off, or you're not an admin on that server. Try `Test-WSMan <server>`. |
| `[WARN] Could not read private working set counters` | The totals are commit size and will read higher than Task Manager. The ranking is still useful. |
| `[WARN] Could not retrieve memory totals` | The memory bar and cards are missing for that server. The per-user breakdown is still correct. |
| A user shows as `UNKNOWN` | Windows didn't report an owner for that process. It's counted with the system accounts. |

---

## For maintainers

Run the tests (no admin or servers needed, since collection is mocked):

```powershell
Invoke-Pester -Path .\Tests
```

The script file must stay **plain ASCII**. Windows PowerShell 5.1 reads a file saved without a
BOM as ANSI, so a single em-dash or box-drawing character breaks the whole script. Version 1.1.0
failed with 65 parse errors because of this. A test fails the build if a non-ASCII byte appears.

### References

- [Get-Process (PowerShell 5.1)](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-process?view=powershell-5.1): `-IncludeUserName` requires Run as administrator
- [Memory Performance Information](https://learn.microsoft.com/windows/win32/memory/memory-performance-information): Working Set - Private maps to Task Manager's Private Working Set, and Private Bytes to Commit Size
