' Launches CloudSignInMgr.ps1 with no PowerShell console window.
'
' Running a .ps1 directly always flashes a blue console: powershell.exe creates it
' before the script gets a chance to hide it, so the in-script ShowWindow/SW_HIDE trick
' still leaves a visible flicker and often a lingering window behind the GUI.
'
' WScript.Shell .Run with intWindowStyle = 0 never creates the window in the first
' place, which is the only way to suppress it completely.
'
' Usage: double-click this file, or point a shortcut at it.
'        To run as administrator, set that on the shortcut (Properties > Advanced),
'        or right-click this file and choose "Run as administrator".

Option Explicit

Dim shell, fso, scriptDir, ps1Path, cmd

Set shell = CreateObject("WScript.Shell")
Set fso   = CreateObject("Scripting.FileSystemObject")

' Resolve the .ps1 next to this launcher so the pair can live in any folder.
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps1Path   = fso.BuildPath(scriptDir, "CloudSignInMgr.ps1")

If Not fso.FileExists(ps1Path) Then
    MsgBox "Could not find CloudSignInMgr.ps1 next to this launcher." & vbCrLf & vbCrLf & _
           "Expected: " & ps1Path, vbCritical, "Cloud Sign-In Manager"
    WScript.Quit 1
End If

cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1Path & """"

' 0 = hide the window, False = do not wait for it to exit.
shell.Run cmd, 0, False
