# Nesting Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Nesting tab to the AD access report that lists every nested group and shows each one's full upward and downward chain as indented trees plus a copyable path list, including loops and nesting into protected groups.

**Architecture:** The export already walks groups downward; it now records each group-in-group edge (including loop-closing ones) and completes the graph upward with `memberOf` plus bounded `Get-ADGroup` lookups. A compact `nest` model is embedded as escaped JSON; a pure ES5 `NestCore` computes loops (SCCs), depth, trees and paths in the browser; a UI script renders the tab.

**Tech Stack:** PowerShell 3.0+ (single-file script, Pester 5 tests), ES5 JavaScript embedded in the HTML (Node.js for unit tests only).

**Spec:** `docs/superpowers/specs/2026-10-14-nesting-tab-design.md`

## Global Constraints

- All code lives in `AD-GroupMembership-Export/Export-ADGroupMembership.ps1`; tests in `AD-GroupMembership-Export/Tests/`.
- PowerShell 3.0 compatible: no `::new()`, classes, `using`, 5.x cmdlets (enforced by `Tests/PSVersionFloor.Tests.ps1`).
- Never `@($x)` on a variable that may be a `List[object]` (throws "Argument types do not match"); iterate directly or use `.ToArray()`.
- Script file stays pure ASCII (non-ASCII in HTML via entities like `&#8635;`).
- JavaScript is ES5 only: no `=>`, `let`/`const`, template literals, `dataset`, `NodeList.forEach`, `Map`/`Set`, `classList.toggle(x, bool)` (enforced by `Tests/OverlapCore.Tests.ps1`).
- All strings embedded in JSON go through `ConvertTo-JsonText`; all strings put into `innerHTML` go through `esc()`.
- Extra AD lookups capped at **1,000**; tree levels show at most **50** child groups; path lists at most **100** paths per direction.
- Protected groups by SID: `S-1-5-32-544|548|549|550|551|552`, and RIDs `512|516|518|519|521|526|527` on any `S-1-5-21-…` SID.
- Read-only: nothing writes to AD.

## Review Focus

- A parent DN that cannot be read (deleted, other forest, no rights) — expect an *unresolved* node and the run continues. (Task 2)
- The lookup cap reached on a huge domain — expect remaining DNs recorded unresolved and `capReached` set, not a hang. (Task 2)
- A group that is a member of itself, or a 2-group loop — expect a single loop marker, no infinite recursion. (Task 4)
- A group containing more than 50 groups — expect the first 50 and "+ N more". (Task 4)
- A group name containing `</script>`, quotes or `<img …>` in the nesting data — expect it rendered as text. (Task 3 and Task 5)

---

### Task 1: Record nesting edges during the walk; protected/built-in checks

**Files:**
- Modify: `AD-GroupMembership-Export/Export-ADGroupMembership.ps1` (`#region Helpers`: new functions before `Resolve-GroupMembership`; `Resolve-GroupMembership` group branch; `Get-TargetGroup` properties)
- Test: `AD-GroupMembership-Export/Tests/NestGraph.Tests.ps1` (new, BOM not needed: ASCII)

**Interfaces:**
- Produces: `$script:NestEdges` (hashtable parentDN → hashtable childDN → `$true`), `$script:NestNames` (hashtable DN → name), `Add-NestEdge -Edges <hashtable> -ParentDN <string> -ChildDN <string>`, `Test-ProtectedGroupSid -Sid <string>` → bool, `Test-BuiltinGroup -DistinguishedName <string> -Sid <string>` → bool.

- [ ] **Step 1: Write the failing tests**

```powershell
<#
    Nesting graph: edge recording during the walk, protected/built-in detection, and the
    upward completion (Resolve-NestGraph). Functions are loaded from the script by AST.
#>
BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Export-ADGroupMembership.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    function Write-Status { }
    function G([string]$Name, [string]$Sid = 'S-1-5-21-1-2-3-1500', [string[]]$MemberOf = @(), [string]$Ou = 'OU=Groups') {
        [PSCustomObject]@{ Name = $Name; SamAccountName = $Name; DistinguishedName = "CN=$Name,$Ou,DC=contoso,DC=com"
            GroupCategory = 'Security'; GroupScope = 'Global'; SID = $Sid; MemberOf = $MemberOf }
    }
    function DN([string]$Name, [string]$Ou = 'OU=Groups') { "CN=$Name,$Ou,DC=contoso,DC=com" }
}

Describe 'Add-NestEdge' {
    It 'stores each parent/child link once' {
        $e = @{}
        Add-NestEdge -Edges $e -ParentDN 'CN=A' -ChildDN 'CN=B'
        Add-NestEdge -Edges $e -ParentDN 'cn=a' -ChildDN 'CN=B'
        $e.Count | Should -Be 1
        $e['CN=A'].Count | Should -Be 1
    }
}

Describe 'Resolve-GroupMembership records nesting edges' {
    BeforeAll {
        $script:IncludeNested = $true; $script:UserMembersOnly = $false; $script:MaxNestingDepth = 10; $script:ADParams = @{}
        function Get-UserDetail { $null }
        # Pester can only mock commands that exist; the AD module is not installed on dev boxes.
        function Get-ADGroupMember { [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Server, $Credential, [switch]$Recursive) }
    }
    It 'records every group-in-group link, including the one that closes a loop' {
        $script:NestEdges = @{}; $script:NestNames = @{}
        Mock Get-ADGroupMember {
            if ($Identity -eq (DN 'A')) { @([PSCustomObject]@{ Name = 'B'; SamAccountName = 'B'; objectClass = 'group'; DistinguishedName = (DN 'B') }) }
            else { @([PSCustomObject]@{ Name = 'A'; SamAccountName = 'A'; objectClass = 'group'; DistinguishedName = (DN 'A') }) }
        }
        $root = [PSCustomObject]@{ Name = 'A'; DistinguishedName = (DN 'A') }
        $visited = New-Object 'System.Collections.Generic.HashSet[string]'
        [void]$visited.Add((DN 'A'))
        $null = Resolve-GroupMembership -Group $root -RootGroup $root -Depth 0 -Path '' -VisitedGroups $visited
        $script:NestEdges[(DN 'A')].ContainsKey((DN 'B')) | Should -BeTrue
        $script:NestEdges[(DN 'B')].ContainsKey((DN 'A')) | Should -BeTrue -Because 'the loop-closing edge must be recorded'
        $script:NestNames[(DN 'B')] | Should -Be 'B'
    }
}

Describe 'Protected and built-in detection' {
    It 'recognises protected groups by SID, whatever their name' {
        Test-ProtectedGroupSid 'S-1-5-32-544' | Should -BeTrue
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-512' | Should -BeTrue
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-519' | Should -BeTrue
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-513' | Should -BeFalse -Because 'Domain Users is not protected'
        Test-ProtectedGroupSid 'S-1-5-32-545' | Should -BeFalse
        Test-ProtectedGroupSid 'S-1-5-21-111-222-333-1512' | Should -BeFalse
        Test-ProtectedGroupSid '' | Should -BeFalse
    }
    It 'recognises built-in groups by container or well-known SID' {
        Test-BuiltinGroup -DistinguishedName 'CN=Administrators,CN=Builtin,DC=contoso,DC=com' -Sid '' | Should -BeTrue
        Test-BuiltinGroup -DistinguishedName 'CN=X,OU=Groups,DC=contoso,DC=com' -Sid 'S-1-5-21-1-2-3-512' | Should -BeTrue
        Test-BuiltinGroup -DistinguishedName 'CN=X,OU=Groups,DC=contoso,DC=com' -Sid 'S-1-5-21-1-2-3-1105' | Should -BeFalse
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `pwsh -NoProfile -c "Invoke-Pester ./AD-GroupMembership-Export/Tests/NestGraph.Tests.ps1 -Output Detailed"`
Expected: FAIL — `Add-NestEdge` / `Test-ProtectedGroupSid` not recognized; edges missing.

- [ ] **Step 3: Implement**

Add before `function Resolve-GroupMembership`:

```powershell
# Group-in-group links seen anywhere in the walk, for the report's Nesting tab:
# parentDN -> @{ childDN = $true }. Hashtable keys ignore case, so a DN seen with different
# casing from two roots is stored once.
$script:NestEdges = @{}
$script:NestNames = @{}

function Add-NestEdge {
    # Records "ChildDN is a direct member of ParentDN".
    param(
        [Parameter(Mandatory)][hashtable]$Edges,
        [Parameter(Mandatory)][string]$ParentDN,
        [Parameter(Mandatory)][string]$ChildDN
    )
    if (-not $Edges.ContainsKey($ParentDN)) { $Edges[$ParentDN] = @{} }
    $Edges[$ParentDN][$ChildDN] = $true
}

function Test-ProtectedGroupSid {
    <#
        Microsoft's protected groups (Appendix C), matched by SID so a renamed or localised
        group is still recognised. Domain-relative groups match by RID on any S-1-5-21 SID,
        which also catches forest-root groups (Schema/Enterprise Admins) seen from a child
        domain. The Administrator and Krbtgt accounts are on the list too but are not groups.
        https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    #>
    param([AllowEmptyString()][AllowNull()][string]$Sid)
    if (-not $Sid) { return $false }
    if ($Sid -match '^S-1-5-32-(544|548|549|550|551|552)$') { return $true }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(512|516|518|519|521|526|527)$') { return $true }
    return $false
}

function Test-BuiltinGroup {
    # Built-in: in CN=Builtin, a BUILTIN (S-1-5-32) SID, or a well-known RID below 1000 -
    # the same rule -ExcludeBuiltin uses.
    param([AllowEmptyString()][string]$DistinguishedName, [AllowEmptyString()][AllowNull()][string]$Sid)
    if ($DistinguishedName -match '(?i),CN=Builtin,') { return $true }
    if ($Sid -match '^S-1-5-32-') { return $true }
    if ($Sid -match '^S-1-5-21-.*-(\d+)$' -and [int]$Matches[1] -lt 1000) { return $true }
    return $false
}
```

In `Resolve-GroupMembership`, at the top of `if ($member.objectClass -eq 'group') {`, before the `-not $UserMembersOnly` block:

```powershell
            # Recorded before the cycle check below, so a loop's closing link is kept too.
            Add-NestEdge -Edges $script:NestEdges -ParentDN $Group.DistinguishedName -ChildDN $member.DistinguishedName
            $script:NestNames[$Group.DistinguishedName] = $Group.Name
            $script:NestNames[$member.DistinguishedName] = $member.Name
```

In `Get-TargetGroup`, add `'MemberOf'` to `$searchParams['Properties']`.

- [ ] **Step 4: Run to verify they pass**

Run: same command, on `powershell` and `pwsh`. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add AD-GroupMembership-Export
git commit -m "feat: record group nesting edges during the walk; protected-group check by SID"
```

---

### Task 2: Complete the graph upward (`Resolve-NestGraph`)

**Files:**
- Modify: `Export-ADGroupMembership.ps1` (after `Test-BuiltinGroup`)
- Test: `Tests/NestGraph.Tests.ps1` (append)

**Interfaces:**
- Consumes: `Add-NestEdge`, `Get-DnFirstValue`.
- Produces: `Resolve-NestGraph -Groups <ADGroup[]> -Edges <hashtable> -Lookup <scriptblock(dn)> [-Names <hashtable>] [-Cap <int>]` → `[PSCustomObject]@{ Nodes = <hashtable DN → node>; CapReached = <bool>; Lookups = <int> }`, node = `[PSCustomObject]@{ DN; Name; Sam; Category; Scope; Sid; InExport; Unresolved }`. Adds `memberOf` edges into `-Edges`.

- [ ] **Step 1: Write the failing tests** (append to `NestGraph.Tests.ps1`)

```powershell
Describe 'Resolve-NestGraph' {
    BeforeAll {
        # Directory: Helpdesk -> IT-Staff -> IT-Admins -> Administrators (builtin, not exported)
        $script:Dir = @{}
        foreach ($g in @(
            (G 'IT-Staff' 'S-1-5-21-1-2-3-1201' @((DN 'IT-Admins')))
            (G 'IT-Admins' 'S-1-5-21-1-2-3-1202' @((DN 'Administrators' 'CN=Builtin')))
            (G 'Administrators' 'S-1-5-32-544' @() 'CN=Builtin')
        )) { $script:Dir[$g.DistinguishedName] = $g }
        $script:Lookup = { param($dn) if ($script:Dir.ContainsKey($dn)) { $script:Dir[$dn] } else { throw "not found: $dn" } }
    }

    It 'follows parents outside the export up to the top' {
        $edges = @{}
        $helpdesk = G 'Helpdesk' 'S-1-5-21-1-2-3-1200' @((DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($helpdesk) -Edges $edges -Lookup $script:Lookup
        $r.Nodes.ContainsKey((DN 'Administrators' 'CN=Builtin')) | Should -BeTrue
        $r.Nodes[(DN 'Administrators' 'CN=Builtin')].InExport | Should -BeFalse
        $r.Nodes[(DN 'Helpdesk')].InExport | Should -BeTrue
        $edges[(DN 'IT-Admins')].ContainsKey((DN 'IT-Staff')) | Should -BeTrue
        $edges[(DN 'Administrators' 'CN=Builtin')].ContainsKey((DN 'IT-Admins')) | Should -BeTrue
        $r.Lookups | Should -Be 3
        $r.CapReached | Should -BeFalse
    }

    It 'never looks up the same group twice' {
        $edges = @{}
        $a = G 'A1' 'S-1-5-21-1-2-3-1301' @((DN 'IT-Staff'))
        $b = G 'B1' 'S-1-5-21-1-2-3-1302' @((DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($a, $b) -Edges $edges -Lookup $script:Lookup
        $r.Lookups | Should -Be 3
    }

    It 'records an unreadable parent as unresolved and carries on' {
        $edges = @{}
        $x = G 'X1' 'S-1-5-21-1-2-3-1401' @('CN=Gone,OU=Old,DC=contoso,DC=com', (DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($x) -Edges $edges -Lookup $script:Lookup
        $r.Nodes['CN=Gone,OU=Old,DC=contoso,DC=com'].Unresolved | Should -BeTrue
        $r.Nodes['CN=Gone,OU=Old,DC=contoso,DC=com'].Name | Should -Be 'Gone'
        $r.Nodes.ContainsKey((DN 'Administrators' 'CN=Builtin')) | Should -BeTrue
    }

    It 'stops at the lookup cap and marks the rest unresolved' {
        $edges = @{}
        $helpdesk = G 'Helpdesk' 'S-1-5-21-1-2-3-1200' @((DN 'IT-Staff'))
        $r = Resolve-NestGraph -Groups @($helpdesk) -Edges $edges -Lookup $script:Lookup -Cap 1
        $r.CapReached | Should -BeTrue
        $r.Lookups | Should -Be 1
        $r.Nodes[(DN 'IT-Admins')].Unresolved | Should -BeTrue
    }

    It 'resolves children seen in the walk that were not exported' {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN (DN 'Helpdesk') -ChildDN (DN 'IT-Staff')
        $helpdesk = G 'Helpdesk' 'S-1-5-21-1-2-3-1200'
        $r = Resolve-NestGraph -Groups @($helpdesk) -Edges $edges -Lookup $script:Lookup
        $r.Nodes[(DN 'IT-Staff')].Unresolved | Should -BeFalse
        $r.Nodes[(DN 'IT-Staff')].Sid | Should -Be 'S-1-5-21-1-2-3-1201'
    }

    It 'accepts a SecurityIdentifier object as the SID' {
        $edges = @{}
        $g = G 'Sid1'
        $g.SID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
        $r = Resolve-NestGraph -Groups @($g) -Edges $edges -Lookup $script:Lookup
        $r.Nodes[(DN 'Sid1')].Sid | Should -Be 'S-1-5-32-544'
    }
}
```

- [ ] **Step 2: Run to verify they fail** — Expected: `Resolve-NestGraph` not recognized.

- [ ] **Step 3: Implement**

```powershell
function Resolve-NestGraph {
    <#
        Completes the nesting graph upward, for the report's Nesting tab.

        Exported groups bring their memberOf (requested in Get-TargetGroup, no extra query).
        Any group not in the export - a parent found through memberOf, or a child group the
        walk saw - is looked up once with Get-ADGroup (via -Lookup), and its own memberOf is
        followed, until nothing new appears. memberOf is a back-link held on the DC queried,
        so nesting into groups in other domains of a forest may not appear.
        https://learn.microsoft.com/windows/win32/adschema/a-memberof

        Bounded: each DN is looked up at most once, and at most -Cap lookups are made. A
        lookup that fails (deleted, no rights, other forest) and anything left past the cap
        become 'unresolved' nodes, so every edge still points at a node and the run continues.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Groups,
        [Parameter(Mandatory)][hashtable]$Edges,
        [Parameter(Mandatory)][scriptblock]$Lookup,
        [hashtable]$Names = @{},
        [int]$Cap = 1000
    )

    $nodes = @{}
    $queue = New-Object 'System.Collections.Generic.Queue[string]'
    $lookups = 0
    $capReached = $false

    function Add-ResolvedNode($Group, [bool]$InExport) {
        $sid = ''
        if ($Group.SID -is [string]) { $sid = $Group.SID }
        elseif ($Group.SID) { $sid = [string]$Group.SID.Value }
        $nodes[[string]$Group.DistinguishedName] = [PSCustomObject]@{
            DN = [string]$Group.DistinguishedName; Name = [string]$Group.Name; Sam = [string]$Group.SamAccountName
            Category = [string]$Group.GroupCategory; Scope = [string]$Group.GroupScope; Sid = $sid
            InExport = $InExport; Unresolved = $false
        }
        foreach ($parent in $Group.MemberOf) {
            if (-not $parent) { continue }
            Add-NestEdge -Edges $Edges -ParentDN ([string]$parent) -ChildDN ([string]$Group.DistinguishedName)
            if (-not $nodes.ContainsKey([string]$parent)) { $queue.Enqueue([string]$parent) }
        }
    }
    function Add-UnresolvedNode([string]$DN) {
        $name = if ($Names.ContainsKey($DN)) { [string]$Names[$DN] } else { Get-DnFirstValue $DN }
        $nodes[$DN] = [PSCustomObject]@{ DN = $DN; Name = $name; Sam = ''; Category = ''; Scope = ''; Sid = ''
            InExport = $false; Unresolved = $true }
    }

    foreach ($g in $Groups) { if ($g) { Add-ResolvedNode $g $true } }
    foreach ($parent in [string[]]$Edges.Keys) {
        if (-not $nodes.ContainsKey($parent)) { $queue.Enqueue($parent) }
        foreach ($child in [string[]]$Edges[$parent].Keys) {
            if (-not $nodes.ContainsKey($child)) { $queue.Enqueue($child) }
        }
    }

    while ($queue.Count -gt 0) {
        $dn = $queue.Dequeue()
        if ($nodes.ContainsKey($dn)) { continue }
        if ($lookups -ge $Cap) { $capReached = $true; Add-UnresolvedNode $dn; continue }
        $lookups++
        $found = $null
        try { $found = & $Lookup $dn } catch { $found = $null }
        if ($found) { Add-ResolvedNode $found $false } else { Add-UnresolvedNode $dn }
    }

    return [PSCustomObject]@{ Nodes = $nodes; CapReached = $capReached; Lookups = $lookups }
}
```

- [ ] **Step 4: Run to verify they pass** (both editions). Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: complete the nesting graph upward with bounded memberOf lookups"`

---

### Task 3: Nest model and JSON

**Files:**
- Modify: `Export-ADGroupMembership.ps1` (in `#region Group-centric model`, after `ConvertTo-ReportJson`)
- Test: `Tests/NestGraph.Tests.ps1` (append)

**Interfaces:**
- Consumes: `Resolve-NestGraph` output, `ConvertTo-OuPath`, `Test-ProtectedGroupSid`, `Test-BuiltinGroup`, `ConvertTo-JsonText`.
- Produces: `ConvertTo-NestModel -Graph <object> -Edges <hashtable> [-NestedExpanded]` → `[PSCustomObject]@{ Nodes = <object[]>; Up = <int[][]>; Down = <int[][]>; NestedExpanded = <bool>; CapReached = <bool> }`, node = `[PSCustomObject]@{ n; s; c; sc; ou; x; p; b; u }`. `ConvertTo-NestJson -Model <object>` → string `{"nodes":[...],"up":[[...]],"down":[[...]],"flags":{"nestedExpanded":bool,"capReached":bool}}`.

- [ ] **Step 1: Write the failing tests** (append)

```powershell
Describe 'ConvertTo-NestModel and ConvertTo-NestJson' {
    BeforeAll {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN (DN 'IT-Admins') -ChildDN (DN 'IT-Staff')
        Add-NestEdge -Edges $edges -ParentDN (DN 'Administrators' 'CN=Builtin') -ChildDN (DN 'IT-Admins')
        $nodes = @{}
        foreach ($n in @(
            [PSCustomObject]@{ DN = (DN 'IT-Staff'); Name = 'IT-Staff'; Sam = 'IT-Staff'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-21-1-2-3-1201'; InExport = $true; Unresolved = $false }
            [PSCustomObject]@{ DN = (DN 'IT-Admins'); Name = 'IT-Admins'; Sam = 'IT-Admins'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-21-1-2-3-1202'; InExport = $true; Unresolved = $false }
            [PSCustomObject]@{ DN = (DN 'Administrators' 'CN=Builtin'); Name = 'Administrators'; Sam = 'Administrators'; Category = 'Security'; Scope = 'DomainLocal'; Sid = 'S-1-5-32-544'; InExport = $false; Unresolved = $false }
            [PSCustomObject]@{ DN = (DN 'Lonely'); Name = 'Lonely'; Sam = 'Lonely'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-21-1-2-3-1999'; InExport = $true; Unresolved = $false }
        )) { $nodes[$n.DN] = $n }
        $script:Graph = [PSCustomObject]@{ Nodes = $nodes; CapReached = $false; Lookups = 1 }
        $script:Model = ConvertTo-NestModel -Graph $script:Graph -Edges $edges -NestedExpanded
        function Id([string]$Name) { for ($i = 0; $i -lt $script:Model.Nodes.Count; $i++) { if ($script:Model.Nodes[$i].n -eq $Name) { return $i } }; -1 }
    }

    It 'includes only groups with at least one nesting link' {
        $script:Model.Nodes.Count | Should -Be 3
        Id 'Lonely' | Should -Be -1
    }
    It 'stores direct parents and children by index' {
        @($script:Model.Up[(Id 'IT-Staff')]) | Should -Be @((Id 'IT-Admins'))
        @($script:Model.Down[(Id 'Administrators')]) | Should -Be @((Id 'IT-Admins'))
        @($script:Model.Up[(Id 'Administrators')]).Count | Should -Be 0
    }
    It 'flags protected, built-in and fetched-only groups' {
        $a = $script:Model.Nodes[(Id 'Administrators')]
        $a.p | Should -BeTrue; $a.b | Should -BeTrue; $a.x | Should -BeFalse
        $script:Model.Nodes[(Id 'IT-Staff')].p | Should -BeFalse
        $script:Model.Nodes[(Id 'IT-Staff')].x | Should -BeTrue
    }
    It 'serialises to JSON that parses back, with flags' {
        $j = ConvertFrom-Json (ConvertTo-NestJson -Model $script:Model)
        @($j.nodes).Count | Should -Be 3
        $j.flags.nestedExpanded | Should -BeTrue
        $j.flags.capReached | Should -BeFalse
        @($j.up[(Id 'IT-Staff')]) | Should -Be @((Id 'IT-Admins'))
    }
    It 'escapes hostile names' {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN 'CN=P,DC=x' -ChildDN 'CN=C,DC=x'
        $nodes = @{
            'CN=P,DC=x' = [PSCustomObject]@{ DN = 'CN=P,DC=x'; Name = '</script><img src=x onerror=alert(1)>'; Sam = ''; Category = ''; Scope = ''; Sid = ''; InExport = $true; Unresolved = $false }
            'CN=C,DC=x' = [PSCustomObject]@{ DN = 'CN=C,DC=x'; Name = '"q"'; Sam = ''; Category = ''; Scope = ''; Sid = ''; InExport = $true; Unresolved = $false }
        }
        $json = ConvertTo-NestJson -Model (ConvertTo-NestModel -Graph ([PSCustomObject]@{ Nodes = $nodes; CapReached = $true }) -Edges $edges)
        $json | Should -Not -Match '<'
        (ConvertFrom-Json $json).flags.capReached | Should -BeTrue
        @((ConvertFrom-Json $json).nodes | ForEach-Object { $_.n }) | Should -Contain '</script><img src=x onerror=alert(1)>'
    }
}
```

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement**

```powershell
function ConvertTo-NestModel {
    <#
        Compact nesting data for the Nesting tab: only groups with at least one group-in-group
        link, indexed, with direct parents (Up) and direct children (Down). Loops, depth and
        paths are worked out in the browser (NestCore).
    #>
    param(
        [Parameter(Mandatory)]$Graph,
        [Parameter(Mandatory)][hashtable]$Edges,
        [switch]$NestedExpanded
    )

    $involved = @{}
    foreach ($parent in [string[]]$Edges.Keys) {
        $involved[$parent] = $true
        foreach ($child in [string[]]$Edges[$parent].Keys) { $involved[$child] = $true }
    }

    $dns = [string[]]($involved.Keys | Sort-Object {
        if ($Graph.Nodes.ContainsKey($_)) { $Graph.Nodes[$_].Name } else { $_ }
    })
    $ids = @{}
    $nodesOut = New-Object System.Collections.Generic.List[object]
    foreach ($dn in $dns) {
        $ids[$dn] = $nodesOut.Count
        $n = if ($Graph.Nodes.ContainsKey($dn)) { $Graph.Nodes[$dn] } else {
            [PSCustomObject]@{ DN = $dn; Name = (Get-DnFirstValue $dn); Sam = ''; Category = ''; Scope = ''; Sid = ''; InExport = $false; Unresolved = $true }
        }
        $nodesOut.Add([PSCustomObject]@{
            n  = [string]$n.Name
            s  = [string]$n.Sam
            c  = [string]$n.Category
            sc = [string]$n.Scope
            ou = ConvertTo-OuPath $dn
            x  = [bool]$n.InExport
            p  = (Test-ProtectedGroupSid $n.Sid)
            b  = (Test-BuiltinGroup -DistinguishedName $dn -Sid $n.Sid)
            u  = [bool]$n.Unresolved
        })
    }

    $up = New-Object 'object[]' $nodesOut.Count
    $down = New-Object 'object[]' $nodesOut.Count
    for ($i = 0; $i -lt $nodesOut.Count; $i++) {
        $up[$i] = New-Object System.Collections.Generic.List[int]
        $down[$i] = New-Object System.Collections.Generic.List[int]
    }
    foreach ($parent in [string[]]$Edges.Keys) {
        foreach ($child in [string[]]$Edges[$parent].Keys) {
            $down[$ids[$parent]].Add($ids[$child])
            $up[$ids[$child]].Add($ids[$parent])
        }
    }
    for ($i = 0; $i -lt $nodesOut.Count; $i++) {
        $up[$i] = $up[$i].ToArray()
        $down[$i] = $down[$i].ToArray()
    }

    return [PSCustomObject]@{
        Nodes = $nodesOut.ToArray(); Up = $up; Down = $down
        NestedExpanded = [bool]$NestedExpanded; CapReached = [bool]$Graph.CapReached
    }
}

function ConvertTo-NestJson {
    # Serialises ConvertTo-NestModel output; strings via ConvertTo-JsonText (safe in <script>).
    param([Parameter(Mandatory)]$Model)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"nodes":[')
    for ($i = 0; $i -lt $Model.Nodes.Count; $i++) {
        $n = $Model.Nodes[$i]
        if ($i) { [void]$sb.Append(',') }
        [void]$sb.Append('{"n":').Append((ConvertTo-JsonText $n.n))
        [void]$sb.Append(',"s":').Append((ConvertTo-JsonText $n.s))
        [void]$sb.Append(',"c":').Append((ConvertTo-JsonText $n.c))
        [void]$sb.Append(',"sc":').Append((ConvertTo-JsonText $n.sc))
        [void]$sb.Append(',"ou":').Append((ConvertTo-JsonText $n.ou))
        foreach ($flag in 'x', 'p', 'b', 'u') {
            [void]$sb.Append(',"').Append($flag).Append('":').Append($(if ($n.$flag) { 'true' } else { 'false' }))
        }
        [void]$sb.Append('}')
    }
    [void]$sb.Append('],"up":[')
    for ($i = 0; $i -lt $Model.Up.Count; $i++) {
        if ($i) { [void]$sb.Append(',') }
        [void]$sb.Append('[').Append(([string[]]$Model.Up[$i] -join ',')).Append(']')
    }
    [void]$sb.Append('],"down":[')
    for ($i = 0; $i -lt $Model.Down.Count; $i++) {
        if ($i) { [void]$sb.Append(',') }
        [void]$sb.Append('[').Append(([string[]]$Model.Down[$i] -join ',')).Append(']')
    }
    [void]$sb.Append('],"flags":{"nestedExpanded":').Append($(if ($Model.NestedExpanded) { 'true' } else { 'false' }))
    [void]$sb.Append(',"capReached":').Append($(if ($Model.CapReached) { 'true' } else { 'false' })).Append('}}')
    return $sb.ToString()
}
```

- [ ] **Step 4: Run to verify they pass** (both editions).
- [ ] **Step 5: Commit** — `git commit -m "feat: nesting model and safe JSON for the report"`

---

### Task 4: `NestCore` browser logic (loops, depth, trees, paths)

**Files:**
- Modify: `Export-ADGroupMembership.ps1` (new `Get-NestCoreScript` after `Get-OverlapCoreScript`)
- Test: `Tests/NestCore.Tests.ps1` (new; Node harness, skipped without Node)

**Interfaces:**
- Produces (JS, global `NestCore`, also `module.exports`):
  - `analyze(nest)` → `{ comp: int[], inLoop: bool[], selfLoop: bool[], upDepth: int[], downDepth: int[], chain: int[], toProtected: bool[], loops: int, deepest: int }`
  - `tree(nest, id, dir, maxChildren)` → `{ id, level, kind: 'node'|'loop'|'seen', children: [...], more: int }` (`dir` = `'up'` or `'down'`)
  - `paths(nest, id, dir, limit)` → `{ list: [ { ids: int[], loop: bool } ], more: int, capped: bool }` — `ids` start at `id`; a loop path's last id is the repeated group.
- `Get-NestCoreScript` → string.

- [ ] **Step 1: Write the failing test**

```powershell
<#
    Unit tests for the Nesting tab's browser logic (NestCore), run with Node.js against the
    exact JavaScript the report embeds. Skipped when Node is not installed.
#>
BeforeDiscovery { $script:NoNode = -not (Get-Command node -ErrorAction SilentlyContinue) }

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Export-ADGroupMembership.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $script:Work = Join-Path $TestDrive 'js'
    $null = New-Item -ItemType Directory -Path $script:Work -Force
    [System.IO.File]::WriteAllText((Join-Path $script:Work 'nest-core.js'), (Get-NestCoreScript))
}

Describe 'NestCore (Node)' -Skip:$script:NoNode {
    It 'passes the assertion suite' {
        $harness = @'
var assert = require('assert');
var N = require('./nest-core.js');
function nest(names, edges, prot) {   // edges: [parent, child]
  var n = { nodes: [], up: [], down: [], flags: { nestedExpanded: true, capReached: false } }, i;
  for (i = 0; i < names.length; i++) { n.nodes.push({ n: names[i], s: names[i], x: true, p: !!(prot && prot[i]), b: false, u: false }); n.up.push([]); n.down.push([]); }
  for (i = 0; i < edges.length; i++) { n.down[edges[i][0]].push(edges[i][1]); n.up[edges[i][1]].push(edges[i][0]); }
  return n;
}
// 0 Admins(protected) <- 1 IT-Admins <- 2 IT-Staff <- 3 Helpdesk ; 4 VPN <- 3 ; 3 -> 5 Tier1 -> 6 Contractors -> 3 (loop)
var d = nest(['Admins','IT-Admins','IT-Staff','Helpdesk','VPN','Tier1','Contractors'],
  [[0,1],[1,2],[2,3],[4,3],[3,5],[5,6],[6,3]], [true]);
var a = N.analyze(d);
assert.strictEqual(a.loops, 1);
assert.ok(a.inLoop[3] && a.inLoop[5] && a.inLoop[6]);
assert.ok(!a.inLoop[2]);
assert.strictEqual(a.upDepth[0], 0);
assert.strictEqual(a.upDepth[2], 2);
assert.strictEqual(a.upDepth[3], 3, 'loop members collapse to one level');
assert.ok(a.toProtected[3] && a.toProtected[1] && !a.toProtected[0] && !a.toProtected[4]);
assert.strictEqual(a.deepest, 3);

// Upward tree from Helpdesk: IT-Staff -> IT-Admins -> Admins, and VPN; Contractors is a parent too (loop)
var up = N.tree(d, 3, 'up', 50);
var names = up.children.map(function (c) { return d.nodes[c.id].n + ':' + c.kind; });
assert.deepStrictEqual(names.sort(), ['Contractors:node', 'IT-Staff:node', 'VPN:node']);
var contractors = up.children.filter(function (c) { return d.nodes[c.id].n === 'Contractors'; })[0];
assert.strictEqual(contractors.children[0].kind, 'node', 'Tier1 above Contractors');
assert.strictEqual(contractors.children[0].children[0].kind, 'loop', 'Tier1 is inside Helpdesk again: loop');
var deepest = up.children.filter(function (c) { return d.nodes[c.id].n === 'IT-Staff'; })[0].children[0].children[0];
assert.strictEqual(d.nodes[deepest.id].n, 'Admins');
assert.strictEqual(deepest.level, 3);

// Downward tree: Tier1 -> Contractors -> loop back to Helpdesk
var down = N.tree(d, 3, 'down', 50);
assert.strictEqual(down.children[0].children[0].children[0].kind, 'loop');
assert.strictEqual(down.children[0].children[0].children[0].id, 3);

// Self-loop
var s = nest(['Self'], [[0,0]]);
var sa = N.analyze(s);
assert.strictEqual(sa.loops, 1);
assert.ok(sa.selfLoop[0] && sa.inLoop[0]);
assert.strictEqual(N.tree(s, 0, 'down', 50).children[0].kind, 'loop');

// Diamond: Top -> L, Top -> R, L -> Bottom, R -> Bottom ; upward from Bottom shows Top twice? second is 'seen'
var dm = nest(['Top','L','R','Bottom'], [[0,1],[0,2],[1,3],[2,3]]);
var dt = N.tree(dm, 3, 'up', 50);
var kinds = [dt.children[0].children[0].kind, dt.children[1].children[0].kind].sort();
assert.deepStrictEqual(kinds, ['node', 'seen']);

// More than 50 children
var wideNames = ['Parent'], wideEdges = [], i;
for (i = 1; i <= 60; i++) { wideNames.push('C' + (i < 10 ? '0' : '') + i); wideEdges.push([0, i]); }
var w = N.tree(nest(wideNames, wideEdges), 0, 'down', 50);
assert.strictEqual(w.children.length, 50);
assert.strictEqual(w.more, 10);

// 10-deep chain
var chainNames = [], chainEdges = [];
for (i = 0; i < 11; i++) { chainNames.push('L' + i); if (i) { chainEdges.push([i - 1, i]); } }
var ch = nest(chainNames, chainEdges);
var ca = N.analyze(ch);
assert.strictEqual(ca.upDepth[10], 10);
assert.strictEqual(ca.deepest, 10);
var cp = N.paths(ch, 10, 'up', 100);
assert.strictEqual(cp.list.length, 1);
assert.strictEqual(cp.list[0].ids.length, 11);

// Paths with a loop and a limit
var lp = N.paths(d, 3, 'down', 100);
assert.strictEqual(lp.list.length, 1);
assert.ok(lp.list[0].loop);
assert.deepStrictEqual(lp.list[0].ids, [3, 5, 6, 3]);
var upPaths = N.paths(d, 3, 'up', 100);
assert.strictEqual(upPaths.list.length, 3);
var limited = N.paths(nest(wideNames, wideEdges), 0, 'down', 5);
assert.strictEqual(limited.list.length, 5);
assert.strictEqual(limited.more, 55);
assert.deepStrictEqual(N.paths(nest(['Solo'], []), 0, 'up', 100).list, []);
console.log('OK');
'@
        $path = Join-Path $script:Work 'harness.js'
        [System.IO.File]::WriteAllText($path, $harness)
        $out = & node $path 2>&1 | Out-String
        $out | Should -Match 'OK'
        $LASTEXITCODE | Should -Be 0 -Because $out
    }
}
```

- [ ] **Step 2: Run to verify it fails** — Expected: `Get-NestCoreScript` not recognized.

- [ ] **Step 3: Implement**

```powershell
function Get-NestCoreScript {
    <#
        Nesting-tab logic as browser JavaScript with no DOM access, unit-tested with Node
        (Tests\NestCore.Tests.ps1). ES5 only, for Internet Explorer on Server 2012 / 2012 R2.

        Loops are found as strongly connected components (Tarjan). Depth is measured on the
        graph with each loop collapsed to one node, so a longest chain is well defined even
        when groups loop. Trees mark a group already on the current branch as a loop and a
        group already expanded elsewhere in the same tree as "shown above", which keeps
        cross-nested domains from multiplying.
    #>
    return @'
var NestCore = (function () {
  'use strict';

  function byName(nest) { return function (a, b) { var x = nest.nodes[a].n.toLowerCase(), y = nest.nodes[b].n.toLowerCase(); return x < y ? -1 : (x > y ? 1 : a - b); }; }

  function analyze(nest) {
    var n = nest.nodes.length, index = [], low = [], onStack = [], stack = [], comp = [], counter = 0, compCount = 0, i;
    for (i = 0; i < n; i++) { index.push(-1); low.push(0); onStack.push(false); comp.push(-1); }
    function strong(v) {
      var j, w;
      index[v] = low[v] = counter++; stack.push(v); onStack[v] = true;
      for (j = 0; j < nest.down[v].length; j++) {
        w = nest.down[v][j];
        if (index[w] === -1) { strong(w); low[v] = Math.min(low[v], low[w]); }
        else if (onStack[w]) { low[v] = Math.min(low[v], index[w]); }
      }
      if (low[v] === index[v]) {
        do { w = stack.pop(); onStack[w] = false; comp[w] = compCount; } while (w !== v);
        compCount++;
      }
    }
    for (i = 0; i < n; i++) { if (index[i] === -1) { strong(i); } }

    var size = [], selfLoop = [], inLoop = [], loops = 0, c;
    for (c = 0; c < compCount; c++) { size.push(0); }
    for (i = 0; i < n; i++) { size[comp[i]]++; selfLoop.push(indexOfInt(nest.down[i], i) > -1); }
    var loopComp = [];
    for (c = 0; c < compCount; c++) { loopComp.push(size[c] > 1); }
    for (i = 0; i < n; i++) { if (selfLoop[i]) { loopComp[comp[i]] = true; } }
    for (c = 0; c < compCount; c++) { if (loopComp[c]) { loops++; } }
    for (i = 0; i < n; i++) { inLoop.push(loopComp[comp[i]]); }

    // Component DAG edges, deduplicated.
    var cUp = [], cDown = [], cProt = [], seen = {}, a, b, key;
    for (c = 0; c < compCount; c++) { cUp.push([]); cDown.push([]); cProt.push(false); }
    for (i = 0; i < n; i++) {
      if (nest.nodes[i].p) { cProt[comp[i]] = true; }
      for (var j = 0; j < nest.down[i].length; j++) {
        a = comp[i]; b = comp[nest.down[i][j]];
        if (a === b) { continue; }
        key = a + '|' + b;
        if (!seen[key]) { seen[key] = true; cDown[a].push(b); cUp[b].push(a); }
      }
    }
    var memoUp = [], memoDown = [], memoProt = [];
    for (c = 0; c < compCount; c++) { memoUp.push(-1); memoDown.push(-1); memoProt.push(-1); }
    function depthUp(cc) {
      if (memoUp[cc] > -1) { return memoUp[cc]; }
      var best = 0, k;
      for (k = 0; k < cUp[cc].length; k++) { best = Math.max(best, 1 + depthUp(cUp[cc][k])); }
      memoUp[cc] = best; return best;
    }
    function depthDown(cc) {
      if (memoDown[cc] > -1) { return memoDown[cc]; }
      var best = 0, k;
      for (k = 0; k < cDown[cc].length; k++) { best = Math.max(best, 1 + depthDown(cDown[cc][k])); }
      memoDown[cc] = best; return best;
    }
    function protAbove(cc) {
      if (memoProt[cc] > -1) { return memoProt[cc] === 1; }
      var hit = false, k;
      for (k = 0; k < cUp[cc].length && !hit; k++) { hit = cProt[cUp[cc][k]] || protAbove(cUp[cc][k]); }
      memoProt[cc] = hit ? 1 : 0; return hit;
    }
    var upDepth = [], downDepth = [], chain = [], toProtected = [], deepest = 0;
    for (i = 0; i < n; i++) {
      upDepth.push(depthUp(comp[i])); downDepth.push(depthDown(comp[i]));
      chain.push(upDepth[i] + downDepth[i]);
      deepest = Math.max(deepest, chain[i]);
      // Inside a protected group, or in a loop together with one.
      toProtected.push(protAbove(comp[i]) || (loopComp[comp[i]] && cProt[comp[i]] && !nest.nodes[i].p));
    }
    return { comp: comp, inLoop: inLoop, selfLoop: selfLoop, upDepth: upDepth, downDepth: downDepth,
             chain: chain, toProtected: toProtected, loops: loops, deepest: deepest };
  }

  function indexOfInt(arr, v) { var i; for (i = 0; i < arr.length; i++) { if (arr[i] === v) { return i; } } return -1; }

  function tree(nest, id, dir, maxChildren) {
    var edges = dir === 'up' ? nest.up : nest.down, onPath = {}, expanded = {}, sorter = byName(nest);
    function build(v, level) {
      var node = { id: v, level: level, kind: 'node', children: [], more: 0 }, list = edges[v].slice(0).sort(sorter), i, c;
      onPath[v] = true; expanded[v] = true;
      for (i = 0; i < list.length && i < maxChildren; i++) {
        c = list[i];
        if (onPath[c]) { node.children.push({ id: c, level: level + 1, kind: 'loop', children: [], more: 0 }); }
        else if (expanded[c]) { node.children.push({ id: c, level: level + 1, kind: 'seen', children: [], more: 0 }); }
        else { node.children.push(build(c, level + 1)); }
      }
      if (list.length > maxChildren) { node.more = list.length - maxChildren; }
      onPath[v] = false;
      return node;
    }
    return build(id, 0);
  }

  // Complete routes from id to a top (dir 'up') or bottom (dir 'down') group. Counting stops
  // at 10,000 so a heavily cross-nested domain cannot hang the page.
  function paths(nest, id, dir, limit) {
    var edges = dir === 'up' ? nest.up : nest.down, out = { list: [], more: 0, capped: false }, onPath = {}, route = [], total = 0;
    function record(isLoop) {
      total++;
      if (out.list.length < limit) { out.list.push({ ids: route.slice(0), loop: isLoop }); } else { out.more++; }
      if (total >= 10000) { out.capped = true; }
    }
    function walk(v) {
      var next = edges[v], i, c;
      route.push(v); onPath[v] = true;
      if (!next.length && route.length > 1) { record(false); }
      for (i = 0; i < next.length && !out.capped; i++) {
        c = next[i];
        if (onPath[c]) { route.push(c); record(true); route.pop(); }
        else { walk(c); }
      }
      onPath[v] = false; route.pop();
    }
    walk(id);
    return out;
  }

  return { analyze: analyze, tree: tree, paths: paths };
}());
if (typeof module !== 'undefined' && module.exports) { module.exports = NestCore; }
'@
}
```

- [ ] **Step 4: Run to verify it passes** (both editions, Node present).
- [ ] **Step 5: Commit** — `git commit -m "feat: NestCore - loops, depth, trees and paths for the Nesting tab"`

---

### Task 5: Nesting tab in the HTML (layout, UI script, cross-links)

**Files:**
- Modify: `Export-ADGroupMembership.ps1` — `New-UserAccessHtml` (new `-NestModel` parameter, tab button, section, data block, scripts, CSS); the main UI script (`showTab`, Groups detail link, Overlap *Contains* link)
- Test: `Tests/GroupAccessModel.Tests.ps1` (append HTML tests), `Tests/OverlapCore.Tests.ps1` ('Report scripts' covers the new block automatically once a nest model is passed — update its BeforeAll)

**Interfaces:**
- Consumes: `ConvertTo-NestModel`, `ConvertTo-NestJson`, `Get-NestCoreScript`, `NestCore`.
- Produces: `New-UserAccessHtml … [-NestModel <object>]`; page globals `window.showNesting(sam)` and `window.nestSummaryFor(sam)` → `{ up: int, down: int } | null`; element ids `tab-nesting`, `tb-nesting`, `nest-data`, `nsum`, `nq`, `nloops`, `nprot`, `nsort`, `nlist`, `ndetail`.

- [ ] **Step 1: Write the failing tests** (append to `GroupAccessModel.Tests.ps1`)

```powershell
Describe 'New-UserAccessHtml with a nesting model' {
    BeforeAll {
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN 'CN=P,DC=x' -ChildDN 'CN=C,DC=x'
        $nodes = @{
            'CN=P,DC=x' = [PSCustomObject]@{ DN = 'CN=P,DC=x'; Name = '</script><img src=x onerror=alert(1)>'; Sam = 'P'; Category = 'Security'; Scope = 'Global'; Sid = 'S-1-5-32-544'; InExport = $false; Unresolved = $false }
            'CN=C,DC=x' = [PSCustomObject]@{ DN = 'CN=C,DC=x'; Name = 'Child'; Sam = 'C'; Category = 'Security'; Scope = 'Global'; Sid = ''; InExport = $true; Unresolved = $false }
        }
        $nest = ConvertTo-NestModel -Graph ([PSCustomObject]@{ Nodes = $nodes; CapReached = $false }) -Edges $edges -NestedExpanded
        $model = ConvertTo-GroupAccessModel -Rows $script:Rows -Groups $script:Groups
        $script:NestHtml = New-UserAccessHtml -Users @() -DomainName 'contoso.com' -ScopeNote 'test' -NestedExpanded `
            -GroupsProcessed 5 -GroupModel $model -NestModel $nest
    }
    It 'adds the Nesting tab and its data' {
        $script:NestHtml | Should -Match 'id="tb-nesting"'
        $script:NestHtml | Should -Match 'id="tab-nesting"'
        $m = [regex]::Match($script:NestHtml, '<script type="application/json" id="nest-data">(.*?)</script>', 'Singleline')
        $m.Success | Should -BeTrue
        @((ConvertFrom-Json $m.Groups[1].Value).nodes).Count | Should -Be 2
    }
    It 'cannot be broken out of by a hostile group name' {
        # people, group data, nest data, overlap core, nest core, overlap UI, nest UI
        ([regex]::Matches($script:NestHtml, '</script>')).Count | Should -Be 7
        $script:NestHtml | Should -Not -Match '<img src=x'
    }
    It 'omits the tab when no nesting model is passed' {
        $html = New-UserAccessHtml -Users @() -DomainName 'contoso.com' -ScopeNote 'test' -GroupsProcessed 0
        $html | Should -Not -Match 'tab-nesting'
    }
}
```

In `Tests/OverlapCore.Tests.ps1`, `Describe 'Report scripts'` BeforeAll: build a one-edge nest model the same way and pass `-NestModel $nest`; change the expected count in `'generates the three executable script blocks'` to **5** (people, overlap core, nest core, overlap UI, nest UI) and rename the test to `'generates the executable script blocks'`.

- [ ] **Step 2: Run to verify they fail** — Expected: parameter `NestModel` not found.

- [ ] **Step 3: Implement**

3a. `New-UserAccessHtml` parameter (after `$GroupModel`):

```powershell
        # From ConvertTo-NestModel. When omitted (or empty) there is no Nesting tab.
        $NestModel
```
and after `$hasGroups = …`:
```powershell
    $hasNest = $hasGroups -and $null -ne $NestModel -and $NestModel.Nodes.Count -gt 0
```

3b. Tab button, after the Overlap button inside `if ($hasGroups)`:
```powershell
        if ($hasNest) {
            $null = $sb.AppendLine("<button class=""tabbtn"" id=""tb-nesting"" onclick=""showTab('nesting')"">Nesting<span class=""cnt"">$($NestModel.Nodes.Count)</span></button>")
        }
```

3c. CSS (append before `@media(max-width:760px){`):
```css
/* ---- Nesting tab ---- */
.nsum{display:flex;gap:26px;flex-wrap:wrap;margin-bottom:14px}
.nsum .stat{cursor:default}.nsum .stat.click{cursor:pointer}.nsum .stat.click:hover .l{color:var(--accent)}
.mk.loop{background:var(--warn-bg);border-color:var(--warn-line);color:var(--warn);font-weight:600}
.mk.prot{border-color:var(--warn-line);color:var(--warn)}
.gl-item.ext .nm2{font-style:italic;color:var(--muted)}
.tree{font-family:var(--mono);font-size:12.5px;line-height:1.9;margin:4px 0 14px}
.tree .row{display:flex;align-items:center;gap:8px;white-space:nowrap}
.tree .lv{color:var(--dim);font-size:11px;margin-left:auto;padding-left:20px}
.tree .glyph{color:var(--accent-dim)}
.nlink{cursor:pointer;border-bottom:1px dotted var(--accent-dim)}.nlink:hover{color:var(--accent)}
.nlink.sel{background:var(--accent);color:#0d1116;border-radius:3px;padding:0 5px;font-weight:700;border:0}
.nlink.ext{border:1px dashed var(--dim);border-radius:3px;padding:0 4px;font-style:italic}
.nlink.prot{color:var(--warn)}
.tree .loopm{color:var(--warn);font-weight:700}.tree .seen{color:var(--dim)}
.npath{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:5px 9px;background:var(--panel);border:1px solid var(--line);border-radius:5px;margin-bottom:5px;font-size:12.5px}
.npath .sep{color:var(--accent-dim)}
.npath .badge3{margin-left:auto;font-size:10px;padding:1px 7px;border-radius:9px;border:1px solid var(--warn-line);background:var(--warn-bg);color:var(--warn);font-weight:600}
.notice{font-size:12.5px;color:var(--muted);border-left:3px solid var(--warn);background:var(--warn-bg);padding:7px 10px;border-radius:4px;margin-bottom:10px}
```

3d. Section, inside `if ($hasGroups)` after the Overlap section here-string:
```powershell
        if ($hasNest) {
            $null = $sb.AppendLine(@'
<section class="tabpane" id="tab-nesting">
<div class="nsum" id="nsum"></div>
<div class="fbar" style="display:flex">
<input type="search" id="nq" placeholder="Filter groups by name...">
<label class="chk" style="display:flex"><input type="checkbox" id="nloops"> Only loops</label>
<label class="chk" style="display:flex"><input type="checkbox" id="nprot"> Only nested into protected groups</label>
<select id="nsort"><option value="deep">Sort: deepest chain first</option><option value="name">Sort: name</option></select>
</div>
<div class="gl-wrap"><div class="gl-list" id="nlist"></div><div class="gd" id="ndetail"></div></div>
</section>
'@)
        }
```

3e. Data + scripts, after the existing UI script inside `if ($hasGroups)`:
```powershell
        if ($hasNest) {
            $null = $sb.Append('<script type="application/json" id="nest-data">')
            $null = $sb.Append((ConvertTo-NestJson -Model $NestModel))
            $null = $sb.AppendLine('</script>')
            $null = $sb.AppendLine('<script>')
            $null = $sb.AppendLine((Get-NestCoreScript))
            $null = $sb.AppendLine('</script>')
            $null = $sb.AppendLine((Get-NestUiScript))
        }
```
Move the existing `<script type="application/json" id="report-data">`, overlap core and overlap UI emission so the order is: report-data, nest-data, overlap core, nest core, overlap UI, nest UI (nest UI defines `window.showNesting`/`nestSummaryFor`, used lazily by the overlap UI).

3f. `Get-NestUiScript` (new function next to `Get-NestCoreScript`):
```powershell
function Get-NestUiScript {
    # Nesting-tab rendering. ES5 (see Get-NestCoreScript). Uses eachEl/hasCls/setCls from
    # the People script and esc-style escaping of its own.
    return @'
<script>
(function () {
  var el = document.getElementById('nest-data');
  if (!el) { return; }
  var nest = JSON.parse(el.text || el.textContent);
  var A = NestCore.analyze(nest), MAX_CHILDREN = 50, MAX_PATHS = 100;
  var st = { q: '', loops: false, prot: false, sort: 'deep', sel: -1 }, timer = null;
  var bySam = {}, i;
  for (i = 0; i < nest.nodes.length; i++) { if (nest.nodes[i].s) { bySam[nest.nodes[i].s.toLowerCase()] = i; } }

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s === null || s === undefined ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function name(id) { return nest.nodes[id].n; }
  function link(id, extra) {
    var n = nest.nodes[id], cls = 'nlink' + (n.x ? '' : ' ext') + (n.p ? ' prot' : '') + (extra || '');
    return '<span class="' + cls + '" data-n="' + id + '" title="' + esc(n.n) + (n.x ? '' : ' (not in export)') + (n.p ? ' - protected group' : '') + '">' + esc(n.n) + '</span>';
  }
  function levels(n) { return n + ' level' + (n === 1 ? '' : 's'); }

  function renderSummary() {
    var prot = 0, j;
    for (j = 0; j < nest.nodes.length; j++) { if (A.toProtected[j]) { prot++; } }
    $('nsum').innerHTML =
      '<div class="stat"><div class="n">' + nest.nodes.length + '</div><div class="l">Groups in nesting</div></div>' +
      '<div class="stat"><div class="n">' + A.deepest + '</div><div class="l">Deepest chain (levels)</div></div>' +
      '<div class="stat click' + (A.loops ? ' alert' : '') + '" data-f="loops" title="Show only groups in a loop"><div class="n">' + A.loops + '</div><div class="l">Loops</div></div>' +
      '<div class="stat click' + (prot ? ' alert' : '') + '" data-f="prot" title="Show only groups nested into protected groups"><div class="n">' + prot + '</div><div class="l">Nested into protected groups</div></div>';
  }

  function renderList() {
    var ids = [], j, html = [], n;
    for (j = 0; j < nest.nodes.length; j++) {
      if (st.q && nest.nodes[j].n.toLowerCase().indexOf(st.q) < 0) { continue; }
      if (st.loops && !A.inLoop[j]) { continue; }
      if (st.prot && !A.toProtected[j]) { continue; }
      ids.push(j);
    }
    ids.sort(function (a, b) {
      if (st.sort === 'deep' && A.chain[b] !== A.chain[a]) { return A.chain[b] - A.chain[a]; }
      var x = name(a).toLowerCase(), y = name(b).toLowerCase(); return x < y ? -1 : (x > y ? 1 : 0);
    });
    if (st.sel < 0 || (ids.length && indexOfInt(ids, st.sel) < 0 && !st.pinned)) { st.sel = ids.length ? ids[0] : -1; }
    for (j = 0; j < ids.length; j++) {
      n = nest.nodes[ids[j]];
      html.push('<div class="gl-item' + (ids[j] === st.sel ? ' on' : '') + (n.x ? '' : ' ext') + '" data-n="' + ids[j] + '">' +
        '<span class="nm2" title="' + esc(n.n) + '">' + esc(n.n) + '</span>' +
        (A.inLoop[ids[j]] ? '<span class="mk loop">loop</span>' : '') +
        (A.toProtected[ids[j]] ? '<span class="mk prot">&rarr; protected</span>' : '') +
        '<span class="n">' + levels(A.chain[ids[j]]) + '</span></div>');
    }
    if (!ids.length) { html.push('<div class="hint">No groups match this filter.</div>'); }
    $('nlist').innerHTML = html.join('');
    renderDetail();
  }

  function indexOfInt(arr, v) { var k; for (k = 0; k < arr.length; k++) { if (arr[k] === v) { return k; } } return -1; }

  function treeHtml(node, out) {
    var k, pad = node.level * 22, glyph = node.level ? '<span class="glyph">&#9492;&#9472;</span> ' : '';
    if (node.kind === 'loop') {
      out.push('<div class="row" style="padding-left:' + pad + 'px">' + glyph + '<span class="loopm">&#8635; ' + esc(name(node.id)) + ' &mdash; loops back</span><span class="lv">level ' + node.level + '</span></div>');
      return;
    }
    if (node.kind === 'seen') {
      out.push('<div class="row" style="padding-left:' + pad + 'px">' + glyph + link(node.id) + ' <span class="seen">&#8599; shown above</span><span class="lv">level ' + node.level + '</span></div>');
      return;
    }
    out.push('<div class="row" style="padding-left:' + pad + 'px">' + glyph + link(node.id, node.level ? '' : ' sel') +
      (node.level ? '<span class="lv">level ' + node.level + '</span>' : '') + '</div>');
    for (k = 0; k < node.children.length; k++) { treeHtml(node.children[k], out); }
    if (node.more) { out.push('<div class="row seen" style="padding-left:' + (pad + 22) + 'px">+ ' + node.more + ' more</div>'); }
  }

  function pathHtml(p, dir) {
    var ids = dir === 'up' ? p.ids.slice(0).reverse() : p.ids, parts = [], k;
    for (k = 0; k < ids.length; k++) {
      var isLast = k === ids.length - 1, loopEnd = p.loop && ((dir === 'down' && isLast) || (dir === 'up' && k === 0));
      parts.push(loopEnd ? '<span class="loopm">&#8635; ' + esc(name(ids[k])) + '</span>' : link(ids[k], ids[k] === st.sel ? ' sel' : ''));
    }
    return '<div class="npath">' + parts.join('<span class="sep">&rsaquo;</span>') + (p.loop ? '<span class="badge3">LOOP</span>' : '') + '</div>';
  }

  function pathText(p, dir) {
    var ids = dir === 'up' ? p.ids.slice(0).reverse() : p.ids, parts = [], k;
    for (k = 0; k < ids.length; k++) { parts.push(name(ids[k])); }
    return '  ' + parts.join(' > ') + (p.loop ? '  (loop)' : '');
  }

  function renderDetail() {
    var d = $('ndetail');
    if (st.sel < 0) { d.innerHTML = '<div class="hint">No group selected.</div>'; return; }
    var n = nest.nodes[st.sel], h = [], up = NestCore.tree(nest, st.sel, 'up', MAX_CHILDREN), down = NestCore.tree(nest, st.sel, 'down', MAX_CHILDREN);
    var pu = NestCore.paths(nest, st.sel, 'up', MAX_PATHS), pd = NestCore.paths(nest, st.sel, 'down', MAX_PATHS), k;
    if (nest.flags.capReached) { h.push('<div class="notice">Upward chains may be incomplete: the export stopped looking up parent groups at its limit.</div>'); }
    h.push('<h2>' + esc(n.n) + '</h2>');
    h.push('<div class="badges">' +
      (n.p ? '<span class="badge2 dup">Protected group</span>' : '') +
      (n.b && !n.p ? '<span class="badge2">Built-in</span>' : '') +
      (n.x ? '' : '<span class="badge2">Not in the export &mdash; fetched to complete the chain</span>') +
      (n.u ? '<span class="badge2">Could not be read from AD</span>' : '') +
      (A.inLoop[st.sel] ? '<span class="badge2 dup">Part of a loop</span>' : '') + '</div>');
    h.push('<div class="kv">' + (n.c ? '<b>Type</b><span>' + esc(n.c) + ' &middot; ' + esc(n.sc) + '</span>' : '') +
      (n.ou ? '<b>Where</b><span>' + esc(n.ou) + '</span>' : '') +
      '<b>Chain</b><span>' + levels(A.upDepth[st.sel]) + ' above, ' + levels(A.downDepth[st.sel]) + ' below</span></div>');
    h.push('<div class="h3">Is inside (its members get these groups&rsquo; access)</div><div class="tree">');
    if (up.children.length) { treeHtml(up, h); } else { h.push('<div class="seen">Not inside any other group.</div>'); }
    h.push('</div><div class="h3">Contains (members of these groups get its access)</div><div class="tree">');
    if (down.children.length) { treeHtml(down, h); } else { h.push('<div class="seen">Contains no groups.</div>'); }
    if (!nest.flags.nestedExpanded) { h.push('<div class="notice">Nested groups were not expanded in this run, so only one level down is shown. Re-run with -IncludeNested.</div>'); }
    h.push('</div><div class="h3">All paths <button class="btn" id="ncopy" style="margin-left:10px;font-size:11.5px;padding:3px 9px">Copy paths</button> <span id="ncopied" class="off"></span></div>');
    for (k = 0; k < pu.list.length; k++) { h.push(pathHtml(pu.list[k], 'up')); }
    if (pu.more) { h.push('<div class="seen">+ ' + pu.more + (pu.capped ? '+' : '') + ' more upward paths</div>'); }
    for (k = 0; k < pd.list.length; k++) { h.push(pathHtml(pd.list[k], 'down')); }
    if (pd.more) { h.push('<div class="seen">+ ' + pd.more + (pd.capped ? '+' : '') + ' more downward paths</div>'); }
    if (!pu.list.length && !pd.list.length) { h.push('<div class="seen">No paths.</div>'); }
    h.push('<p class="off" style="font-size:12px;margin-top:14px">Nesting into groups in other domains of the forest may not appear: group parents are read from the domain controller that was queried.</p>');
    d.innerHTML = h.join('');
    d.setAttribute('data-copy', copyText(pu, pd));
  }

  function copyText(pu, pd) {
    var lines = ['Nesting for ' + name(st.sel)], k;
    lines.push('Is inside:');
    for (k = 0; k < pu.list.length; k++) { lines.push(pathText(pu.list[k], 'up')); }
    if (!pu.list.length) { lines.push('  (none)'); }
    lines.push('Contains:');
    for (k = 0; k < pd.list.length; k++) { lines.push(pathText(pd.list[k], 'down')); }
    if (!pd.list.length) { lines.push('  (none)'); }
    return lines.join('\r\n');
  }

  function copy(text) {
    var ok = false, ta;
    if (window.clipboardData && window.clipboardData.setData) { ok = window.clipboardData.setData('Text', text); }
    if (!ok) {
      ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select();
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
    }
    $('ncopied').innerHTML = ok ? 'Copied.' : 'Copy blocked by the browser &mdash; select the paths and press Ctrl+C.';
  }

  function select(id) {
    st.sel = id; st.pinned = true;
    eachEl('#nlist .gl-item', function (it) { setCls(it, 'on', parseInt(it.getAttribute('data-n'), 10) === id); });
    renderDetail();
  }

  window.renderNesting = function () { renderSummary(); renderList(); };
  window.nestSummaryFor = function (sam) {
    var id = sam ? bySam[sam.toLowerCase()] : undefined;
    if (id === undefined) { return null; }
    return { up: nest.up[id].length, down: nest.down[id].length };
  };
  window.showNesting = function (sam) {
    var id = sam ? bySam[sam.toLowerCase()] : undefined;
    if (id === undefined) { return; }
    st.q = ''; $('nq').value = ''; st.loops = false; $('nloops').checked = false; st.prot = false; $('nprot').checked = false;
    st.sel = id; st.pinned = true;
    window.showTab('nesting');
  };

  $('nq').oninput = $('nq').onkeyup = function () {
    var v = this.value;
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () { st.q = v.toLowerCase().replace(/^\s+|\s+$/g, ''); st.pinned = false; renderList(); }, 200);
  };
  $('nloops').onclick = function () { st.loops = this.checked; st.pinned = false; renderList(); };
  $('nprot').onclick = function () { st.prot = this.checked; st.pinned = false; renderList(); };
  $('nsort').onchange = function () { st.sort = this.value; renderList(); };
  $('nsum').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement;
    while (t && t !== this && !(t.getAttribute && t.getAttribute('data-f'))) { t = t.parentNode; }
    if (!t || t === this) { return; }
    if (t.getAttribute('data-f') === 'loops') { st.loops = !st.loops; $('nloops').checked = st.loops; }
    else { st.prot = !st.prot; $('nprot').checked = st.prot; }
    st.pinned = false; renderList();
  };
  $('nlist').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement;
    while (t && t !== this && !(t.className && hasCls(t, 'gl-item'))) { t = t.parentNode; }
    if (t && t !== this) { select(parseInt(t.getAttribute('data-n'), 10)); }
  };
  $('ndetail').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement;
    if (t.id === 'ncopy') { copy(this.getAttribute('data-copy') || ''); return; }
    if (t.getAttribute && t.getAttribute('data-n') !== null) { select(parseInt(t.getAttribute('data-n'), 10)); }
  };
}());
</script>
'@
}
```

3g. Main UI script changes:
- `showTab`: `var tabs = ['people', 'groups', 'overlap', 'nesting']`; `fbar.style.display = (name === 'groups' || name === 'overlap') ? '' : 'none';`; move the fbar only for groups/overlap: `if (name === 'groups' || name === 'overlap') { … insertBefore … }`; keep `setCls(main, 'wide', name !== 'people')`.
- `render()`: add `else if (st.tab === 'nesting' && window.renderNesting) { window.renderNesting(); }`.
- `renderDetail()` (Groups), after the badges block:
```js
    var ns = window.nestSummaryFor ? window.nestSummaryFor(g.s) : null;
    if (ns && (ns.up || ns.down)) {
      h.push('<p style="font-size:12.5px;margin:0 0 12px">Nesting: inside ' + ns.up + ' group' + (ns.up === 1 ? '' : 's') +
        ', contains ' + ns.down + ' group' + (ns.down === 1 ? '' : 's') + ' &mdash; <button class="badge2" data-nestgo="' + esc(g.s) + '" style="cursor:pointer">View chain</button></p>');
    }
```
- `$('gdetail').onclick`: first check `if (t && t.getAttribute && t.getAttribute('data-nestgo') !== null && window.showNesting) { window.showNesting(t.getAttribute('data-nestgo')); return; }`.
- `renderPairs()`: for `p.label === 'contains'` render the label as `'<span class="lab contains" data-nestgo="' + esc(a.s) + '" title="View the nesting chain" style="cursor:pointer">Contains</span>'`.
- `$('ovbody').onclick`: first check the same `data-nestgo` handling.

- [ ] **Step 4: Run tests** — `GroupAccessModel.Tests.ps1`, `OverlapCore.Tests.ps1` (IE-syntax guard and `node --check` now include both nest scripts), both editions. Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: Nesting tab - trees, paths, loops and protected-group markers"`

---

### Task 6: Wire into the main flow; fake AD; end-to-end; README; browser check

**Files:**
- Modify: `Export-ADGroupMembership.ps1` (user-report block in main), `Tests/FakeAD/ActiveDirectory/ActiveDirectory.psm1`, `Tests/EndToEnd.Tests.ps1`, `README.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Extend the fake directory** — in `ActiveDirectory.psm1`:
  - Add groups `(Grp 'Administrators' 544 'DomainLocal' 'Security' 'CN=Builtin')` with SID `S-1-5-32-544` (override `SID` after creation), `(Grp 'IT-Admins' 1120)`, and `Chain-01` … `Chain-10` (RIDs 1201–1210).
  - Members: `'IT-Admins' = @((G 'HR-Staff'))`, `'Administrators' = @((G 'IT-Admins'))`, `'Chain-NN' = @((G 'Chain-(NN+1)'))` for 01–09, `'Chain-10' = @((U 'dave'))`.
  - After the members table, compute `MemberOf` for every group: for each `$parent` in `$script:Members.Keys`, for each member with `objectClass -eq 'group'`, add the parent's DN to that member's `MemberOf` (initialise `MemberOf = @()` in `Grp`).
  - `Get-ADGroup -Identity`: return the group whose `DistinguishedName` or `Name` equals `$Identity`; throw `"Cannot find an object with identity: '$Identity'"` when none.
  - `Get-ADGroup -Filter`: unchanged (all groups); `-ExcludeBuiltin` in the export excludes `Administrators`, so it is reached only via `memberOf` lookup.

- [ ] **Step 2: Write the failing end-to-end assertions** (append inside `Context 'report content'` of `EndToEnd.Tests.ps1`)

```powershell
        It 'embeds the nesting data, following a chain into a built-in protected group outside the export' {
            $text = [System.IO.File]::ReadAllText($script:Html.FullName)
            $m = [regex]::Match($text, '<script type="application/json" id="nest-data">(.*?)</script>', 'Singleline')
            $m.Success | Should -BeTrue
            $nest = ConvertFrom-Json $m.Groups[1].Value
            $names = @($nest.nodes | ForEach-Object { $_.n })
            $admins = [array]::IndexOf($names, 'Administrators')
            $admins | Should -BeGreaterOrEqual 0
            $nest.nodes[$admins].p | Should -BeTrue
            $nest.nodes[$admins].x | Should -BeFalse -Because 'excluded as built-in, fetched to complete the chain'
            @($nest.down[$admins]) | Should -Contain ([array]::IndexOf($names, 'IT-Admins'))
        }

        It 'records a 10-deep chain and both directions of the loop' {
            $text = [System.IO.File]::ReadAllText($script:Html.FullName)
            $nest = ConvertFrom-Json ([regex]::Match($text, '<script type="application/json" id="nest-data">(.*?)</script>', 'Singleline').Groups[1].Value)
            $names = @($nest.nodes | ForEach-Object { $_.n })
            for ($i = 1; $i -le 9; $i++) {
                $p = [array]::IndexOf($names, ('Chain-{0:D2}' -f $i)); $c = [array]::IndexOf($names, ('Chain-{0:D2}' -f ($i + 1)))
                @($nest.down[$p]) | Should -Contain $c
            }
            $a = [array]::IndexOf($names, 'Cycle-A'); $b = [array]::IndexOf($names, 'Cycle-B')
            @($nest.down[$a]) | Should -Contain $b
            @($nest.down[$b]) | Should -Contain $a
        }
```

- [ ] **Step 3: Run to verify they fail** — Expected: `nest-data` missing.

- [ ] **Step 4: Wire into main** — in the user-report `try` block, after `$groupModel = …` and before `New-UserAccessHtml`:

```powershell
            # Nesting tab: complete the group graph upward. Isolated so a failure here costs
            # only the tab, never the rest of the report.
            $nestModel = $null
            try {
                $nestGraph = Resolve-NestGraph -Groups $groups -Edges $script:NestEdges -Names $script:NestNames -Lookup {
                    param($dn)
                    Get-ADGroup -Identity $dn @ADParams -Properties MemberOf, GroupCategory, GroupScope, SID -ErrorAction Stop
                }
                $nestModel = ConvertTo-NestModel -Graph $nestGraph -Edges $script:NestEdges -NestedExpanded:$IncludeNested
                $capNote = if ($nestGraph.CapReached) { '; lookup limit reached, upward chains may be incomplete' } else { '' }
                Write-Status "Nesting: $($nestModel.Nodes.Count) group(s) involved, $($nestGraph.Lookups) extra lookup(s)$capNote."
            }
            catch {
                Write-Status "Nesting tab skipped: $($_.Exception.Message)" 'WARN'
                $script:LogLines.Add("[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARN] Stack: $($_.ScriptStackTrace -replace '\r?\n', ' <- ')")
            }
```
and pass `-NestModel $nestModel` to `New-UserAccessHtml`.

- [ ] **Step 5: Run end-to-end and all suites** (both editions): `AD-GroupMembership-Export/Tests` and `Tests`. Expected: all PASS.

- [ ] **Step 6: README** — in `AD-GroupMembership-Export/README.md`, extend the tabs table with:

```markdown
| **Nesting** | Which groups are inside which, and how deep? | Every group that is inside another group or contains one, including built-in and out-of-scope parents fetched from AD (shown dashed). Select one to see an **Is inside** tree up to the top, a **Contains** tree down to the bottom, and every complete path, with **Copy paths** for tickets. Loops are marked where they close; nesting into protected groups (Domain Admins, Administrators, …, recognised by SID) is highlighted. |
```
and a short paragraph: lookups capped at 1,000; `-IncludeNested` needed for full downward chains; cross-domain nesting may not appear.

- [ ] **Step 7: Browser check** — extend the scratch sample generator (`New-SampleReport.ps1`) to build a nest model (10-deep chain, a loop, a group nested into a protected group, a hostile name, a group with 60 child groups); serve it on 127.0.0.1; in Chrome verify: summary counts, list filters (loops / protected / search / sort), trees (levels, loop marker, shown-above, + more), path list and Copy paths, clicking names, the Groups-tab "View chain" link and the Overlap *Contains* link; no console errors.

- [ ] **Step 8: Commit and push**

```bash
git add AD-GroupMembership-Export docs
git commit -m "feat: Nesting tab in the access report"
git push
```
