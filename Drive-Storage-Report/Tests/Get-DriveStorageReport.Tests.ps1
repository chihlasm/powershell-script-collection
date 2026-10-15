<#
    Folder-walker regression tests.

    Invoke-FolderWalk was converted from [T]::new() (PowerShell 5.0+) to forms that work on
    PowerShell 3.0/4.0: New-Object for one-off objects, [Activator]::CreateInstance and a
    [DirectoryInfo] cast inside the per-folder loop, where New-Object's ~100x overhead would
    add minutes to a large scan. These tests run the real functions against a real folder
    tree and check the sizes, depths, unreadable-folder handling, and report ordering.

    The script runs a full report when executed, so its functions are extracted by AST
    rather than dot-sourcing the file.
#>

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-DriveStorageReport.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    $wanted = 'Write-Status', 'Format-Bytes', 'New-WalkState', 'Invoke-FolderWalk', 'Merge-SmallFolders', 'Sort-FolderRecords'
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        if ($wanted -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
    }

    function New-SizedFile {
        param([string]$Path, [int]$Bytes)
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force
        [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] $Bytes))
    }

    # root\A\a.bin (1000)  root\A\A1\a1.bin (2000)  root\B\b.bin (500)  root\top.bin (7)
    $script:Root = Join-Path $TestDrive 'walk'
    New-SizedFile (Join-Path $script:Root 'A\a.bin') 1000
    New-SizedFile (Join-Path $script:Root 'A\A1\a1.bin') 2000
    New-SizedFile (Join-Path $script:Root 'B\b.bin') 500
    New-SizedFile (Join-Path $script:Root 'top.bin') 7
}

Describe 'Invoke-FolderWalk' {
    BeforeAll {
        $script:State = New-WalkState
        Invoke-FolderWalk -RootPath $script:Root -MaxDepth 2 -State $script:State 6>$null
        $script:ByPath = @{}
        foreach ($r in $script:State.Records) { $script:ByPath[(Split-Path -Leaf $r.Path)] = $r }
    }

    It 'totals the root including every descendant file' {
        $script:State.RootBytes | Should -Be 3507
    }

    It 'rolls child folder sizes up into their parents' {
        $script:ByPath['A'].SizeBytes  | Should -Be 3000
        $script:ByPath['A1'].SizeBytes | Should -Be 2000
        $script:ByPath['B'].SizeBytes  | Should -Be 500
    }

    It 'records depth relative to the root and respects MaxDepth' {
        $script:ByPath['A'].Depth  | Should -Be 1
        $script:ByPath['A1'].Depth | Should -Be 2
        $script:State.Records.Count | Should -Be 3
    }

    It 'counts every folder visited, including the root' {
        $script:State.FolderCount | Should -Be 4
    }

    It 'leaves Unreadable empty when everything is readable' {
        $script:State.Unreadable.Count | Should -Be 0
    }

    It 'stops at MaxDepth 1 without losing the deeper bytes from the totals' {
        $s = New-WalkState
        Invoke-FolderWalk -RootPath $script:Root -MaxDepth 1 -State $s 6>$null
        $s.Records.Count | Should -Be 2
        (@($s.Records | Where-Object { (Split-Path -Leaf $_.Path) -eq 'A' }))[0].SizeBytes | Should -Be 3000
    }
}

Describe 'Invoke-FolderWalk with an unreadable root' {
    It 'records the folder as unreadable instead of throwing' {
        $s = New-WalkState
        $missing = Join-Path $TestDrive 'does-not-exist'
        { Invoke-FolderWalk -RootPath $missing -MaxDepth 2 -State $s 6>$null } | Should -Not -Throw
        $s.Unreadable | Should -Contain $missing
        $s.RootBytes | Should -Be 0
    }
}

Describe 'Sort-FolderRecords' {
    It 'orders largest first with each folder followed by its children' {
        $s = New-WalkState
        Invoke-FolderWalk -RootPath $script:Root -MaxDepth 2 -State $s 6>$null
        $ordered = @(Sort-FolderRecords -Records $s.Records.ToArray())
        @($ordered | ForEach-Object { Split-Path -Leaf $_.Path }) | Should -Be @('A', 'A1', 'B')
    }
}

Describe 'Merge-SmallFolders' {
    It 'folds folders under the threshold into one Misc row per parent' {
        $s = New-WalkState
        Invoke-FolderWalk -RootPath $script:Root -MaxDepth 1 -State $s 6>$null
        $merged = @(Merge-SmallFolders -Records $s.Records -ThresholdBytes 1000 -DriveRootPath $script:Root)
        @($merged | Where-Object { -not $_.IsMisc }).Count | Should -Be 1
        $misc = @($merged | Where-Object { $_.IsMisc })
        $misc.Count | Should -Be 1
        $misc[0].SizeBytes | Should -Be 500
    }
}
