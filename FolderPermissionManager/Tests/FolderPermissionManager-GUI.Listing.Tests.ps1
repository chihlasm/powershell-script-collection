<#
    Regression tests for the GUI's folder listing (Pester 5, run under pwsh).

    - Send-Json must keep a one-element array an array. Piping it into ConvertTo-Json unrolled it,
      so a folder with a single subfolder came back as an object and the page's .forEach() failed
      ("Error loading children: children.forEach is not a function").
    - A folder that can't be listed gets plain next-step text: owning it isn't enough to open it.
    - After take ownership / add / remove permission the page reloads the files list and the tree.

    The GUI is never run or launched: the functions are taken from its syntax tree. All folders are
    under $TestDrive.
#>

BeforeAll {
    $folder = Join-Path $PSScriptRoot '..'
    $script:GuiPath = (Resolve-Path (Join-Path $folder 'FolderPermissionManager-WebGUI.ps1')).Path
    $script:GuiText = Get-Content -LiteralPath $script:GuiPath -Raw
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:GuiPath, [ref]$null, [ref]$null)
    $wanted = 'Send-Json', 'Resolve-MappedDrive', 'Get-AccessDeniedMessage', 'Get-Children'
    $definitions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
        Where-Object { $wanted -contains $_.Name }
    foreach ($d in $definitions) {
        # HttpListener types have no public constructor; loosen them so stand-ins can be passed.
        $text = $d.Extent.Text -replace '\[System\.Net\.HttpListener(Response|Request)\]', '[object]'
        . ([scriptblock]::Create($text))
    }

    function New-FakeResponse {
        [PSCustomObject]@{ ContentType = $null; ContentLength64 = 0; StatusCode = 200
            OutputStream = (New-Object System.IO.MemoryStream) }
    }
    function Get-SentJson { param($Response) [System.Text.Encoding]::UTF8.GetString($Response.OutputStream.ToArray()) }
    function New-FakeRequest {
        param([string]$Path)
        $qs = New-Object System.Collections.Specialized.NameValueCollection
        $qs.Add('path', $Path)
        [PSCustomObject]@{ QueryString = $qs }
    }
}

Describe 'Send-Json keeps lists as lists' {
    It 'sends a one-element array as a JSON array' {
        $r = New-FakeResponse
        Send-Json $r @([PSCustomObject]@{ name = 'A' })
        (Get-SentJson $r) | Should -Be '[{"name":"A"}]'
    }

    It 'sends an empty array as []' {
        $r = New-FakeResponse
        Send-Json $r @()
        (Get-SentJson $r) | Should -Be '[]'
    }

    It 'still sends a single error object as an object' {
        $r = New-FakeResponse
        Send-Json $r @{ error = 'x' }
        (Get-SentJson $r) | Should -Be '{"error":"x"}'
    }
}

Describe 'Get-Children' {
    BeforeEach { $script:driveMappings = @{} }

    It 'returns a JSON array for a folder with exactly one subfolder' {
        $parent = Join-Path $TestDrive 'FPMTest'
        New-Item -ItemType Directory -Path (Join-Path $parent 'A') -Force | Out-Null
        $r = New-FakeResponse

        Get-Children (New-FakeRequest $parent) $r

        $json = Get-SentJson $r
        $json | Should -BeLike '`[*'
        $items = @($json | ConvertFrom-Json)
        $items.Count | Should -Be 1
        $items[0].name | Should -Be 'A'
    }
}

Describe 'Get-AccessDeniedMessage' {
    It 'tells the owner to add a permission rather than take ownership again' {
        $p = Join-Path $TestDrive 'owned'
        New-Item -ItemType Directory -Path $p -Force | Out-Null   # created by, so owned by, the current user

        Get-AccessDeniedMessage $p | Should -BeLike "You own '*owned' but have no permission to open it. Use Add Permission*"
    }

    It 'tells a non-owner to take ownership first, then add a permission' {
        $p = Join-Path $TestDrive 'notowned'
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        Mock Get-Acl { throw [System.UnauthorizedAccessException]::new('denied') }

        Get-AccessDeniedMessage $p | Should -BeLike "Access denied to '*notowned'. Take ownership (this folder only) first, then use Add Permission*"
    }
}

Describe 'The page reloads files and tree after a change' {
    It 'take ownership, add permission and remove permission reload files and the tree entry' {
        $callers = [regex]::Matches($script:GuiText, "api\('/api/(take-ownership|add-ace|remove-ace)'[\s\S]*?\.then\(function\(r\) \{[\s\S]*?\}\)")
        $callers.Count | Should -Be 3
        foreach ($m in $callers) {
            $m.Value | Should -Match 'loadFiles\(currentFolder\)'
            $m.Value | Should -Match 'refreshTreeEntry\(currentFolder\)'
        }
    }
}
