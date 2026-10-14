<#
    Unit tests for the report's overlap math (OverlapCore), run with Node.js against the
    exact JavaScript the report embeds. Skipped when Node is not installed - it is a
    developer-machine check, never needed on the servers that run the export.

    Also checks every script block in a generated report parses (node --check) and avoids
    syntax Internet Explorer 10/11 cannot run, since that is the default browser on
    Server 2012 / 2012 R2.
#>

BeforeDiscovery {
    $script:NoNode = -not (Get-Command node -ErrorAction SilentlyContinue)
}

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Export-ADGroupMembership.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $script:Work = Join-Path $TestDrive 'js'
    $null = New-Item -ItemType Directory -Path $script:Work -Force
    [System.IO.File]::WriteAllText((Join-Path $script:Work 'overlap-core.js'), (Get-OverlapCoreScript))

    function Invoke-NodeScript([string]$Name, [string]$Source) {
        $path = Join-Path $script:Work $Name
        [System.IO.File]::WriteAllText($path, $Source)
        $out = & node $path 2>&1
        [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = ($out | Out-String) }
    }
}

Describe 'OverlapCore (Node)' -Skip:$script:NoNode {
    It 'passes the assertion suite' {
        $harness = @'
var assert = require('assert');
var C = require('./overlap-core.js');
function grp(name, members, contains) {
  return { n: name, s: name, c: 'Security', sc: 'Global', m: members, o: [], k: contains || [] };
}
function direct(ids) { return ids.map(function (i) { return [i, 0, '']; }); }
var people = []; for (var i = 0; i < 40; i++) { people.push({ n: 'P' + i, s: 'p' + i, d: '', t: '', e: true }); }

// 0 A: 0-9          1 B: 0-8 (near-duplicate of A: 9/10 = 90% of the larger)
// 2 C: 0-3 (subset of A and B)     3 D: 0 and 20 (shares only 1 person with A)
// 4 E: contains F, members 30-33 via nesting   5 F: 30-33
// 6 G: 0,1,30,31,32 (partial)      7 H: nested-only members 0-4 (how 2)
var data = { people: people, groups: [
  grp('A', direct([0,1,2,3,4,5,6,7,8,9])),
  grp('B', direct([0,1,2,3,4,5,6,7,8])),
  grp('C', direct([0,1,2,3])),
  grp('D', direct([0,20])),
  grp('E', [[30,2,'F'],[31,2,'F'],[32,2,'F'],[33,2,'F']], [5]),
  grp('F', direct([30,31,32,33])),
  grp('G', direct([0,1,30,31,32])),
  grp('H', [[0,2,'X'],[1,2,'X'],[2,2,'X'],[3,2,'X'],[4,2,'X']])
]};
var all = [0,1,2,3,4,5,6,7];

// labels
assert.strictEqual(C.label(9, 10, 9, false), 'duplicate');
assert.strictEqual(C.label(8, 10, 9, false), 'partial', '8 of 9 is not all of the smaller group, and 8/10 < 90%');
assert.strictEqual(C.label(4, 10, 4, false), 'subset');
assert.strictEqual(C.label(2, 10, 5, false), 'partial');
assert.strictEqual(C.label(4, 4, 4, true), 'contains', 'nesting wins over duplicate');

function find(res, a, b) {
  for (var i = 0; i < res.pairs.length; i++) {
    var p = res.pairs[i];
    if ((p.a === a && p.b === b) || (p.a === b && p.b === a)) { return p; }
  }
  return null;
}
var res = C.computePairs(data, { mode: 'effective', ids: all, minPct: 0.5, minShared: 2 });
assert.strictEqual(res.tooLarge, false);
var ab = find(res, 0, 1);
assert.ok(ab, 'A/B pair present');
assert.strictEqual(ab.label, 'duplicate');
assert.strictEqual(ab.shared, 9);
assert.strictEqual(ab.a, 0, 'larger group listed first');
assert.strictEqual(find(res, 0, 2).label, 'subset');
assert.strictEqual(find(res, 0, 2).pct, 1);
assert.strictEqual(find(res, 0, 3), null, 'one shared person is below the 2-person minimum');
var ef = find(res, 4, 5);
assert.strictEqual(ef.label, 'contains');
assert.strictEqual(ef.a, 4, 'container listed first');
assert.strictEqual(find(res, 0, 6), null, 'G/A shares 2 of 5 = 40%, below 50%');
assert.strictEqual(res.pairs[0].label, 'duplicate', 'near-duplicates sort first');
assert.strictEqual(res.pairs[res.pairs.length - 1].label, 'contains', 'nesting sorts last');

var low = C.computePairs(data, { mode: 'effective', ids: all, minPct: 0.25, minShared: 2 });
assert.strictEqual(find(low, 0, 6).label, 'partial');
assert.strictEqual(find(low, 0, 6).pct, 0.4);

// Direct mode ignores nested members: E has none, H has none.
var dir = C.computePairs(data, { mode: 'direct', ids: all, minPct: 0.25, minShared: 2 });
assert.strictEqual(find(dir, 4, 5), null);
assert.strictEqual(find(dir, 0, 7), null);
assert.strictEqual(find(res, 0, 7).label, 'subset', 'effective mode sees H inside A');
assert.strictEqual(C.sizeOf(data, 'direct', 7), 0);
assert.strictEqual(C.sizeOf(data, 'effective', 7), 5);

// Work estimate and the guard.
var bp = C.personGroups(data, 'effective', [0, 1]);
assert.strictEqual(C.estimateWork(bp), 9, '9 people in both A and B -> 9 pair increments');
var big = C.computePairs(data, { mode: 'effective', ids: all, minPct: 0, minShared: 1, maxWork: 5 });
assert.strictEqual(big.tooLarge, true);
assert.strictEqual(big.pairs.length, 0);

// Intersection (pair drill-down and combination check).
assert.deepStrictEqual(C.intersect(data, 'effective', [0, 1, 2]).sort(function (x, y) { return x - y; }), [0,1,2,3]);
assert.deepStrictEqual(C.intersect(data, 'effective', [0, 5]), []);
assert.deepStrictEqual(C.intersect(data, 'effective', []), []);
assert.deepStrictEqual(C.intersect(data, 'effective', [6]).sort(function (x, y) { return x - y; }), [0,1,30,31,32]);

// Grid counts and diagonal.
var gr = C.grid(data, { mode: 'effective', ids: [0, 1, 2] });
assert.strictEqual(C.sharedCount(gr, 0, 1), 9);
assert.strictEqual(C.sharedCount(gr, 1, 0), 9);
assert.strictEqual(C.sharedCount(gr, 2, 2), 4);
assert.strictEqual(C.sharedCount(gr, 0, 3), 0);

// Large-group detection (90% of the 40 people in the report).
var wide = { people: people, groups: [grp('Everyone', direct(people.map(function (p, i) { return i; }))), grp('Small', direct([1, 2]))] };
assert.deepStrictEqual(C.largeGroupIds(wide, 'effective', 0.9), [0]);
console.log('OK');
'@
        $r = Invoke-NodeScript 'harness.js' $harness
        $r.Output | Should -Match 'OK'
        $r.ExitCode | Should -Be 0 -Because $r.Output
    }
}

Describe 'Report scripts' {
    BeforeAll {
        $grp = [PSCustomObject]@{ Name = 'G1'; SamAccountName = 'G1'; GroupCategory = 'Security'; GroupScope = 'Global'
                                  Description = ''; DistinguishedName = 'CN=G1,OU=Groups,DC=contoso,DC=com'; ManagedBy = $null }
        $model = ConvertTo-GroupAccessModel -Rows @() -Groups @($grp)
        $edges = @{}
        Add-NestEdge -Edges $edges -ParentDN 'CN=P,DC=x' -ChildDN 'CN=G1,OU=Groups,DC=contoso,DC=com'
        $nodes = @{ 'CN=P,DC=x' = [PSCustomObject]@{ DN = 'CN=P,DC=x'; Name = 'P'; Sam = 'P'; Category = 'Security'; Scope = 'Global'; Sid = ''; InExport = $false; Unresolved = $false } }
        $nest = ConvertTo-NestModel -Graph ([PSCustomObject]@{ Nodes = $nodes; CapReached = $false }) -Edges $edges -NestedExpanded
        $html = New-UserAccessHtml -Users @() -DomainName 'contoso.com' -ScopeNote 'test' -GroupsProcessed 1 -GroupModel $model -NestModel $nest
        $script:Scripts = @([regex]::Matches($html, '<script>(.*?)</script>', 'Singleline') | ForEach-Object { $_.Groups[1].Value })
    }

    It 'generates the executable script blocks' {
        # people, overlap core, nest core, overlap UI, nest UI
        $script:Scripts.Count | Should -Be 5
    }

    It 'uses only syntax Internet Explorer 10/11 can run' {
        foreach ($js in $script:Scripts) {
            $js | Should -Not -Match '=>'                      # arrow functions
            $js | Should -Not -Match '(^|[;{\s])(let|const)\s'  # block-scoped declarations
            $js | Should -Not -Match '`'                       # template literals
            $js | Should -Not -Match '\.dataset\b'
            $js | Should -Not -Match 'querySelectorAll\([^)]*\)\.forEach'
            $js | Should -Not -Match 'new (Map|Set)\('
            $js | Should -Not -Match 'classList\.toggle\([^,)]+,'
        }
    }

    It 'parses (node --check)' -Skip:$script:NoNode {
        for ($i = 0; $i -lt $script:Scripts.Count; $i++) {
            $path = Join-Path $script:Work "block$i.js"
            [System.IO.File]::WriteAllText($path, $script:Scripts[$i])
            $out = & node --check $path 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ($out | Out-String)
        }
    }
}
