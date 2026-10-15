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

// Diamond: Top -> L, Top -> R, L -> Bottom, R -> Bottom ; upward from Bottom reaches Top twice: second is 'seen'
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
// Final review #1: protected-inside-protected is AD's default (Administrators contains Domain Admins
// and Enterprise Admins) and must not raise the "nested into protected groups" alert.
var bi = nest(['Administrators','Domain Admins','Enterprise Admins','Helpdesk'], [[0,1],[0,2],[1,3]], [true, true, true, false]);
var ba = N.analyze(bi);
assert.deepStrictEqual(ba.toProtected, [false, false, false, true], 'only the non-protected Helpdesk is flagged');

// Final review #2: copied paths must say when some were left out.
var ct = N.copyText(nest(wideNames, wideEdges), 0, 5);
assert.ok(ct.indexOf('Parent > C01') > -1, ct);
assert.ok(ct.indexOf('(+ 55 more downward paths not shown)') > -1, ct);
assert.ok(N.copyText(d, 3, 100).indexOf('more') < 0, 'no notice when nothing was cut');
assert.ok(N.copyText(d, 3, 100).indexOf('Helpdesk > Tier1 > Contractors > Helpdesk  (loop)') > -1);
console.log('OK');
'@
        $path = Join-Path $script:Work 'harness.js'
        [System.IO.File]::WriteAllText($path, $harness)
        $out = & node $path 2>&1 | Out-String
        $out | Should -Match 'OK'
        $LASTEXITCODE | Should -Be 0 -Because $out
    }
}
