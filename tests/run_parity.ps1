param(
    [string]$Configuration = "Debug",
    [string]$Cdb = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe",
    [string]$Dll,
    [string]$Fixture
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if (!$Dll) { $Dll = Join-Path $repo "x64\$Configuration\wef.dll" }
if (!$Fixture) { $Fixture = Join-Path $repo "x64\$Configuration\wef_fixture.exe" }
foreach ($path in @($Cdb, $Dll, $Fixture)) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "File not found: $path. Build on Windows first." }
}
$Dll = (Resolve-Path -LiteralPath $Dll).Path
$Fixture = (Resolve-Path -LiteralPath $Fixture).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("wef-parity-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
$script = Join-Path $work "parity.cdb"
$log = Join-Path $work "parity.log"
$commands = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "wef_parity.cdb"))
$commands = $commands.Replace("__WEF_DLL__", $Dll).Replace("__FIXTURE_DIR__", (Split-Path $Fixture -Parent))
[IO.File]::WriteAllText($script, $commands, [Text.Encoding]::Default)
& $Cdb -logo $log -cf $script $Fixture | Out-Host
if ($LASTEXITCODE -ne 0) { throw "CDB failed ($LASTEXITCODE). Log: $log" }
$output = [IO.File]::ReadAllText($log)
$cases = @{}
foreach ($match in [regex]::Matches($output, '(?ms)^WEF_CASE=(\w+)\r?\n(.*?)(?=^WEF_CASE=|\z)')) {
    $cases[$match.Groups[1].Value] = $match.Groups[2].Value
}
$expected = [ordered]@{
    pattern4 = 'aaaabaaacaaadaaaeaaafaaagaaahaaai'
    pattern8 = 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaae'
    offset4 = 'little-endian\s*:\s*offset 0xc \(12\)'
    literal = 'little-endian\s*:\s*offset 0x4 \(4\)'
    custom = 'aabacbbcc'
    cyclic_lookup = 'little-endian\s*:\s*offset 0xc \(12\)'
    legacy = 'little-endian\s*:\s*offset 0x9 \(9\)'
    capacity = 'exceeds the unique pattern capacity'
    negative = 'usage:'
    empty = 'usage:'
    typed_search = '(?s)pattern\s*:\s*88 77 66 55.*\[dump\]'
    hex_search = '(?s)pattern\s*:\s*88 77 66 55.*\[dump\]'
    wide_search = '(?s)77 00 65 00 66 00.*\[dump\]'
    search_overflow = 'integer does not fit'
    scan = 'Matches\s*:\s*1\b'
    aligned_scan = 'Matches\s*:\s*0\b'
    unaligned_scan = 'Matches\s*:\s*1\b'
    boundary_scan = 'Matches\s*:\s*1\b'
    rop = '(?is)pop\s+rcx;\s*ret.*Gadgets\s*:\s*1\b'
    invalid_depth = 'gadget depth must be between 1 and 10'
    reversed_range = 'mapping range must have end > start'
    invalid_before = 'previous instruction count must be between 0 and 64'
    nearpc = '(?is)Disassembly.*\bje\b|Disassembly.*\bjz\b'
    distance = '0x18 \(24 bytes\)'
    negative_distance = '-0x18 \(-24 bytes\)'
    hex2ptr = '0x1122334455667788'
    dumpargs = 'arg5 \[rsp\+0x28\]'
    nop_instructions = '90 90 90 90 90 c3'
    nop_revert = '48 89 c0 66 90 c3'
    stub = '48 b8 2a 00 00 00 00 00 00 00 c3'
    stub_revert = '(cc ){10}cc'
    patch_conflict = 'saved patch differs from current memory'
    patch_restore = 'No saved patches'
    heap_kind = 'nt/backend'
    heap_busy = '(?m)^  [0-9a-f]{2}\s+[0-9a-f`]+\s+[0-9a-f`]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+busy\b'
    heap_free = '(?m)^  [0-9a-f]{2}\s+[0-9a-f`]+\s+[0-9a-f`]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+free\b'
    heap_validate = 'no structural issues found in [1-9][0-9]* decoded NT backend chunks'
    heap_corruption = '(?s)checksum mismatch.*validation coverage is incomplete'
    heap_repair = 'no structural issues found in [1-9][0-9]* decoded NT backend chunks'
    heap_native_stats = 'Command\s*:\s*!ext\.heap -stat -h'
    heap_native_lfh = 'Command\s*:\s*!ext\.heap -hl'
    heap_snapshot = 'Saved heap snapshot: [1-9][0-9]* observed busy backend chunks'
    heap_unchanged = 'Added: 0, missing: 0, changed: 0'
    heap_changed = 'Added: [1-9][0-9]*, missing: [1-9][0-9]*'
    heap_clear = 'Heap snapshots cleared'
    nextcall_export = 'usage: !wef\.nextcall'
    nextret_export = 'usage: !wef\.nextret'
    stepout_export = 'usage: !wef\.stepout'
}
$failures = @()
foreach ($name in $expected.Keys) {
    if (!$cases.ContainsKey($name) -or $cases[$name] -notmatch $expected[$name]) {
        $failures += $name
    }
}
foreach ($name in @("heap_validate", "heap_repair", "heap_snapshot", "heap_unchanged", "heap_changed")) {
    if ($cases.ContainsKey($name) -and $cases[$name] -match 'incomplete|inconclusive|partial coverage|snapshot is partial') {
        $failures += "$name has incomplete coverage"
    }
}
if (!$cases.ContainsKey("done")) { $failures += "script did not finish" }
if ($output -match 'No export .* found|extension DLL.*not found|Unable to load.*wef|internal error:') {
    $failures += "extension load/export/internal error"
}
if ($failures.Count) { throw "Failed: $($failures -join ', '). Full debugger log: $log" }
Write-Host "Passed $($expected.Count) parity checks. Log: $log"
