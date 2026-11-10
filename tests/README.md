# Windows verification

Build `wef.sln` on Windows, including the `wef_fixture` project. No Linux build is required or supported by this workflow.

Run the assertion-based checks from PowerShell:

```powershell
.\tests\run_parity.ps1 -Configuration Debug
.\tests\run_parity.ps1 -Configuration Release
```

Use `-Cdb`, `-Dll`, and `-Fixture` to override paths. The script does not build anything. It runs the x64 Windows CDB, writes a temporary command file and full debugger log, and fails if an expected result or final marker is missing. A successful run reports the number of checked cases and log location.

Configure Microsoft symbols in WinDbg or `_NT_SYMBOL_PATH` before running. Heap checks require `ntdll` type information; the script reloads `ntdll` after the first fixture stop. Missing symbols are a test failure, rather than a skipped allocator check. `!ext.heap` must be available for native integration tests. Run with page heap/Application Verifier disabled for this fixture: they replace the backend layouts these checks intentionally exercise. LFH activation may be suppressed when heap debugging is enabled by the debugger; `!wef.heaps lfh` still checks the native command route.

The fixture creates a dedicated NT backend heap, a separate LFH-capable heap, pointer/string buffers, and executable gadget bytes. The checks cover:

- Known De Bruijn prefixes/offsets, custom alphabets, legacy patterns, and invalid sizes.
- Typed/hex/UTF-16 memory search and integer-width overflow.
- Aligned/unaligned pointer scans, a pointer across an internal scan-window boundary, and a no-access page.
- A gadget across a scan-window boundary, disassembly, argument locations, address distances, and hex conversion.
- Instruction-count NOPs, stubs, verified undo, and refusing undo after an external memory change.
- NT heap kind, allocated/free chunk classification, decoded checksums, validation failure after deliberate header corruption, and restoration.
- Native statistics/LFH integration, an unchanged snapshot, then actual allocation/free changes after resuming to a second stop.

The header corruption is limited to this suspended fixture and restored before the target resumes. CDB terminates the fixture after the final checks. The preexisting `wef_smoke.cdb` remains a broader manual smoke script for context, PE, stack and TTD commands; it is not an assertion suite.

Execution helpers delegate to `pc`, `pt`, and `gu`. Verify their stop/resume behavior manually in a live test process with calls and returns. Segment-heap inspection should also be checked manually with a target configured to use the Windows segment heap; this fixture intentionally uses an NT backend heap for deterministic decoding checks.
