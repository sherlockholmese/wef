# WEF

WEF is a native C++ WinDbg extension DLL that adds GEF-like debugger ergonomics while preserving normal WinDbg command behavior.

**Note: Currently only support amd64/x86-64 based systems and binaries!**

![screenshot of wef in action](screenshots/wef.png)

## Build

Requirements:

- Visual Studio 2026 with **Desktop development with C++**
- Debugging Tools for Windows

Open `wef.sln` and build `Debug|x64` or `Release|x64`.

Output:

```text
x64\Debug\wef.dll
x64\Release\wef.dll
```

The project expects the DbgEng SDK here:

```text
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sdk\
```

If your SDK is installed elsewhere, open `wef.vcxproj` and change the `DbgSdkDir` user macro.

## Load

### From source build

Build `Release|x64`, then copy:

```text
x64\Release\wef.dll
```

to:

```text
%LOCALAPPDATA%\Dbg\EngineExtensions\wef.dll
```

### From GitHub release

Download the compiled `wef.dll` from the GitHub release, then copy it to:

```text
%LOCALAPPDATA%\Dbg\EngineExtensions\wef.dll
```

You can also keep it anywhere and load it by absolute path:

```text
.load C:\dev\wef\x64\Release\wef.dll
!wef
```

Restart WinDbg and run:

```text
!wef
```

If your WinDbg build does not auto-load it by module name, run `.load wef` once in that session.

UserExtensions gallery files are also available under `manifest/`, but the simple `EngineExtensions` install is usually better for this native DLL.

Aliases are opt-in:

```text
!wef.install
ctx
telescope @rsp L8
!wef.uninstall
```

Canonical commands like `!wef.ctx` always work, even without aliases.

WEF uses WinDbg DML by default. In WinDbg, bracketed actions such as `[dump]`, `[chunk]`, `[vis]`, or `[ttd gui]` are clickable command buttons.

## Commands

```text
!wef
!wef.install
!wef.uninstall
!wef.aliases
!wef.ctx
!wef.telescope [addr] L<count>
!wef.hexdump <addr> L<size>
!wef.search_pattern <text|addr|hex:bytes> [start] [L<size>]
!wef.vmmap [-all|-free] [-commit|-reserve] [-x|-w|-rwx] [-image|-mapped|-private] [-module <name>] [-contains <addr>] [L<count>]
!wef.pattern create <length>
!wef.pattern offset <value|ascii> [L<max-length>]
!wef.checksec
!wef.registers [-plain|-reset|<register>]
!wef.colors
!wef.heaps [L<count>|heap-address]       (alias: wef-heap)
!wef.heaps flags [L<count>|heap-address]
!wef.heaps segments [L<count>|heap-address]
!wef.heaps chunks [-busy|-free] [-contains <addr>] [L<count>|heap-address]
!wef.heaps chunk <addr>
!wef.heaps find <addr|text> [L<count>|heap-address]
!wef.heaps stats [L<count>|heap-address]
!wef.heaps xref <addr> [L<count>|heap-address]
!wef.heaps validate [L<count>|heap-address]
!wef.chunk <addr>
!wef.vis [L<count>|heap-address]
!vis [L<count>|heap-address]
!wef.stack [<addr>] [L<count>]
!wef.stack cookie [L<max-scan-bytes>]
!wef.canary scan [L<max-scan-bytes>]
!wef.ttd calls <module!function|pattern> [L<count>]
!wef.ttd exceptions [L<count>]
!wef.ttd memory <addr> L<size> [-r|-w|-x|-rw|-all] [-take <count>]
!wef.ttd allocs [addr] [L<size>|L<count>]
!wef.ttd timeline [L<count>]
!wef.ttd gui
!wef.config get [key]
!wef.config set <key> <value>
```

Aliases installed by `!wef.install`:

```text
ctx
telescope
hexdump
search-pattern
vmmap
pattern
checksec
chunk
wef-heap
vis
stack
ttd-events
wef-config
```

### Heap workflow

```text
!wef.heaps
!wef.vis
!wef.chunk <addr>
!wef.heaps find <addr|text>
!wef.heaps stats
!wef.heaps xref <addr>
!wef.heaps validate
```

`!wef.vis` prints a compact heap map, summary counts, and the largest chunks instead of dumping every chunk. Use the DML buttons or `!wef.heaps chunks <heap>` for the full table.

`!wef.heaps stats` aggregates Windows NT-heap backend chunks per heap: busy/free counts and bytes, utilization, a power-of-two size histogram, largest busy allocations, and adjacent-free-run hints for fragmentation. `!wef.heaps xref <addr>` scans chunk data for pointer-sized references to an allocation; hits in free chunks are marked `(stale)` as use-after-free evidence. `!wef.heaps chunk <addr>` flags addresses that fall inside freed chunks.

### Stack workflow

```text
!wef.stack
!wef.stack @rbp L32
!wef.stack cookie
```

`!wef.stack` prints the stack from `@rsp` (or an explicit address) with one annotation column: return-address slots found by a stack walk, frame bases, stack pointers, security-cookie values, and dereference chains. `!wef.stack cookie` (also `!wef.canary scan`) reads `/GS` cookies from every loaded module's load config and reports each instance found on the current thread's stack, with rsp-relative offsets.

### Register workflow

```text
!wef.registers
!wef.registers rax
!wef.registers -plain
```

`!wef.registers` prints a two-column grid with inline annotations: resolved symbols, `(stack)` tags for values inside the thread stack, and xinfo buttons. Registers that changed since the previous stop are marked with `*` and colored red (per-thread baseline; `regs.show_diff`, reset with `-reset`). `-plain` prints bare values for clean copy-paste. A single-register query shows value, symbol, region, string preview, pointer chain, and action buttons.

`checksec` renders each mitigation (`ASLR`, `DEP/NX`, `CFG`, `GS cookie`, `SafeSEH`) colored green when enabled and red when missing, with an enabled-count summary line.

Run `!wef.colors` to verify DML color output works in your debugger host; it prints swatches, a sample link, warning/error samples, and hints when DML is disabled.

### Memory and exploit helpers

```text
!wef.search_pattern hex:41414141
!wef.search_pattern str:password
!wef.pattern create 512
!wef.pattern offset Aa3A L8192
!wef.vmmap -x
!wef.vmmap -contains @rsp
```

`search_pattern` scans committed readable memory and supports text, numeric pointer-sized values, and `hex:` byte patterns. `pattern` uses a GEF/metasploit-style cyclic pattern.

### TTD Event Explorer

```text
!wef.ttd gui
!wef.ttd calls ntdll!RtlAllocateHeap
!wef.ttd exceptions
!wef.ttd memory <addr> L<size> -rw
!wef.ttd allocs <addr> L<size>
!wef.ttd timeline
```

The TTD commands emit `dx -g` grid views for searchable, sortable timelines of calls, exceptions, memory access, and allocation-related APIs. They require a loaded TTD trace.

## Config

Config is in-memory only and resets when WinDbg exits or the extension reloads.

```text
!wef.config get
!wef.config set output.use_dml false
```

Defaults:

```text
output.use_dml = true
ctx.stack.count = 20
ctx.code.lines = 8
ctx.regs.show_flags = true
dereference.depth = 3
heap.max_count = 80
heap.chunk.max_search_chunks = 4096
heap.find.max_chunk_read = 65536
heap.find.max_hits = 80
heap.vis.max_chunks = 160
heap.vis.detail_count = 8
heap.vis.max_segments = 16
heap.vis.width = 80
heap.stats.top_count = 5
pattern.max_length = 8192
search.max_hits = 80
stack.count = 20
stack.cookie.max_scan = 1048576
regs.annotate = true
regs.show_diff = true
telescope.count = 20
ttd.max_events = 200
hexdump.size = 100
```

`output.use_dml` controls colored DML output and clickable command buttons.
