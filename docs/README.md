# WEF Documentation

WEF is a native C++ WinDbg extension that brings GEF-like ergonomics to Windows debugging without replacing normal WinDbg workflows. It focuses on fast context views, readable memory inspection, heap exploration, exploit-development helpers, and Time Travel Debugging (TTD) event exploration.

## Documentation Map

- [Installation and loading](installation.md)
- [Command reference](commands.md)
- [Heap workflows](heap.md)
- [Memory, vmmap, and exploit helpers](memory.md)
- [TTD Event Explorer](ttd.md)
- [Configuration](configuration.md)
- [Troubleshooting](troubleshooting.md)

## Core Ideas

WEF keeps all canonical commands under the `!wef.` namespace so it can coexist with other WinDbg extensions. Optional aliases are installed only when you run `!wef.install`.

WEF uses WinDbg DML by default. When DML is enabled, bracketed actions like `[dump]`, `[chunk]`, `[segments]`, or `[ttd gui]` are clickable command buttons. These buttons are intentionally small shortcuts around normal commands, not a separate UI framework.

## Quick Start

```text
.load C:\path\to\wef.dll
!wef
!wef.ctx
!wef.vmmap
!wef.heaps
!wef.vis
```

Install aliases if you want shorter commands:

```text
!wef.install
ctx
vis
search-pattern hex:41414141
!wef.uninstall
```

## Major Feature Areas

### Context and Navigation

- `!wef.ctx` gives a compact register, code, and stack view.
- `!wef.telescope` follows pointer-sized values and annotates them.
- `!wef.hexdump` prints bytes with ASCII previews.

### Memory and Exploit Helpers

- `!wef.vmmap` shows memory regions and supports filters.
- `!wef.search_pattern` scans committed readable regions for bytes, strings, or pointer-sized values.
- `!wef.pattern` creates cyclic patterns and resolves crash offsets.

### Heap Analysis

- `!wef.heaps` lists process heaps.
- `!wef.vis` renders a compact heap visualization.
- `!wef.chunk <addr>` inspects the heap chunk containing an address and flags dangling references.
- `!wef.heaps find` searches heap chunks.
- `!wef.heaps stats` aggregates busy/free bytes, size histograms, largest allocations, and free-run fragmentation hints.
- `!wef.heaps xref <addr>` finds heap pointers to an allocation, marking stale references in freed chunks.
- `!wef.heaps validate` performs lightweight structural checks.

### Stack Analysis

- `!wef.stack` prints annotated stack slots with return addresses, frame bases, stack pointers, and cookies from the engine stack walk.
- `!wef.stack cookie` (or `!wef.canary scan`) locates `/GS` security-cookie instances on the current thread's stack.

### TTD Event Explorer

- `!wef.ttd gui` exposes clickable entrypoints for common TTD grids.
- `!wef.ttd calls` queries call timelines.
- `!wef.ttd exceptions` shows exception events.
- `!wef.ttd memory` queries reads, writes, or execution for a memory range.
- `!wef.ttd allocs` shows allocation-related APIs, optionally centered on an address.

## Supported Target Shape

WEF currently targets amd64/x86-64 user-mode debugging. Many commands assume user-mode process state and private `ntdll` symbols when inspecting heap internals. If symbols are missing, heap commands fail gracefully or show partial information.
