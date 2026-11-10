# GEF/pwndbg workflows on Windows

WEF targets native x64 Windows user-mode debugging. This reference tracks workflow coverage; it does not claim full command or option parity with either upstream project. The runtime checks in [tests](../tests/README.md) must be run on Windows after building.

## Core workflows

| GEF / pwndbg workflow | WEF / WinDbg command | Coverage and differences |
| --- | --- | --- |
| `context`, `ctx`, `regs`, `registers` | `!wef.ctx`, `!wef.regs`, `!wef.registers` | Register annotations and changes, code, branch prediction, stack, memory watches; `!wef.ctx auto on` enables stop context. |
| `nearpc` | `!wef.nearpc [address] [L<count>] [-before <count>]` | Native disassembly, current-IP marker, direct branch targets and current branch prediction. Backward decoding uses WinDbg's boundary heuristic. |
| `telescope`, `dereference`, `stack` | Corresponding `!wef.*` commands | Pointer chains, strings, symbols, regions, stack frames and `/GS` cookie candidates. |
| `vmmap`, `xinfo`, `xfiles` | Corresponding `!wef.*` commands | Windows virtual memory regions and PE sections. |
| `search`, `search-pattern` | `!wef.search`, `!wef.search_pattern` | Text, UTF-16LE, hex, 1/2/4/8-byte integers, pointers, alignment, permission/type/module filters, ranges and hit limits. See syntax below. |
| `scan`, mapping-to-mapping pointers | `!wef.scan <source> <target>` | Aligned pointers by default; `-unaligned` scans every byte. Select module names, `stack`, `all`, `private`, `image`, `mapped`, an address's region, or `start:end` / `start-end`. The first selector is scanned for pointers into the second. |
| `pattern`, `cyclic` | `!wef.pattern`, `!wef.cyclic` | De Bruijn generation, custom alphabet, widths 1–8, numeric/register/literal lookup, both endian orders. Default width is target pointer size. `--legacy` preserves old WEF/Metasploit patterns. |
| ROP gadget search | `!wef.rop ["pop rcx; ret"] [-module <name>]` | Built-in x86/x64 decoder searches executable readable memory, including unaligned starts. Ret-terminated sequences only, at most 10 instructions. Filter is a case/whitespace-insensitive substring, not a regular expression. This is a limited replacement for ROPgadget/ropper. |
| `distance`, `hex2ptr` | Corresponding `!wef.*` commands | Signed address difference and little-endian byte conversion. |
| `dumpargs` | `!wef.dumpargs [L<count>] [--entry]` | Windows x64 integer/pointer ABI: RCX/RDX/R8/R9 and stack slots. Default position is immediately before CALL; `--entry` is before the callee prologue. Floating-point/vector/aggregate argument recovery is not implemented. |
| `checksec`, `elf-info`, `got`, `canary` | `!wef.checksec`, `!wef.pe_info`, `!wef.iat` / `!wef.got`, `!wef.canary` | PE mitigations, imports and Windows `/GS` cookies replace ELF, GOT and Linux TLS canaries. |
| `pie`, `entry-break`, `name-break` | `!wef.pie`, `!wef.entry_break`, `!wef.name_break` | Loaded-module-relative and named breakpoints. Deferred launch/attach PIE workflows remain native WinDbg `bu` workflows. |
| `nextcall`, `nextret`, step out | `!wef.nextcall`, `!wef.nextret`, `!wef.stepout` | Delegate to WinDbg `pc`, `pt`, `gu`. Normal breakpoints/exceptions can stop execution sooner. These resume a live target. |
| `stepover`, `skipi`, `nop`, flags | `!wef.stepover`, `!wef.skipi`, `!wef.nop`, `!wef.edit_flags` | `nop --n` counts decoded instructions; `--b` and `L` count bytes. |
| `patch`, revert, `stub` | `!wef.patch`, `!wef.patch list`, `!wef.patch revert [all]`, `!wef.stub` | Verified memory writes and reverse-order undo of patch/nop/stub operations for the current engine process and PID. Undo stops if memory changed externally. History is in-memory, up to 128 writes, and lost on extension unload. `stub` writes an 11-byte `mov rax, imm64; ret`; choose an entry with enough space. It supports integer/pointer returns on x64. |
| `print-format`, `xor-memory`, watches | `!wef.print_format`, `!wef.xor_memory`, `!wef.memory` | Existing byte export, XOR display/patch and context memory watches. XOR writes are separate from patch history. |
| Custom structures, assembler, backtrace, processes, threads | Native `dt`, `a`, `k`, `|`, `~` | Use WinDbg's commands; WEF does not recreate its type system or assembler. |

`!wef.install` opts into short text aliases. Canonical commands always work. `!wef.heap` is an alternate export for `!wef.heaps`; no bare `heap` alias is installed, so Windows' native `!heap` remains available.

## Search syntax

```text
!wef.search -4 0x41414141 @rsp L1000
!wef.search -p @rsp -module wef_fixture
!wef.search -x "41 42 43 44" -e
!wef.search -t wide "password" -w
!wef.search_pattern hex:41424344 -x
!wef.search -t word 0x4142 @rsp L100 -a 2 --limit 10
!wef.scan stack ntdll
!wef.scan @rsp:(@rsp+1000) ntdll -unaligned
```

WEF uses Windows integer widths: `word` and `short` are 2 bytes, `dword` is 4 and `qword` is 8. In `search`, `-x` means hex input and `-e` means executable. The existing `search_pattern -x` continues to mean executable. Options `-a` / `--aligned` and `--limit` are decimal or `0x`-prefixed; `L<size>`, addresses, and `-max` follow WinDbg's hexadecimal notation. Positional mapping names from pwndbg are spelled `-module <name>` in WEF. Search is limited to readable committed regions and does not join a match across different virtual-region boundaries.

Pointer and gadget scans check for debugger interruption, skip guard/no-access pages, accept partial reads in dumps, and stop at `scan.max_bytes` (default 256 MiB). Use a module/range selector to focus a large process. Look-ahead catches pointers/gadgets that straddle an internal 4096-byte scan window within a region. Ret-only scanning does not emulate gadgets or evaluate their usefulness.

## Heap workflows

| Workflow | WEF command | Scope |
| --- | --- | --- |
| List allocators | `!wef.heaps`, `!wef.heaps native` | PEB list with detected NT/segment allocator type; native summary handles layouts unavailable to WEF. |
| Chunks, free/busy filtering, visualization | `!wef.heaps chunks`, `!wef.chunk`, `!wef.vis` | Symbol-driven NT backend traversal, including encoded entry headers. Missing chunks fall back to native lookup. LFH container blocks are not individual LFH allocations. |
| LFH entries and NT free lists | `!wef.heaps lfh [heap]`, `!wef.heaps freelist [heap]` | WinDbg `!ext.heap -hl` / `-f`. These are native allocator views, not WEF's formatted backend tables. |
| Segment heap / allocator statistics | `!wef.heaps native stats [heap]`, `!wef.heaps native chunks [heap]` | WinDbg's Windows allocator implementation. Availability and output depend on the installed debugger. |
| Statistics, find and references | `!wef.heaps stats`, `!wef.heaps find`, `!wef.heaps xref` | Decoded NT backend scope, bounded by configuration. References in freed data are triage hints; they do not prove a use-after-free. |
| Structural checks | `!wef.heaps validate [heap]` | Header checksum, bounds, overlaps, adjacent `PreviousSize`; incomplete walks are identified. |
| Allocator corruption triage | `!wef.heaps triage [heap-or-address]` | Native `!ext.heap -triage`, including LFH/segment heap support. |
| Page heap / suspected leaks | `!wef.heaps pageheap [address]`, `!wef.heaps native leaks` | Native page heap diagnostics and reachability-based leak candidates. Page heap must already be enabled for the target. |
| Changes between stops | `!wef.heaps snapshot [heap]`, `!wef.heaps diff [heap]` | Observed busy backend additions, missing chunks and changed sizes. Requires the same heap selection/L limit; baseline stays fixed until replaced. Up to 16 process baselines, cleared with `snapshot-clear`. Address reuse and changes between snapshots are not allocation history. |

Native integration invokes `!ext.heap` explicitly to avoid extension-name ambiguity. It requires Microsoft's Windows debugger extensions. WEF's formatted tables, statistics and snapshots do not yet enumerate individual LFH or segment-heap allocations.

## Remaining gaps

Core workflows still lacking a WEF implementation include saved/refined searches (`search --save/--next`), regex/assembly search, JOP/SYS gadgets, next-jump/syscall stepping, general instruction tracing/emulation, patching assembly text, configurable context layouts/history, persistent configuration/themes, and external decompiler integration. Hardware watchpoints and execution tracing remain available through WinDbg `ba` and native tracing/TTD commands. WEF memory watches are display watches, not hardware data breakpoints.

Allocator instrumentation (allocation/free histories, double-free/UAF breakpoints), individual LFH/segment entries in formatted tables, virtual-allocation enumeration and complete allocation-size recovery remain future work. Native allocator commands cover inspection and triage without pretending Linux bins/tcache structures exist on Windows. Glibc/musl/jemalloc bins, ELF relocations, Linux syscalls, procfs and QEMU-specific commands have no direct Windows counterpart.

The comparison uses the upstream [GEF command reference](https://hugsy.github.io/gef/commands/pattern/), [GEF scan semantics](https://hugsy.github.io/gef/commands/scan/), [pwndbg search reference](https://pwndbg.re/pwndbg/dev/commands/memory/search/), and [pwndbg cyclic reference](https://pwndbg.re/pwndbg/dev/commands/misc/cyclic/). Native heap coverage follows [Microsoft's heap command reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-heap). The NT header encoding approach is corroborated by Google's [symbol-driven heap walker](https://github.com/google/syzygy/blob/2642ad0dd5c3b684306bb311d5f1e4a9232c40bd/syzygy/experimental/heap_enumerate/heap_entry_walker.cc).
