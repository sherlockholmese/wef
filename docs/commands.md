# Command Reference

This page lists WEF commands by category. Canonical commands use the `!wef.` namespace and do not require aliases.

The [GEF/pwndbg parity reference](parity.md) covers typed searches, pointer/gadget scans, navigation, call arguments, execution helpers, patch undo, stubs, and the limits of Windows allocator coverage.

## Top-Level Commands

```text
!wef
!wef.install
!wef.uninstall
!wef.aliases
!wef.config get [key]
!wef.config set <key> <value>
```

### `!wef`

Shows the command overview and quick-action DML buttons.

### `!wef.install`

Installs optional text replacement aliases for shorter commands.

### `!wef.uninstall`

Removes WEF aliases installed by `!wef.install`.

### `!wef.aliases`

Displays aliases and their canonical targets.

## Context Commands

```text
!wef.ctx [-full] [-regs] [-stack L<count>] [-code L<count>]
!wef.telescope [addr] L<count>
!wef.hexdump <addr> L<size> [-force]
```

### `!wef.ctx`

Displays:

- Target summary
- Current thread
- Registers
- Disassembly near the instruction pointer
- Stack entries with dereference annotations

Useful examples:

```text
!wef.ctx
!wef.ctx -full
!wef.ctx -stack L40
!wef.ctx -code L16
```

### `!wef.telescope`

Reads pointer-sized slots and annotates values as symbols, strings, memory regions, or pointer chains.

```text
!wef.telescope @rsp L20
!wef.telescope poi(@rsp) L8
```

### `!wef.hexdump`

Shows hex bytes and printable ASCII.

```text
!wef.hexdump @rsp L80
!wef.hexdump 00000000`0019f000 L200 -force
```

Reads larger than `0x1000` require `-force`.

## Register Commands

```text
!wef.registers [-plain] [-reset]
!wef.registers <register>
```

### `!wef.registers`

Prints a two-column register grid with inline annotations:

- Resolved symbols for values that land on known code or data
- `(stack)` for values inside the current thread stack range
- Clickable values that open `!wef.xinfo`

Registers whose value changed since the previous call are marked `*` and shown in red, mirroring GEF's change highlighting. The baseline is tracked per engine thread and refreshed on every display; `-reset` discards it.

```text
!wef.registers
!wef.registers -reset
!wef.registers -plain
```

`-plain` prints bare name/value pairs without annotations, diff markers, or links.

### Single-register query

Passing a register name prints a detailed view for one register:

```text
!wef.registers rax
!wef.registers @rsp
```

The detail view includes value, symbol, memory region (state/protection/type/module), string preview, a dereference chain, and `[telescope]` / `[hexdump]` / `[xinfo]` action buttons. Queries for `rip` note the instruction pointer role; queries for `rsp` add a `[stack]` button.

Settings: `regs.annotate`, `regs.show_diff`, plus `ctx.regs.show_flags` for the flags line.

## Color Commands

```text
!wef.colors
```

### `!wef.colors`

Self-test for DML color output. Prints each supported color rendered in itself, a sample command link, warning and error samples, and guidance when DML is disabled (`output.use_dml`). Use it to confirm your debugger host renders colored DML; cdb and ntkd show raw tags unless DML is preferred.

## Memory Commands

```text
!wef.vmmap [-all|-free] [-commit|-reserve] [-x|-w|-rwx] [-image|-mapped|-private] [-module <name>] [-contains <addr>] [L<count>]
!wef.search_pattern <text|addr|hex:bytes> [start] [L<size>] [-max <count>] [-x|-w|-rwx] [-image|-mapped|-private]
```

### `!wef.vmmap`

Lists memory regions with base, end, size, state, protection, type, and module.

Examples:

```text
!wef.vmmap
!wef.vmmap -x
!wef.vmmap -w -private
!wef.vmmap -image -module ntdll
!wef.vmmap -contains @rsp
!wef.vmmap L20
```

Rows include DML buttons for dumping, searching, and focusing on a region.

### `!wef.search_pattern`

Searches committed readable memory. Supported pattern forms:

- Plain text token, for example `password`
- Explicit string token, for example `str:password`
- Hex bytes, for example `hex:41424344`
- Numeric expression or pointer-like value, for example `0x41414141` or `@rsp`

Examples:

```text
!wef.search_pattern hex:41414141
!wef.search_pattern str:password
!wef.search_pattern 0x4141414141414141
!wef.search_pattern hex:cc 00007ff6`00000000 L100000 -x
!wef.search_pattern token @rsp L1000 -max 10
```

Results include buttons for:

- `dump`, hexdump at the match
- `tel`, telescope at the match
- `chunk`, inspect containing heap chunk

## Pattern Commands

```text
!wef.pattern create [-n <width>] [-a <alphabet>] [--legacy] <length>
!wef.pattern offset [-n <width>] [--legacy] <value|str:text> [L<max-length>]
!wef.cyclic [-n <width>] [-a <alphabet>] [<length>|-l <value>]
```

### `!wef.pattern create`

Creates a pwntools-compatible De Bruijn pattern. The default unique subsequence width is the target pointer size; select the same width when generating and searching:

```text
!wef.pattern create -n 4 512
```

### `!wef.pattern offset`

Finds the offset of an ASCII token or numeric value inside the cyclic pattern.

```text
!wef.pattern offset -n 4 str:daaa L1000
!wef.pattern offset -n 4 0x61616164 L1000
!wef.pattern offset --legacy 0x41336141 L1000
```

`--legacy` is required for old WEF/Metasploit patterns beginning `Aa0Aa1`. Both endian orders are searched, with short lookups flagged as potentially ambiguous. `str:` forces literal lookup for tokens that resemble registers or expressions. Pattern creation and lookup are bounded by `pattern.max_length` and a 16 MiB hard limit. `-n` accepts 1–8; `-a` must contain unique characters.

## PE Security

```text
!wef.checksec [module]
```

Inspects PE security mitigations for the main module or a specified module. Each mitigation prints green when enabled and red when missing:

- ASLR (`DYNAMIC_BASE`, notes high entropy VA)
- DEP / NX (`NX_COMPAT`)
- Control Flow Guard (with GuardFlags when metadata is readable)
- GS cookie (load-config `SecurityCookie` address)
- SafeSEH (x86 images only; `n/a` elsewhere)

A summary line reports how many applicable mitigations are enabled, followed by `[pe_info]`, `[canary]`, and `[iat]` shortcut buttons.

```text
!wef.checksec
!wef.checksec ntdll
```

## Heap Commands

```text
!wef.heaps [L<count>|heap-address]
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
```

See [Heap Workflows](heap.md) for detailed examples.

## Stack Commands

```text
!wef.stack [<addr|expression>] [L<count>]
!wef.stack cookie [L<max-scan-bytes>]
!wef.canary scan [L<max-scan-bytes>]
```

### `!wef.stack`

Prints pointer-sized slots from `@rsp`, or an explicit address, with an annotation column:

- `ret#N -> symbol` for slots holding a return address found by the engine stack walk
- `frame #N` for slot addresses that match a walked frame base
- `stack ptr` for values that point into the current thread stack
- `cookie <module>` for values equal to a module `/GS` security cookie
- Dereference chain and string previews

A compact clickable backtrace is printed after the table.

```text
!wef.stack
!wef.stack @rbp L32
!wef.stack 00000000`0019f000 L16
```

### `!wef.stack cookie`

Reads the `/GS` security cookie from every loaded module's load-config directory, then scans the current thread's stack (from the TEB stack limits) for instances of those values. Each hit shows its address, rsp-relative offset, owning module, and a dump button. This mirrors GEF's canary workflow on Windows.

```text
!wef.stack cookie
!wef.canary scan L200000
```

Scan depth defaults to `stack.cookie.max_scan` bytes above the stack limit.

## TTD Commands

```text
!wef.ttd calls <module!function|pattern> [L<count>]
!wef.ttd exceptions [L<count>]
!wef.ttd memory <addr> L<size> [-r|-w|-x|-rw|-all] [-take <count>]
!wef.ttd allocs [addr] [L<size>|L<count>]
!wef.ttd timeline [L<count>]
!wef.ttd gui|grid
```

See [TTD Event Explorer](ttd.md) for detailed usage.
