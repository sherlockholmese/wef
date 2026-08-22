# Configuration

WEF configuration is in-memory only. Settings reset when WinDbg exits or when the extension is reloaded.

## Commands

Show all settings:

```text
!wef.config get
```

Show one setting:

```text
!wef.config get <key>
```

Set one setting:

```text
!wef.config set <key> <value>
```

Example:

```text
!wef.config set output.use_dml false
!wef.config set heap.vis.max_chunks 320
```

## Defaults

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

## Output Settings

### `output.use_dml`

Controls colored DML output and clickable command buttons.

```text
!wef.config set output.use_dml true
!wef.config set output.use_dml false
```

Disable DML if copying output into plain logs or if your debugger frontend does not render DML cleanly.

## Context Settings

### `ctx.stack.count`

Default number of stack entries shown by `!wef.ctx`.

### `ctx.code.lines`

Default number of disassembly lines shown by `!wef.ctx`.

### `ctx.regs.show_flags`

Controls flag display in context output.

### `dereference.depth`

Controls how far pointer-chain annotations follow references in `ctx` and `telescope`.

## Memory Settings

### `telescope.count`

Default number of pointer-sized values shown by `!wef.telescope`.

### `hexdump.size`

Default byte count for `!wef.hexdump`.

### `search.max_hits`

Default maximum number of hits for `!wef.search_pattern`.

## Register Settings

### `regs.annotate`

Controls inline register annotations (symbols, `(stack)` tags, xinfo links) in `!wef.registers` and `!wef.ctx`. Disable with `-plain` per call.

### `regs.show_diff`

Controls red `*` change markers for registers whose value changed since the previous display. The baseline is tracked per engine thread; `!wef.registers -reset` discards it.

## Heap Settings

### `heap.max_count`

Default maximum number of heaps listed from the PEB heap list.

### `heap.vis.max_chunks`

Maximum chunks collected per heap for `!wef.vis`.

### `heap.vis.detail_count`

Number of largest chunks shown in compact heap visualization.

### `heap.vis.max_segments`

Maximum heap segments walked per heap.

### `heap.vis.width`

Width of the compact heap visualization map.

### `heap.chunk.max_search_chunks`

Maximum backend chunks walked for chunk lookup, heap search, and validation.

### `heap.find.max_chunk_read`

Maximum bytes read from an individual chunk for heap content search.

### `heap.find.max_hits`

Maximum hits printed by `!wef.heaps find` and `!wef.heaps xref`.

### `heap.stats.top_count`

Number of largest busy chunks shown per heap in `!wef.heaps stats`.

## Stack Settings

### `stack.count`

Default number of slots shown by `!wef.stack`.

### `stack.cookie.max_scan`

Maximum bytes scanned above the stack limit by `!wef.stack cookie`. Override a single scan with an explicit length, for example `!wef.stack cookie L200000`.

## Pattern Settings

### `pattern.max_length`

Maximum cyclic pattern length for `!wef.pattern create` and default search length for `!wef.pattern offset`.

## TTD Settings

### `ttd.max_events`

Default number of TTD rows requested by event commands.

Examples:

```text
!wef.config set ttd.max_events 50
!wef.ttd exceptions
!wef.ttd allocs
```
