# Heap Workflows

WEF heap commands provide GEF-adjacent heap inspection for Windows process heaps. They rely on PEB heap lists and `ntdll` heap type symbols where available.

NT backend entry headers are decoded with the heap's encoding key using symbol-derived offsets. WEF checks allocator signatures before walking NT structures and identifies incomplete walks. Statistics and visualizations describe backend blocks; LFH container blocks are not individual user allocations.

## Quick Workflow

```text
!wef.heaps
!wef.vis
!wef.chunk <addr>
!wef.heaps find <addr|text>
!wef.heaps stats
!wef.heaps xref <addr>
!wef.heaps validate
```

## List Process Heaps

```text
!wef.heaps
!wef.heaps L20
!wef.heaps <heap-address>
```

The table includes:

- Heap index
- Heap address
- `_HEAP.Flags`
- `_HEAP.ForceFlags`
- Front-end heap type, for example backend, lookaside, or LFH
- Virtual memory region summary

## Visualize Heaps

```text
!wef.vis
!wef.vis L4
!wef.vis <heap-address>
```

`!wef.vis` is intentionally compact. It shows:

- Heap address
- Chunk count
- Busy/free counts and byte totals
- A compact map
- A small table of largest chunks

Map legend:

```text
A = allocated or busy
F = free
V = virtual allocation chunk
M = mixed bucket
```

Use DML buttons from the visual view:

- `[chunks]` opens the full chunk table
- `[segments]` lists segments
- `[flags]` decodes heap flags
- `[validate]` runs lightweight structural checks

## Inspect One Chunk

```text
!wef.chunk <addr>
!wef.heaps chunk <addr>
```

The address can point at the chunk header or user data. WEF walks backend chunks and reports the chunk containing that address. If no backend chunk is found, it invokes Windows `!ext.heap -x` to inspect LFH, segment heaps, and other native allocator state.

Output includes:

- Requested address
- Heap address
- Segment address
- Header address
- User-data address
- Total chunk size
- Usable size
- Previous size units
- Next chunk address
- Flags
- User-byte preview

If the requested address falls inside a free chunk, WEF prints a warning that live references to it are dangling (use-after-free candidate).

Useful follow-up buttons:

- `[hexdump user]`
- `[telescope user]`
- `[heap chunks]`
- `[validate heap]`

## List Chunks

```text
!wef.heaps chunks
!wef.heaps chunks <heap-address>
!wef.heaps chunks -busy <heap-address>
!wef.heaps chunks -free <heap-address>
!wef.heaps chunks -contains <addr>
```

The chunk table includes:

- Header address
- User address
- Size
- Usable size
- Decoded flags

`-contains <addr>` is useful when you want to find the owning chunk but still see surrounding heap context.

## Search Heap Contents

```text
!wef.heaps find <addr|text>
!wef.heaps find password
!wef.heaps find 0x4141414141414141
!wef.heaps find token <heap-address>
```

Numeric values are searched as pointer-sized little-endian values. Text values are searched as raw bytes.

Search limits are controlled by:

```text
heap.find.max_hits
heap.find.max_chunk_read
heap.chunk.max_search_chunks
```

## Show Segments

```text
!wef.heaps segments
!wef.heaps segments <heap-address>
```

Segment output includes:

- Owning heap
- Segment address
- First chunk entry
- Last valid entry
- Segment span
- Virtual memory region details

This is useful when a chunk walk stops early or when checking whether an address belongs to a backend segment.

## Heap Statistics

```text
!wef.heaps stats
!wef.heaps stats <heap-address>
```

Per heap, `stats` walks backend chunks and reports:

- Busy and free chunk counts with byte totals
- Utilization percentage of walked bytes
- A power-of-two size histogram (`<=0x10`, `<=0x20`, ...)
- Largest busy allocations with dump buttons (`heap.stats.top_count`)
- Adjacent free-run analysis: coalescible byte totals and per-run details as a fragmentation hint

Large free runs are normal after bursts of frees; sudden growth across snapshots often points at fragmentation or a leak/free mismatch.

## Cross References (xref)

```text
!wef.heaps xref <addr>
!wef.heaps xref <addr> <heap-address>
```

`xref` scans chunk user data for pointer-sized little-endian references to the target address. This answers "who still points at this allocation" during use-after-free analysis.

Hits in free chunks are marked `(stale)` in red; those are dangling-reference evidence. Hits in busy chunks show live holders.

Limits follow `heap.find.max_hits` and `heap.find.max_chunk_read`.

## Decode Heap Flags

```text
!wef.heaps flags
!wef.heaps flags <heap-address>
```

Displays `_HEAP.Flags`, `_HEAP.ForceFlags`, decoded flag names, and front-end type. This is useful for identifying debugging options, validation flags, execute-enabled heaps, and front-end heap behavior.

## Validate Heap Structure

```text
!wef.heaps validate
!wef.heaps validate <heap-address>
```

Validation is intentionally lightweight and read-only. It checks walked backend chunks for obvious structural problems such as:

- Zero or misaligned sizes
- Overlapping chunks
- Invalid encoded-header checksums and adjacent `PreviousSize` mismatches
- Walk truncation due to limits or unreadable metadata

It does not call process-mutating heap validation APIs.

## LFH Notes

Modern Windows often uses LFH or segment heaps. WEF's formatted backend tables do not enumerate their individual allocations. Use Microsoft's native allocator analysis through WEF:

```text
!wef.heaps native
!wef.heaps native stats [heap-address]
!wef.heaps native chunks [heap-address]
!wef.heaps lfh [nt-heap-address]
!wef.heaps freelist [nt-heap-address]
!wef.heaps triage [heap-or-address]
!wef.heaps pageheap [address]
!wef.heaps native leaks
```

The bracketed arguments above are optional; omit the brackets when entering an address. These commands invoke Windows `!ext.heap` and display its output. `lfh` / `freelist` are NT heap operations. `native stats`, `native chunks` and `triage` cover segment heaps using the installed Windows debugger. Page heap inspection requires page heap to have been enabled for the target. Native leak output reports reachability-based candidates, which need investigation.

## Compare Heap Stops

```text
!wef.heaps snapshot <heap-address>
g
!wef.heaps diff <heap-address>
!wef.heaps snapshot-clear
```

`snapshot` saves observed busy NT backend chunks for the current process. `diff` compares addresses, sizes, and heap ownership using the same heap selection and L limit; it reports added, missing, and changed blocks. The baseline remains until replaced or cleared. Both captures identify partial coverage. Missing blocks in an incomplete walk may be unreadable or outside the walk limits. Address reuse between stops and allocations created and freed between captures cannot be detected. This is a comparison of observations, not allocation/free instrumentation. See the [parity reference](parity.md) for remaining allocator gaps.

## Common Heap Triage Recipes

### Find the chunk for a crash pointer

```text
!wef.chunk @rax
```

### Check whether a freed allocation is still referenced

```text
!wef.chunk <freed-user-addr>
!wef.heaps xref <freed-user-addr>
```

### Profile a heap before and after an operation

```text
!wef.heaps stats
g
!wef.heaps stats
```

### Search all heaps for a marker

```text
!wef.heaps find marker
```

### Visualize the first few heaps

```text
!wef.vis L4
```

### Show only busy chunks in one heap

```text
!wef.heaps chunks -busy <heap-address>
```

### Check a heap before digging deeper

```text
!wef.heaps flags <heap-address>
!wef.heaps segments <heap-address>
!wef.heaps validate <heap-address>
```
