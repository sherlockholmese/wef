# Memory, VMMap, and Exploit Helpers

This page covers WEF commands for memory maps, memory searches, hexdumps, pointer inspection, and cyclic patterns.

For typed searches (`!wef.search`), mapping-to-mapping pointer scans (`!wef.scan`), and executable-memory gadgets (`!wef.rop`), see the [GEF/pwndbg parity reference](parity.md). It also documents supported upstream switches and differences.

## VMMap

```text
!wef.vmmap [-all|-free] [-commit|-reserve] [-x|-w|-rwx] [-image|-mapped|-private] [-module <name>] [-contains <addr>] [L<count>]
```

`!wef.vmmap` enumerates virtual memory regions and prints:

- Base address
- End address
- Region size
- State
- Protection
- Type
- Module name when available
- DML action buttons

## VMMap Filters

### Executable regions

```text
!wef.vmmap -x
```

Useful for finding code, JIT pages, shellcode candidates, or executable private mappings.

### Writable regions

```text
!wef.vmmap -w
```

Useful for finding data regions, heap-like regions, and writable private mappings.

### Writable and executable regions

```text
!wef.vmmap -rwx
```

This filters for pages that are both writable and executable.

### Region type filters

```text
!wef.vmmap -image
!wef.vmmap -mapped
!wef.vmmap -private
```

### Module filters

```text
!wef.vmmap -module ntdll
!wef.vmmap -image -module kernelbase
```

### Address containment

```text
!wef.vmmap -contains @rsp
!wef.vmmap -contains 00000000`0019f000
```

This finds the memory region containing a specific address.

### Limit output

```text
!wef.vmmap L20
```

## VMMap DML Buttons

Rows include buttons:

- `[dump]`, run `!wef.hexdump` at the region base
- `[search]`, start a search in the region
- `[contains]`, re-run vmmap focused on that address

## Search Pattern

```text
!wef.search_pattern <text|addr|hex:bytes> [start] [L<size>] [-max <count>] [-x|-w|-rwx] [-image|-mapped|-private]
```

`search_pattern` scans committed readable pages. It skips guard and no-access pages.

## Pattern Formats

### Plain text

```text
!wef.search_pattern password
```

Plain text is a single WinDbg argument token.

### Explicit string

```text
!wef.search_pattern str:password
```

This is useful when the string might look like a number or expression.

### Hex bytes

```text
!wef.search_pattern hex:41424344
!wef.search_pattern hex:cc
```

`hex:` takes a sequence of hexadecimal bytes.

### Numeric or pointer-sized values

```text
!wef.search_pattern 0x4141414141414141
!wef.search_pattern @rsp
```

Pointer-like values and expressions are searched as pointer-sized little-endian byte sequences.

## Search Ranges

Search the whole process:

```text
!wef.search_pattern hex:41414141
```

Search a specific range:

```text
!wef.search_pattern hex:41414141 00000000`00190000 L10000
```

Limit hits:

```text
!wef.search_pattern token -max 10
```

Filter to executable pages:

```text
!wef.search_pattern hex:cc -x
```

Filter to private writable pages:

```text
!wef.search_pattern marker -w -private
```

## Search Result Buttons

Each match includes:

- `[dump]`, hexdump at the match
- `[tel]`, telescope at the match
- `[chunk]`, inspect the containing heap chunk

## Hexdump

```text
!wef.hexdump <addr> [L<size>] [-force]
```

Examples:

```text
!wef.hexdump @rsp L80
!wef.hexdump poi(@rsp) L100
!wef.hexdump <addr> L2000 -force
```

Reads larger than `0x1000` require `-force`.

## Telescope

```text
!wef.telescope [addr] [L<count>]
```

Examples:

```text
!wef.telescope @rsp L20
!wef.telescope poi(@rsp) L8
```

Telescope annotates pointer-sized values with symbols, strings, memory region data, and pointer chains.

## Cyclic Patterns

```text
!wef.pattern create [-n <width>] [-a <alphabet>] [--legacy] <length>
!wef.pattern offset [-n <width>] [--legacy] <value|str:text> [L<max-length>]
!wef.cyclic [-n <width>] [<length>|-l <value>]
```

Create a pattern:

```text
!wef.pattern create -n 4 512
```

Find an offset:

```text
!wef.pattern offset -n 4 str:daaa L1000
!wef.pattern offset -n 4 0x61616164 L1000
```

Patterns now use the same lowercase De Bruijn ordering as GEF/pwntools. Width defaults to the target pointer size (8 on x64), so use `-n 4` explicitly when working with four-byte patterns. Searches report both endian orders. `str:` forces a literal token. The legacy sequence is still available explicitly:

```text
!wef.pattern create --legacy 512
!wef.pattern offset --legacy 0x41336141 L1000
```

## Exploit Triage Recipes

### Find crash-pattern offset

```text
!wef.pattern offset @rip L8192
```

Use the same `-n` as pattern creation. Four-byte overwrites should use a four-byte sequence and `-n 4`; wider numeric values are rejected instead of being silently truncated.

### Find executable private memory

```text
!wef.vmmap -x -private
```

### Search the stack for a marker

```text
!wef.vmmap -contains @rsp
!wef.search_pattern marker @rsp L4000
```

### Search for breakpoint bytes in executable pages

```text
!wef.search_pattern hex:cc -x
```
