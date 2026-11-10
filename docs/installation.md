# Installation and Loading

This page covers building, loading, and enabling aliases for WEF.

## Requirements

- Windows x64 target environment
- Visual Studio 2026 with Desktop development with C++
- Debugging Tools for Windows
- WinDbg or WinDbg Preview
- DbgEng SDK installed at:

```text
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sdk\
```

If your Debugging Tools installation uses another path, edit the `DbgSdkDir` user macro in `wef.vcxproj`.

## Build From Source

Open `wef.sln` in Visual Studio and build one of:

```text
Debug|x64
Release|x64
```

Expected outputs:

```text
x64\Debug\wef.dll
x64\Release\wef.dll
```

## Load Manually

Use an absolute path when testing a local build:

```text
.load C:\dev\wef\x64\Release\wef.dll
!wef
```

If the command list appears, the extension is loaded.

## Install As An Engine Extension

For persistent loading, copy the release DLL to:

```text
%LOCALAPPDATA%\Dbg\EngineExtensions\wef.dll
```

Restart WinDbg and run:

```text
!wef
```

If your WinDbg build does not auto-load by module name, load once manually:

```text
.load wef
```

## Optional Aliases

Canonical commands like `!wef.ctx` and `!wef.vmmap` always work. Short aliases are opt-in.

Install aliases:

```text
!wef.install
```

Remove aliases:

```text
!wef.uninstall
```

Show configured alias mappings:

```text
!wef.aliases
```

Selected installed aliases (use `!wef.aliases` for the complete list):

```text
ctx
telescope
hexdump
search-pattern
search
cyclic
scan
rop
nearpc
dumpargs
vmmap
pattern
checksec
chunk
wef-heap
vis
ttd-events
wef-config
```

## DML Buttons

WEF enables DML output by default. In WinDbg, bracketed labels are clickable command links:

```text
[dump] [tel] [chunk] [segments] [ttd gui]
```

Disable DML if you need plain output:

```text
!wef.config set output.use_dml false
```

Re-enable it:

```text
!wef.config set output.use_dml true
```
