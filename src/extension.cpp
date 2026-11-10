#include "command_router.hpp"

#include <windows.h>
#include <dbgeng.h>

#include <string>

#define WEF_EXPORT extern "C" __declspec(dllexport)
#define WEF_ALIAS_TARGET extern "C"

#if defined(_MSC_VER)
#pragma comment(linker, "/EXPORT:wef=wef_entry")
#endif

WEF_EXPORT HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags) {
    *Version = (1u << 16) | 0u;
    *Flags = 0;
    return S_OK;
}

WEF_EXPORT void CALLBACK DebugExtensionUninitialize(void) {}

WEF_ALIAS_TARGET HRESULT CALLBACK wef_entry(IDebugClient* client, PCSTR args) {
    return wef::commands::WefHelp(client, args);
}

WEF_EXPORT HRESULT CALLBACK install(IDebugClient* client, PCSTR args) {
    return wef::commands::Install(client, args);
}

WEF_EXPORT HRESULT CALLBACK uninstall(IDebugClient* client, PCSTR args) {
    return wef::commands::Uninstall(client, args);
}

WEF_EXPORT HRESULT CALLBACK aliases(IDebugClient* client, PCSTR args) {
    return wef::commands::Aliases(client, args);
}

WEF_EXPORT HRESULT CALLBACK ctx(IDebugClient* client, PCSTR args) {
    return wef::commands::Ctx(client, args);
}

WEF_EXPORT HRESULT CALLBACK context(IDebugClient* client, PCSTR args) {
    return wef::commands::Ctx(client, args);
}

WEF_EXPORT HRESULT CALLBACK registers(IDebugClient* client, PCSTR args) {
    return wef::commands::Registers(client, args);
}

WEF_EXPORT HRESULT CALLBACK telescope(IDebugClient* client, PCSTR args) {
    return wef::commands::Telescope(client, args);
}

WEF_EXPORT HRESULT CALLBACK dereference(IDebugClient* client, PCSTR args) {
    return wef::commands::Dereference(client, args);
}

WEF_EXPORT HRESULT CALLBACK hexdump(IDebugClient* client, PCSTR args) {
    return wef::commands::Hexdump(client, args);
}

WEF_EXPORT HRESULT CALLBACK search_pattern(IDebugClient* client, PCSTR args) {
    return wef::commands::SearchPattern(client, args);
}

WEF_EXPORT HRESULT CALLBACK print_format(IDebugClient* client, PCSTR args) {
    return wef::commands::PrintFormat(client, args);
}

WEF_EXPORT HRESULT CALLBACK xor_memory(IDebugClient* client, PCSTR args) {
    return wef::commands::XorMemory(client, args);
}

WEF_EXPORT HRESULT CALLBACK memory(IDebugClient* client, PCSTR args) {
    return wef::commands::Memory(client, args);
}

WEF_EXPORT HRESULT CALLBACK vmmap(IDebugClient* client, PCSTR args) {
    return wef::commands::Vmmap(client, args);
}

WEF_EXPORT HRESULT CALLBACK xinfo(IDebugClient* client, PCSTR args) {
    return wef::commands::Xinfo(client, args);
}

WEF_EXPORT HRESULT CALLBACK xfiles(IDebugClient* client, PCSTR args) {
    return wef::commands::Xfiles(client, args);
}

WEF_EXPORT HRESULT CALLBACK arch(IDebugClient* client, PCSTR args) {
    return wef::commands::Arch(client, args);
}

WEF_EXPORT HRESULT CALLBACK eval(IDebugClient* client, PCSTR args) {
    return wef::commands::Eval(client, args);
}

WEF_EXPORT HRESULT CALLBACK process_status(IDebugClient* client, PCSTR args) {
    return wef::commands::ProcessStatus(client, args);
}

WEF_EXPORT HRESULT CALLBACK pie(IDebugClient* client, PCSTR args) {
    return wef::commands::Pie(client, args);
}

WEF_EXPORT HRESULT CALLBACK checksec(IDebugClient* client, PCSTR args) {
    return wef::commands::Checksec(client, args);
}

WEF_EXPORT HRESULT CALLBACK pe_info(IDebugClient* client, PCSTR args) {
    return wef::commands::PeInfo(client, args);
}

WEF_EXPORT HRESULT CALLBACK iat(IDebugClient* client, PCSTR args) {
    return wef::commands::Iat(client, args);
}

WEF_EXPORT HRESULT CALLBACK got(IDebugClient* client, PCSTR args) {
    return wef::commands::Iat(client, args);
}

WEF_EXPORT HRESULT CALLBACK canary(IDebugClient* client, PCSTR args) {
    return wef::commands::Canary(client, args);
}

WEF_EXPORT HRESULT CALLBACK pattern(IDebugClient* client, PCSTR args) {
    return wef::commands::Pattern(client, args);
}

WEF_EXPORT HRESULT CALLBACK patch(IDebugClient* client, PCSTR args) {
    return wef::commands::Patch(client, args);
}

WEF_EXPORT HRESULT CALLBACK nop(IDebugClient* client, PCSTR args) {
    return wef::commands::Nop(client, args);
}

WEF_EXPORT HRESULT CALLBACK skipi(IDebugClient* client, PCSTR args) {
    return wef::commands::Skipi(client, args);
}

WEF_EXPORT HRESULT CALLBACK edit_flags(IDebugClient* client, PCSTR args) {
    return wef::commands::EditFlags(client, args);
}

WEF_EXPORT HRESULT CALLBACK stepover(IDebugClient* client, PCSTR args) {
    return wef::commands::Stepover(client, args);
}

WEF_EXPORT HRESULT CALLBACK entry_break(IDebugClient* client, PCSTR args) {
    return wef::commands::EntryBreak(client, args);
}

WEF_EXPORT HRESULT CALLBACK name_break(IDebugClient* client, PCSTR args) {
    return wef::commands::NameBreak(client, args);
}

WEF_EXPORT HRESULT CALLBACK heaps(IDebugClient* client, PCSTR args) {
    return wef::commands::Heaps(client, args);
}

WEF_EXPORT HRESULT CALLBACK chunk(IDebugClient* client, PCSTR args) {
    const std::string fullArgs = std::string("chunk ") + (args != nullptr ? args : "");
    return wef::commands::Heaps(client, fullArgs.c_str());
}

WEF_EXPORT HRESULT CALLBACK vis(IDebugClient* client, PCSTR args) {
    return wef::commands::Vis(client, args);
}

WEF_EXPORT HRESULT CALLBACK stack(IDebugClient* client, PCSTR args) {
    return wef::commands::Stack(client, args);
}

WEF_EXPORT HRESULT CALLBACK colors(IDebugClient* client, PCSTR args) {
    return wef::commands::Colors(client, args);
}

WEF_EXPORT HRESULT CALLBACK ttd(IDebugClient* client, PCSTR args) {
    return wef::commands::Ttd(client, args);
}

WEF_EXPORT HRESULT CALLBACK config(IDebugClient* client, PCSTR args) {
    return wef::commands::Config(client, args);
}

WEF_EXPORT HRESULT CALLBACK search(IDebugClient* client, PCSTR args) {
    return wef::commands::Search(client, args);
}

WEF_EXPORT HRESULT CALLBACK cyclic(IDebugClient* client, PCSTR args) {
    return wef::commands::Cyclic(client, args);
}

WEF_EXPORT HRESULT CALLBACK scan(IDebugClient* client, PCSTR args) {
    return wef::commands::Scan(client, args);
}

WEF_EXPORT HRESULT CALLBACK rop(IDebugClient* client, PCSTR args) {
    return wef::commands::Rop(client, args);
}

WEF_EXPORT HRESULT CALLBACK nearpc(IDebugClient* client, PCSTR args) {
    return wef::commands::Nearpc(client, args);
}

WEF_EXPORT HRESULT CALLBACK distance(IDebugClient* client, PCSTR args) {
    return wef::commands::Distance(client, args);
}

WEF_EXPORT HRESULT CALLBACK dumpargs(IDebugClient* client, PCSTR args) {
    return wef::commands::Dumpargs(client, args);
}

WEF_EXPORT HRESULT CALLBACK hex2ptr(IDebugClient* client, PCSTR args) {
    return wef::commands::Hex2ptr(client, args);
}

WEF_EXPORT HRESULT CALLBACK stub(IDebugClient* client, PCSTR args) {
    return wef::commands::Stub(client, args);
}

WEF_EXPORT HRESULT CALLBACK nextcall(IDebugClient* client, PCSTR args) {
    return wef::commands::Nextcall(client, args);
}

WEF_EXPORT HRESULT CALLBACK nextret(IDebugClient* client, PCSTR args) {
    return wef::commands::Nextret(client, args);
}

WEF_EXPORT HRESULT CALLBACK stepout(IDebugClient* client, PCSTR args) {
    return wef::commands::Stepout(client, args);
}

WEF_EXPORT HRESULT CALLBACK regs(IDebugClient* client, PCSTR args) {
    return wef::commands::Registers(client, args);
}

WEF_EXPORT HRESULT CALLBACK heap(IDebugClient* client, PCSTR args) {
    return wef::commands::Heaps(client, args);
}
