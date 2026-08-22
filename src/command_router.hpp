#pragma once

#include "dbg_session.hpp"
#include "output.hpp"

#include <dbgeng.h>

#include <string>
#include <string_view>
#include <vector>

namespace wef {

using CommandHandler = HRESULT (*)(DbgSession&, const Output&, const std::vector<std::string>&);

HRESULT executeCommand(IDebugClient* client, PCSTR args, CommandHandler handler);
std::vector<std::string> splitArgs(PCSTR args);
bool parseLengthToken(std::string_view token, ULONG64& value);
bool parseNumber(std::string_view text, ULONG64& value);
std::string joinArgs(const std::vector<std::string>& args, size_t start, size_t end);

namespace commands {

HRESULT WefHelp(IDebugClient* client, PCSTR args);
HRESULT Install(IDebugClient* client, PCSTR args);
HRESULT Uninstall(IDebugClient* client, PCSTR args);
HRESULT Aliases(IDebugClient* client, PCSTR args);
HRESULT Ctx(IDebugClient* client, PCSTR args);
HRESULT Registers(IDebugClient* client, PCSTR args);
HRESULT Telescope(IDebugClient* client, PCSTR args);
HRESULT Dereference(IDebugClient* client, PCSTR args);
HRESULT Hexdump(IDebugClient* client, PCSTR args);
HRESULT SearchPattern(IDebugClient* client, PCSTR args);
HRESULT PrintFormat(IDebugClient* client, PCSTR args);
HRESULT XorMemory(IDebugClient* client, PCSTR args);
HRESULT Memory(IDebugClient* client, PCSTR args);
HRESULT Vmmap(IDebugClient* client, PCSTR args);
HRESULT Xinfo(IDebugClient* client, PCSTR args);
HRESULT Xfiles(IDebugClient* client, PCSTR args);
HRESULT Arch(IDebugClient* client, PCSTR args);
HRESULT Eval(IDebugClient* client, PCSTR args);
HRESULT ProcessStatus(IDebugClient* client, PCSTR args);
HRESULT Pie(IDebugClient* client, PCSTR args);
HRESULT Checksec(IDebugClient* client, PCSTR args);
HRESULT PeInfo(IDebugClient* client, PCSTR args);
HRESULT Iat(IDebugClient* client, PCSTR args);
HRESULT Canary(IDebugClient* client, PCSTR args);
HRESULT Pattern(IDebugClient* client, PCSTR args);
HRESULT Patch(IDebugClient* client, PCSTR args);
HRESULT Nop(IDebugClient* client, PCSTR args);
HRESULT Skipi(IDebugClient* client, PCSTR args);
HRESULT EditFlags(IDebugClient* client, PCSTR args);
HRESULT Stepover(IDebugClient* client, PCSTR args);
HRESULT EntryBreak(IDebugClient* client, PCSTR args);
HRESULT NameBreak(IDebugClient* client, PCSTR args);
HRESULT Heaps(IDebugClient* client, PCSTR args);
HRESULT Vis(IDebugClient* client, PCSTR args);
HRESULT Stack(IDebugClient* client, PCSTR args);
HRESULT Colors(IDebugClient* client, PCSTR args);
HRESULT Ttd(IDebugClient* client, PCSTR args);
HRESULT Config(IDebugClient* client, PCSTR args);

}

}
