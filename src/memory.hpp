#pragma once

#include "command_router.hpp"

#include <string>

namespace wef {

HRESULT runTelescope(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runHexdump(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runSearchPattern(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runPrintFormat(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runXorMemory(DbgSession& session, const Output& out, const std::vector<std::string>& args);
std::string describePointer(DbgSession& session, ULONG64 value);
std::string describePointerChain(DbgSession& session, ULONG64 value, ULONG64 depth);
std::string previewString(DbgSession& session, ULONG64 address);

}
