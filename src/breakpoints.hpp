#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT addNamedBreakpoint(
    DbgSession& session,
    const Output& out,
    std::string_view name,
    ULONG64 address);
HRESULT runNameBreak(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
