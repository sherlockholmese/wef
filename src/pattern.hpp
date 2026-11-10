#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT runPattern(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runCyclic(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
