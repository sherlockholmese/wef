#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT runStack(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runCanaryScan(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
