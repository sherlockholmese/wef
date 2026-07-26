#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT runPatch(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runNop(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runSkipi(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
