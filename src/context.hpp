#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT runCtx(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runRegisters(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
