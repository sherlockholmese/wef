#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT runChecksec(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runPeInfo(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runIat(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runCanary(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
