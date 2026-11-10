#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT runPatch(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runStub(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runExecution(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runNop(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runSkipi(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runEditFlags(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runStepover(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runEntryBreak(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
