#pragma once

#include "command_router.hpp"

namespace wef {

HRESULT runVmmap(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runXinfo(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runXfiles(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runArch(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runEval(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runProcessStatus(DbgSession& session, const Output& out, const std::vector<std::string>& args);
HRESULT runPie(DbgSession& session, const Output& out, const std::vector<std::string>& args);

}
