#pragma once

#include "command_router.hpp"

#include <optional>
#include <string>
#include <vector>

namespace wef {

HRESULT runConfig(DbgSession& session, const Output& out, const std::vector<std::string>& args);
std::optional<std::string> configGet(std::string_view key);
ULONG64 configGetNumber(std::string_view key, ULONG64 fallback);
bool configGetBool(std::string_view key, bool fallback);
bool configSet(std::string_view key, std::string_view value);
std::vector<std::pair<std::string, std::string>> configItems();

}
