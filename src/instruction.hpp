#pragma once

#include "dbg_session.hpp"

namespace wef {

struct DecodedInstruction {
    ULONG length = 0;
    bool conditionalBranch = false;
    bool unconditionalBranch = false;
    bool call = false;
    bool ret = false;
    bool hasTarget = false;
    ULONG64 target = 0;
};

bool decodeInstruction(DbgSession& session, ULONG64 address, DecodedInstruction& decoded);

}
