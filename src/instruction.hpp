#pragma once

#include "dbg_session.hpp"

namespace wef {

enum class BranchCondition {
    None,
    Below,
    BelowEqual,
    Counter16Zero,
    Counter32Zero,
    Counter64Zero,
    Less,
    LessEqual,
    NotBelow,
    NotBelowEqual,
    NotLess,
    NotLessEqual,
    NotOverflow,
    NotParity,
    NotSign,
    NotZero,
    Overflow,
    Parity,
    Sign,
    Zero,
    Loop,
    LoopEqual,
    LoopNotEqual,
};

struct DecodedInstruction {
    ULONG length = 0;
    bool conditionalBranch = false;
    bool unconditionalBranch = false;
    bool call = false;
    bool ret = false;
    bool hasTarget = false;
    ULONG64 target = 0;
    BranchCondition condition = BranchCondition::None;
};

bool decodeInstruction(DbgSession& session, ULONG64 address, DecodedInstruction& decoded);
bool evaluateBranch(DbgSession& session, const DecodedInstruction& decoded, bool& taken);

}
