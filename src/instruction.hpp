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
    bool system = false;
    bool hasTarget = false;
    ULONG64 target = 0;
    ULONG addressWidth = 0;
    BranchCondition condition = BranchCondition::None;
};

bool decodeInstruction(DbgSession& session, ULONG64 address, DecodedInstruction& decoded);
bool decodeInstructionBytes(const void* bytes, size_t size, bool is32Bit, ULONG64 address,
                            DecodedInstruction& decoded, std::string* text = nullptr);
bool evaluateBranch(DbgSession& session, const DecodedInstruction& decoded, bool& taken);

}
