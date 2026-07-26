#include "instruction.hpp"

#include <Zydis.h>

#include <array>

namespace wef {

namespace {

BranchCondition branchCondition(ZydisMnemonic mnemonic) {
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_JB:
        return BranchCondition::Below;
    case ZYDIS_MNEMONIC_JBE:
        return BranchCondition::BelowEqual;
    case ZYDIS_MNEMONIC_JCXZ:
        return BranchCondition::Counter16Zero;
    case ZYDIS_MNEMONIC_JECXZ:
        return BranchCondition::Counter32Zero;
    case ZYDIS_MNEMONIC_JL:
        return BranchCondition::Less;
    case ZYDIS_MNEMONIC_JLE:
        return BranchCondition::LessEqual;
    case ZYDIS_MNEMONIC_JNB:
        return BranchCondition::NotBelow;
    case ZYDIS_MNEMONIC_JNBE:
        return BranchCondition::NotBelowEqual;
    case ZYDIS_MNEMONIC_JNL:
        return BranchCondition::NotLess;
    case ZYDIS_MNEMONIC_JNLE:
        return BranchCondition::NotLessEqual;
    case ZYDIS_MNEMONIC_JNO:
        return BranchCondition::NotOverflow;
    case ZYDIS_MNEMONIC_JNP:
        return BranchCondition::NotParity;
    case ZYDIS_MNEMONIC_JNS:
        return BranchCondition::NotSign;
    case ZYDIS_MNEMONIC_JNZ:
        return BranchCondition::NotZero;
    case ZYDIS_MNEMONIC_JO:
        return BranchCondition::Overflow;
    case ZYDIS_MNEMONIC_JP:
        return BranchCondition::Parity;
    case ZYDIS_MNEMONIC_JRCXZ:
        return BranchCondition::Counter64Zero;
    case ZYDIS_MNEMONIC_JS:
        return BranchCondition::Sign;
    case ZYDIS_MNEMONIC_JZ:
        return BranchCondition::Zero;
    case ZYDIS_MNEMONIC_LOOP:
        return BranchCondition::Loop;
    case ZYDIS_MNEMONIC_LOOPE:
        return BranchCondition::LoopEqual;
    case ZYDIS_MNEMONIC_LOOPNE:
        return BranchCondition::LoopNotEqual;
    default:
        return BranchCondition::None;
    }
}

bool flagSet(ULONG64 flags, ULONG64 mask) {
    return (flags & mask) != 0;
}

}

bool decodeInstruction(DbgSession& session, ULONG64 address, DecodedInstruction& decoded) {
    std::array<unsigned char, ZYDIS_MAX_INSTRUCTION_LENGTH> bytes = {};
    ULONG read = 0;
    const HRESULT readHr = session.readVirtual(
        address,
        bytes.data(),
        static_cast<ULONG>(bytes.size()),
        &read);
    if (FAILED(readHr) || read == 0) {
        return false;
    }

    const bool is32Bit = session.effectiveProcessor() == IMAGE_FILE_MACHINE_I386 || session.pointerSize() == 4;
    ZydisDecoder decoder = {};
    const ZyanStatus initStatus = ZydisDecoderInit(
        &decoder,
        is32Bit ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_64,
        is32Bit ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64);
    if (!ZYAN_SUCCESS(initStatus)) {
        return false;
    }

    ZydisDecodedInstruction instruction = {};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {};
    const ZyanStatus decodeStatus = ZydisDecoderDecodeFull(
        &decoder,
        bytes.data(),
        read,
        &instruction,
        operands);
    if (!ZYAN_SUCCESS(decodeStatus) || instruction.length == 0) {
        return false;
    }

    decoded = {};
    decoded.length = instruction.length;
    decoded.conditionalBranch = instruction.meta.category == ZYDIS_CATEGORY_COND_BR;
    decoded.unconditionalBranch = instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
    decoded.call = instruction.meta.category == ZYDIS_CATEGORY_CALL;
    decoded.ret = instruction.meta.category == ZYDIS_CATEGORY_RET;
    decoded.condition = branchCondition(instruction.mnemonic);

    if (decoded.conditionalBranch || decoded.unconditionalBranch || decoded.call) {
        for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
            if (operands[i].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !operands[i].imm.is_relative) {
                continue;
            }
            ZyanU64 target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[i], address, &target))) {
                decoded.hasTarget = true;
                decoded.target = target;
            }
            break;
        }
    }
    return true;
}

bool evaluateBranch(DbgSession& session, const DecodedInstruction& decoded, bool& taken) {
    if (!decoded.conditionalBranch || decoded.condition == BranchCondition::None) {
        return false;
    }

    ULONG64 flags = 0;
    if (!session.readRegister("efl", flags)) {
        return false;
    }
    const bool carry = flagSet(flags, 1ULL << 0);
    const bool parity = flagSet(flags, 1ULL << 2);
    const bool zero = flagSet(flags, 1ULL << 6);
    const bool sign = flagSet(flags, 1ULL << 7);
    const bool overflow = flagSet(flags, 1ULL << 11);

    switch (decoded.condition) {
    case BranchCondition::Below:
        taken = carry;
        return true;
    case BranchCondition::BelowEqual:
        taken = carry || zero;
        return true;
    case BranchCondition::Less:
        taken = sign != overflow;
        return true;
    case BranchCondition::LessEqual:
        taken = zero || sign != overflow;
        return true;
    case BranchCondition::NotBelow:
        taken = !carry;
        return true;
    case BranchCondition::NotBelowEqual:
        taken = !carry && !zero;
        return true;
    case BranchCondition::NotLess:
        taken = sign == overflow;
        return true;
    case BranchCondition::NotLessEqual:
        taken = !zero && sign == overflow;
        return true;
    case BranchCondition::NotOverflow:
        taken = !overflow;
        return true;
    case BranchCondition::NotParity:
        taken = !parity;
        return true;
    case BranchCondition::NotSign:
        taken = !sign;
        return true;
    case BranchCondition::NotZero:
        taken = !zero;
        return true;
    case BranchCondition::Overflow:
        taken = overflow;
        return true;
    case BranchCondition::Parity:
        taken = parity;
        return true;
    case BranchCondition::Sign:
        taken = sign;
        return true;
    case BranchCondition::Zero:
        taken = zero;
        return true;
    case BranchCondition::Counter16Zero:
    case BranchCondition::Counter32Zero:
    case BranchCondition::Counter64Zero:
    case BranchCondition::Loop:
    case BranchCondition::LoopEqual:
    case BranchCondition::LoopNotEqual: {
        ULONG64 counter = 0;
        const char* registerName =
            decoded.condition == BranchCondition::Counter16Zero ? "ecx" :
            decoded.condition == BranchCondition::Counter32Zero ? "ecx" :
            decoded.condition == BranchCondition::Counter64Zero ? "rcx" :
            session.pointerSize() == 8 ? "rcx" : "ecx";
        if (!session.readRegister(registerName, counter)) {
            return false;
        }
        if (decoded.condition == BranchCondition::Counter16Zero ||
            decoded.condition == BranchCondition::Counter32Zero ||
            decoded.condition == BranchCondition::Counter64Zero) {
            const ULONG64 counterMask =
                decoded.condition == BranchCondition::Counter16Zero ? 0xffffULL :
                decoded.condition == BranchCondition::Counter32Zero ? 0xffffffffULL :
                ~0ULL;
            taken = (counter & counterMask) == 0;
            return true;
        }
        const ULONG64 mask = session.pointerSize() == 8 ? ~0ULL : 0xffffffffULL;
        const bool counterNonZero = ((counter - 1) & mask) != 0;
        taken =
            decoded.condition == BranchCondition::Loop ? counterNonZero :
            decoded.condition == BranchCondition::LoopEqual ? counterNonZero && zero :
            counterNonZero && !zero;
        return true;
    }
    default:
        return false;
    }
}

}
