#include "instruction.hpp"

#include <Zydis.h>

#include <array>

namespace wef {

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

}
