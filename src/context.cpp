#include "context.hpp"

#include "config.hpp"
#include "instruction.hpp"
#include "memory.hpp"

#include <array>
#include <sstream>

namespace wef {

namespace {

std::string padRight(std::string text, size_t width) {
    if (text.size() >= width) {
        return text;
    }
    text.append(width - text.size(), ' ');
    return text;
}

void usage(const Output& out) {
    out.line("usage: !wef.ctx [-full] [-regs] [-stack L<count>] [-code L<count>]");
    out.line("       !wef.ctx auto <on|off|status>");
}

void registersUsage(const Output& out) {
    out.line("usage: !wef.registers");
}

bool nextLength(const std::vector<std::string>& args, size_t& index, ULONG64& value) {
    if (index + 1 >= args.size()) {
        return false;
    }
    ++index;
    return parseLengthToken(args[index], value);
}

std::string decodeFlags(ULONG64 value) {
    struct Flag {
        ULONG64 mask;
        const char* name;
    };
    static constexpr std::array<Flag, 16> flags = {{
        {1ULL << 0, "CF"},
        {1ULL << 2, "PF"},
        {1ULL << 4, "AF"},
        {1ULL << 6, "ZF"},
        {1ULL << 7, "SF"},
        {1ULL << 8, "TF"},
        {1ULL << 9, "IF"},
        {1ULL << 10, "DF"},
        {1ULL << 11, "OF"},
        {1ULL << 14, "NT"},
        {1ULL << 16, "RF"},
        {1ULL << 17, "VM"},
        {1ULL << 18, "AC"},
        {1ULL << 19, "VIF"},
        {1ULL << 20, "VIP"},
        {1ULL << 21, "ID"},
    }};

    std::string result;
    for (const auto& flag : flags) {
        if ((value & flag.mask) == 0) {
            continue;
        }
        if (!result.empty()) {
            result += ' ';
        }
        result += flag.name;
    }

    if (!result.empty()) {
        result += ' ';
    }
    result += "IOPL=" + std::to_string((value >> 12) & 3);
    return result;
}

void printRegisters(DbgSession& session, const Output& out) {
    out.heading("Registers");
    const auto regs = session.readCommonRegisters();
    if (regs.empty()) {
        out.line("  unavailable: register interface returned no common registers");
        return;
    }

    std::string line = "  ";
    size_t columns = 0;
    for (const auto& reg : regs) {
        const std::string item = padRight(reg.name, 4) + " " + formatAddress(reg.value);
        line += padRight(item, 27);
        ++columns;
        if (columns == 3) {
            out.line(line);
            line = "  ";
            columns = 0;
        }
    }
    if (columns != 0) {
        out.line(line);
    }

    if (configGetBool("ctx.regs.show_flags", true)) {
        for (const auto& reg : regs) {
            if (reg.name == "efl" || reg.name == "rflags" || reg.name == "eflags") {
                out.field("Flags", decodeFlags(reg.value));
                break;
            }
        }
    }
}

void printCode(DbgSession& session, const Output& out, ULONG64 ip, ULONG64 codeLines) {
    out.heading("Code");
    if (ip == 0) {
        out.line("  unavailable: instruction pointer is unavailable");
        return;
    }

    const std::string symbol = session.resolveSymbol(ip);
    if (!symbol.empty()) {
        out.dmlLine(
            "  symbol: " + symbol,
            std::string("  <col fg=\"green\">symbol:</col> <col fg=\"cyan\">") + dmlEscape(symbol) + "</col>");
    }

    DecodedInstruction decoded;
    if (decodeInstruction(session, ip, decoded) && decoded.hasTarget) {
        if (decoded.conditionalBranch) {
            bool taken = false;
            if (evaluateBranch(session, decoded, taken)) {
                const ULONG64 destination = taken ? decoded.target : ip + decoded.length;
                const std::string state = taken ? "taken" : "not taken";
                out.dmlLine(
                    "  branch: " + state + " -> " + formatAddress(destination),
                    "  <col fg=\"green\">branch:</col> <col fg=\"" +
                        std::string(taken ? "green" : "yellow") + "\">" + state + "</col> -&gt; " +
                        dmlCommandLink(formatAddress(destination), "!wef.xinfo " + formatAddress(destination)));
            } else {
                out.field("Branch target", formatAddress(decoded.target));
            }
        } else if (decoded.call || decoded.unconditionalBranch) {
            out.dmlLine(
                "  target: " + formatAddress(decoded.target),
                "  <col fg=\"green\">target:</col> " +
                    dmlCommandLink(formatAddress(decoded.target), "!wef.xinfo " + formatAddress(decoded.target)));
        }
    }

    ULONG64 current = ip;
    for (ULONG64 i = 0; i < codeLines; ++i) {
        ULONG64 next = current;
        const std::string disasm = session.disassembleLine(current, next);
        if (disasm.empty()) {
            out.line("  " + formatAddress(current) + "  disassembly unavailable");
            break;
        }
        const std::string marker = i == 0 ? "=> " : "   ";
        out.normal(marker);
        out.normal(disasm);
        if (!disasm.empty() && disasm.back() != '\n') {
            out.blank();
        }
        if (next == current) {
            break;
        }
        current = next;
    }
}

void printStack(DbgSession& session, const Output& out, std::string_view spName, ULONG64 sp, ULONG64 count) {
    out.heading("Stack");
    if (sp == 0) {
        out.line("  unavailable: stack pointer is unavailable");
        return;
    }

    const ULONG ptrSize = session.pointerSize();
    out.line("  #    offset        address             value               dereference");
    out.line("  --   ------------  -----------------   -----------------   ----------------------------------------");
    for (ULONG64 i = 0; i < count; ++i) {
        const ULONG64 current = sp + (i * ptrSize);
        ULONG64 value = 0;
        const std::string slot = formatHex(i, 2);
        const std::string offset = std::string(spName) + "+0x" + formatHex(i * ptrSize, 4);
        const std::string paddedSlot = padRight(slot, 4);
        const std::string paddedOffset = padRight(offset, 12);
        std::ostringstream line;
        line << "  " << paddedSlot << " " << paddedOffset << "  ";
        line << formatAddress(current) << "  ";
        if (!session.readPointer(current, value)) {
            line << "<read failed>";
            out.line(line.str());
            continue;
        }
        const std::string desc = describePointerChain(session, value, configGetNumber("dereference.depth", 3));
        line << formatAddress(value) << "  " << desc;
        out.line(line.str());
    }
}

}

HRESULT runCtx(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!args.empty() && args[0] == "auto") {
        if (args.size() != 2 || (args[1] != "on" && args[1] != "off" && args[1] != "status")) {
            usage(out);
            return S_OK;
        }
        if (args[1] == "status") {
            out.field("Automatic context", configGetBool("ctx.auto", false) ? "on" : "off");
            return S_OK;
        }

        const bool enable = args[1] == "on";
        const char* command = enable ? ".pcmd -s \"!wef.ctx\"" : ".pcmd -c";
        const HRESULT hr = session.control()->Execute(DEBUG_OUTCTL_ALL_CLIENTS, command, DEBUG_EXECUTE_DEFAULT);
        if (FAILED(hr)) {
            out.error("failed to update automatic context: " + formatHResult(hr) + "\n");
            return S_OK;
        }
        configSet("ctx.auto", enable ? "true" : "false");
        out.field("Automatic context", enable ? "on" : "off");
        if (enable) {
            out.warning("WinDbg supports one prompt command; enabling automatic context replaces any existing .pcmd command.\n");
        }
        return S_OK;
    }

    ULONG64 stackCount = configGetNumber("ctx.stack.count", 20);
    ULONG64 codeLines = configGetNumber("ctx.code.lines", 8);
    bool full = false;
    bool regsOnly = false;

    for (size_t i = 0; i < args.size(); ++i) {
        const auto& arg = args[i];
        if (arg == "-full") {
            full = true;
            continue;
        }
        if (arg == "-regs") {
            regsOnly = true;
            continue;
        }
        if (arg == "-stack") {
            if (!nextLength(args, i, stackCount)) {
                usage(out);
                return S_OK;
            }
            continue;
        }
        if (arg == "-code") {
            if (!nextLength(args, i, codeLines)) {
                usage(out);
                return S_OK;
            }
            continue;
        }
        usage(out);
        return S_OK;
    }

    out.heading("WEF Context");
    const TargetInfo target = session.targetInfo();
    out.field("Target", target.description);
    out.field("Thread", session.currentThreadText());
    out.blank();

    ULONG64 ip = 0;
    ULONG64 sp = 0;
    std::string_view spName = "rsp";
    if (!session.readRegister("rip", ip)) {
        session.readRegister("eip", ip);
    }
    if (!session.readRegister("rsp", sp)) {
        if (session.readRegister("esp", sp)) {
            spName = "esp";
        }
    }

    printRegisters(session, out);
    if (regsOnly && !full) {
        return S_OK;
    }
    out.blank();
    printCode(session, out, ip, codeLines);
    out.blank();
    printStack(session, out, spName, sp, stackCount);
    const auto watches = memoryWatches();
    for (const auto& watch : watches) {
        out.blank();
        out.heading("Memory Watch #" + std::to_string(watch.id));
        runHexdump(
            session,
            out,
            {formatAddress(watch.address), "L" + formatHex(watch.size)});
    }
    return S_OK;
}

HRESULT runRegisters(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!args.empty()) {
        registersUsage(out);
        return S_OK;
    }
    printRegisters(session, out);
    return S_OK;
}

}
