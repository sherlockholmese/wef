#include "context.hpp"

#include "config.hpp"
#include "instruction.hpp"
#include "memory.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <sstream>
#include <string>
#include <vector>

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
    out.line("usage:");
    out.line("  !wef.registers [-plain] [-reset]");
    out.line("  !wef.registers <register>              example: rax");
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

std::string dmlColor(std::string_view text, std::string_view color) {
    return "<col fg=\"" + std::string(color) + "\">" + dmlEscape(text) + "</col>";
}

std::map<ULONG, std::map<std::string, ULONG64>>& registerBaselineStore() {
    static std::map<ULONG, std::map<std::string, ULONG64>> store;
    return store;
}

ULONG currentEngineThreadId(DbgSession& session) {
    ULONG threadId = 0;
    if (FAILED(session.systemObjects()->GetCurrentThreadId(&threadId))) {
        return 0;
    }
    return threadId;
}

void threadStackLimits(DbgSession& session, ULONG64& stackBase, ULONG64& stackLimit) {
    stackBase = 0;
    stackLimit = 0;

    ULONG64 teb = 0;
    if (!session.evaluate("@$teb", teb) || teb == 0) {
        return;
    }

    const ULONG size = session.pointerSize();
    const ULONG baseOffset = size == 8 ? 0x08 : 0x04;
    const ULONG limitOffset = size == 8 ? 0x10 : 0x08;

    ULONG read = 0;
    if (FAILED(session.readVirtual(teb + baseOffset, &stackBase, sizeof(ULONG64), &read)) ||
        FAILED(session.readVirtual(teb + limitOffset, &stackLimit, sizeof(ULONG64), &read))) {
        stackBase = 0;
        stackLimit = 0;
    }
}

std::string shortRegisterAnnotation(DbgSession& session, ULONG64 value, ULONG64 stackBase, ULONG64 stackLimit) {
    if (value == 0) {
        return {};
    }

    const std::string symbol = session.resolveSymbol(value);
    if (!symbol.empty()) {
        return symbol;
    }

    if (stackLimit != 0 && stackBase > stackLimit && value >= stackLimit && value < stackBase) {
        return "(stack)";
    }
    return {};
}

struct RegisterCell {
    std::string plain;
    std::string dml;
};

RegisterCell renderRegisterCell(
    DbgSession& session,
    const RegisterValue& reg,
    bool changed,
    bool annotate,
    ULONG64 stackBase,
    ULONG64 stackLimit) {
    RegisterCell cell;
    const std::string marker = changed ? "*" : " ";
    const std::string annotation =
        annotate ? shortRegisterAnnotation(session, reg.value, stackBase, stackLimit) : std::string();
    const std::string valueText = formatAddress(reg.value);

    cell.plain =
        marker + padRight(reg.name, 4) + " " + valueText +
        (annotation.empty() ? "" : " " + annotation);

    cell.dml =
        dmlColor(marker + reg.name, changed ? "red" : "green") + " " +
        dmlCommandLink(valueText, "!wef.xinfo " + valueText) +
        (annotation.empty() ? "" : " " + dmlColor(annotation, annotation[0] == '(' ? "cyan" : "yellow"));
    return cell;
}

void printRegisters(DbgSession& session, const Output& out, bool annotate, bool showDiff) {
    out.heading("Registers");
    const auto regs = session.readCommonRegisters();
    if (regs.empty()) {
        out.line("  unavailable: register interface returned no common registers");
        return;
    }

    ULONG64 stackBase = 0;
    ULONG64 stackLimit = 0;
    if (annotate) {
        threadStackLimits(session, stackBase, stackLimit);
    }

    const auto& baseline = registerBaselineStore()[currentEngineThreadId(session)];
    std::vector<RegisterCell> cells;
    cells.reserve(regs.size());
    std::string changedNames;
    for (const auto& reg : regs) {
        bool changed = false;
        if (showDiff) {
            const auto found = baseline.find(reg.name);
            changed = found != baseline.end() && found->second != reg.value;
            if (changed) {
                if (!changedNames.empty()) {
                    changedNames += " ";
                }
                changedNames += reg.name;
            }
        }
        cells.push_back(renderRegisterCell(session, reg, changed, annotate, stackBase, stackLimit));
    }

    constexpr size_t kColumnWidth = 44;
    for (size_t i = 0; i < cells.size(); i += 2) {
        std::string plain = "  " + cells[i].plain;
        std::string dml = "  " + cells[i].dml;
        if (cells[i].plain.size() < kColumnWidth) {
            const size_t pad = kColumnWidth - cells[i].plain.size();
            plain.append(pad, ' ');
            dml.append(pad, ' ');
        } else {
            plain += ' ';
            dml += ' ';
        }
        if (i + 1 < cells.size()) {
            plain += cells[i + 1].plain;
            dml += cells[i + 1].dml;
        }
        out.dmlLine(plain, dml);
    }

    if (configGetBool("ctx.regs.show_flags", true)) {
        for (const auto& reg : regs) {
            if (reg.name == "efl" || reg.name == "rflags" || reg.name == "eflags") {
                out.field("Flags", decodeFlags(reg.value));
                break;
            }
        }
    }

    if (showDiff && !changedNames.empty()) {
        out.dmlLine(
            "  changed: " + changedNames,
            "  " + dmlColor("changed", "gray") + ": " + dmlColor(changedNames, "red"));
    }

    for (const auto& reg : regs) {
        baseline[reg.name] = reg.value;
    }
}

void printRegisterDetail(DbgSession& session, const Output& out, const std::string& requestedName) {
    std::string name = requestedName;
    if (!name.empty() && name.front() == '@') {
        name.erase(name.begin());
    }
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    ULONG64 value = 0;
    if (!session.readRegister(name, value)) {
        out.error("unknown or unavailable register: " + requestedName + "\n");
        return;
    }

    out.heading("Register " + name);
    const std::string valueText = formatAddress(value);

    ULONG64 ip = 0;
    bool isIp = session.readRegister("rip", ip);
    if (!isIp) {
        isIp = session.readRegister("eip", ip);
    }
    if (isIp && value == ip && value != 0) {
        out.dmlLine(
            "  value   " + valueText + "   (instruction pointer)",
            "  " + dmlColor("value", "gray") + "   " +
                dmlCommandLink(valueText, "!wef.xinfo " + valueText) +
                dmlColor("   (instruction pointer)", "green"));
    } else {
        out.dmlLine(
            "  value   " + valueText,
            "  " + dmlColor("value", "gray") + "   " +
                dmlCommandLink(valueText, "!wef.xinfo " + valueText));
    }

    if (value == 0) {
        out.field("Note", "null");
        return;
    }

    const std::string symbol = session.resolveSymbol(value);
    if (!symbol.empty()) {
        out.field("Symbol", symbol);
    }

    MEMORY_BASIC_INFORMATION64 region = {};
    if (session.queryVirtual(value, region)) {
        std::string text = stateToString(region.State);
        const std::string protection = protectionToString(region.Protect);
        if (!protection.empty()) {
            text += " " + protection;
        }
        const std::string type = typeToString(region.Type);
        if (!type.empty()) {
            text += " " + type;
        }
        const std::string module = session.moduleNameForOffset(value);
        if (!module.empty()) {
            text += " (" + module + ")";
        }
        out.field("Region", text);
    }

    const std::string preview = previewString(session, value);
    if (!preview.empty()) {
        out.field("String", preview);
    }

    out.field(
        "Chain",
        describePointerChain(session, value, configGetNumber("dereference.depth", 3)));

    std::string actions =
        dmlCommandLink("[telescope]", "!wef.telescope " + valueText + " L8") + " " +
        dmlCommandLink("[hexdump]", "!wef.hexdump " + valueText + " L64") + " " +
        dmlCommandLink("[xinfo]", "!wef.xinfo " + valueText);
    std::string plainActions = "  [telescope] [hexdump] [xinfo]";
    if (name == "rsp" || name == "esp") {
        actions += " " + dmlCommandLink("[stack]", "!wef.stack L20");
        plainActions += " [stack]";
    }
    out.dmlLine(plainActions, "  " + actions);
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

    printRegisters(
        session,
        out,
        configGetBool("regs.annotate", true),
        configGetBool("regs.show_diff", true));
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
    bool plain = false;
    bool reset = false;
    std::string single;

    for (const auto& arg : args) {
        if (arg == "-plain" || arg == "-raw") {
            plain = true;
            continue;
        }
        if (arg == "-reset") {
            reset = true;
            continue;
        }
        if (arg == "help" || arg == "-h" || arg == "/?") {
            registersUsage(out);
            out.line("       !wef.registers <register>      example: rax");
            return S_OK;
        }
        if (!single.empty()) {
            registersUsage(out);
            return S_OK;
        }
        single = arg;
    }

    if (reset) {
        registerBaselineStore().erase(currentEngineThreadId(session));
    }

    if (!single.empty()) {
        printRegisterDetail(session, out, single);
        return S_OK;
    }

    const bool annotate = !plain && configGetBool("regs.annotate", true);
    const bool showDiff = !plain && configGetBool("regs.show_diff", true);
    printRegisters(session, out, annotate, showDiff);
    return S_OK;
}

}
