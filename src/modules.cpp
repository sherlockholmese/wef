#include "modules.hpp"

#include "breakpoints.hpp"
#include "memory.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <string>

namespace wef {

namespace {

std::string padRight(std::string text, size_t width) {
    if (text.size() >= width) {
        return text;
    }
    text.append(width - text.size(), ' ');
    return text;
}

std::string padLeft(std::string text, size_t width) {
    if (text.size() >= width) {
        return text;
    }
    return std::string(width - text.size(), ' ') + text;
}

std::string sizeText(ULONG64 size) {
    return "0x" + formatHex(size, 8);
}

bool hasWriteProtect(ULONG protect) {
    const ULONG base = protect & 0xff;
    return base == PAGE_READWRITE || base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool hasExecuteProtect(ULONG protect) {
    const ULONG base = protect & 0xff;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool containsAddress(const MEMORY_BASIC_INFORMATION64& info, ULONG64 address) {
    return address >= info.BaseAddress && address - info.BaseAddress < info.RegionSize;
}

bool containsInsensitive(std::string text, std::string needle) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return text.find(needle) != std::string::npos;
}

struct VmmapFilter {
    bool includeFree = false;
    bool onlyCommit = false;
    bool onlyReserve = false;
    bool onlyWrite = false;
    bool onlyExecute = false;
    bool onlyImage = false;
    bool onlyMapped = false;
    bool onlyPrivate = false;
    bool hasContains = false;
    ULONG64 contains = 0;
    ULONG64 limit = 0;
    std::string module;
};

void vmmapUsage(const Output& out) {
    out.line("usage: !wef.vmmap [-all|-free] [-commit|-reserve] [-x|-w|-rwx] [-image|-mapped|-private] [-module <name>] [-contains <addr>] [L<count>]");
}

bool evalAddress(DbgSession& session, std::string_view text, ULONG64& value) {
    return session.evaluate(text, value) || parseNumber(text, value);
}

std::string processorName(ULONG machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
        return "x86";
    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";
    case IMAGE_FILE_MACHINE_ARM64:
        return "arm64";
    default:
        return "0x" + formatHex(machine);
    }
}

std::string moduleNameByIndex(DbgSession& session, ULONG index, ULONG64 base) {
    char image[1024] = {};
    char module[512] = {};
    if (FAILED(session.symbols()->GetModuleNames(
            index,
            base,
            image,
            sizeof(image),
            nullptr,
            module,
            sizeof(module),
            nullptr,
            nullptr,
            0,
            nullptr))) {
        return "<unknown>";
    }
    return module[0] != '\0' ? module : image;
}

template <typename T>
bool readStruct(DbgSession& session, ULONG64 address, T& value) {
    ULONG read = 0;
    return SUCCEEDED(session.readVirtual(address, &value, sizeof(T), &read)) && read == sizeof(T);
}

std::string sectionProtection(ULONG characteristics) {
    std::string result;
    if ((characteristics & IMAGE_SCN_MEM_READ) != 0) {
        result += 'R';
    }
    if ((characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
        result += 'W';
    }
    if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
        result += 'X';
    }
    return result.empty() ? "-" : result;
}

bool findModule(DbgSession& session, std::string_view name, ULONG& index, ULONG64& base) {
    const std::string copy(name);
    return SUCCEEDED(session.symbols()->GetModuleByModuleName(copy.c_str(), 0, &index, &base));
}

}

HRESULT runVmmap(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    VmmapFilter filter;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "-all" || args[i] == "-free") {
            filter.includeFree = true;
        } else if (args[i] == "-commit") {
            filter.onlyCommit = true;
        } else if (args[i] == "-reserve") {
            filter.onlyReserve = true;
        } else if (args[i] == "-x") {
            filter.onlyExecute = true;
        } else if (args[i] == "-w") {
            filter.onlyWrite = true;
        } else if (args[i] == "-rwx") {
            filter.onlyExecute = true;
            filter.onlyWrite = true;
        } else if (args[i] == "-image") {
            filter.onlyImage = true;
        } else if (args[i] == "-mapped") {
            filter.onlyMapped = true;
        } else if (args[i] == "-private") {
            filter.onlyPrivate = true;
        } else if (args[i] == "-module" && i + 1 < args.size()) {
            filter.module = args[++i];
        } else if (args[i] == "-contains" && i + 1 < args.size()) {
            if (!session.evaluate(args[i + 1], filter.contains) && !parseNumber(args[i + 1], filter.contains)) {
                vmmapUsage(out);
                return S_OK;
            }
            filter.hasContains = true;
            ++i;
        } else {
            ULONG64 parsed = 0;
            if (parseLengthToken(args[i], parsed)) {
                filter.limit = parsed;
            } else {
                vmmapUsage(out);
                return S_OK;
            }
        }
    }

    const TargetInfo target = session.targetInfo();
    if (target.kernelMode) {
        out.error("vmmap is unsupported for kernel targets in this milestone\n");
        return S_OK;
    }
    if (!target.userMode) {
        out.error("vmmap requires a user-mode target in this milestone\n");
        return S_OK;
    }
    if (target.dump) {
        out.warning("dump target detected; memory region information may be partial\n");
    }

    out.heading("VM Map");
    out.line("  base               end                size        state     protect      type      module            actions");
    out.line("  -----------------  -----------------  ----------  --------  -----------  --------  ----------------  ------------------------------");

    const ULONG64 maxAddress = session.pointerSize() == 8 ? 0x0000800000000000ULL : 0xffffffffULL;
    ULONG64 address = 0;
    ULONG64 regions = 0;
    ULONG64 printedCount = 0;
    bool printed = false;

    while (address < maxAddress && regions < 200000) {
        MEMORY_BASIC_INFORMATION64 info = {};
        if (!session.queryVirtual(address, info)) {
            if (address == 0) {
                out.error("QueryVirtual failed at " + formatAddress(address) + "\n");
                return S_OK;
            }
            out.warning("QueryVirtual stopped at " + formatAddress(address) + "\n");
            break;
        }

        const ULONG64 base = info.BaseAddress;
        const ULONG64 size = info.RegionSize;
        const ULONG64 end = size == 0 ? base : base + size;
        const std::string moduleName = session.moduleNameForOffset(base);
        const bool matches =
            (filter.includeFree || info.State != MEM_FREE) &&
            (!filter.onlyCommit || info.State == MEM_COMMIT) &&
            (!filter.onlyReserve || info.State == MEM_RESERVE) &&
            (!filter.onlyWrite || hasWriteProtect(info.Protect)) &&
            (!filter.onlyExecute || hasExecuteProtect(info.Protect)) &&
            (!filter.onlyImage || info.Type == MEM_IMAGE) &&
            (!filter.onlyMapped || info.Type == MEM_MAPPED) &&
            (!filter.onlyPrivate || info.Type == MEM_PRIVATE) &&
            (!filter.hasContains || containsAddress(info, filter.contains)) &&
            (filter.module.empty() || containsInsensitive(moduleName, filter.module));
        if (matches) {
            const std::string baseText = formatAddress(base);
            const std::string endText = formatAddress(end);
            const std::string regionSize = sizeText(size);
            const std::string state = stateToString(info.State);
            const std::string protection = protectionToString(info.Protect);
            const std::string type = typeToString(info.Type);
            const std::string line =
                "  " +
                padRight(baseText, 17) + "  " +
                padRight(endText, 17) + "  " +
                padLeft(regionSize, 10) + "  " +
                padRight(state, 8) + "  " +
                padRight(protection, 11) + "  " +
                padRight(type, 8) + "  " +
                padRight(moduleName, 16) + "  " +
                "[dump] [search] [contains]";
            const std::string dml =
                std::string("  <col fg=\"yellow\">") + dmlEscape(padRight(baseText, 17)) + "</col>  " +
                "<col fg=\"yellow\">" + dmlEscape(padRight(endText, 17)) + "</col>  " +
                "<col fg=\"white\">" + dmlEscape(padLeft(regionSize, 10)) + "</col>  " +
                "<col fg=\"green\">" + dmlEscape(padRight(state, 8)) + "</col>  " +
                "<col fg=\"cyan\">" + dmlEscape(padRight(protection, 11)) + "</col>  " +
                "<col fg=\"magenta\">" + dmlEscape(padRight(type, 8)) + "</col>  " +
                "<col fg=\"white\">" + dmlEscape(padRight(moduleName, 16)) + "</col>  " +
                dmlCommandLink("dump", "!wef.hexdump " + baseText + " L80") + " " +
                dmlCommandLink("search", "!wef.search_pattern hex:4141 " + baseText + " L" + formatHex(size)) + " " +
                dmlCommandLink("contains", "!wef.vmmap -contains " + baseText);
            out.dmlLine(
                line,
                dml);
            printed = true;
            ++printedCount;
            if (filter.limit != 0 && printedCount >= filter.limit) {
                break;
            }
        }

        if (size == 0 || end <= address) {
            address += 0x1000;
        } else {
            address = end;
        }
        ++regions;
    }

    if (!printed) {
        out.warning("no committed or reserved regions were reported\n");
    }
    return S_OK;
}

HRESULT runXinfo(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        out.line("usage: !wef.xinfo <address> [address ...]");
        return S_OK;
    }

    for (const auto& arg : args) {
        ULONG64 address = 0;
        if (!evalAddress(session, arg, address)) {
            out.error("could not evaluate address: " + arg + "\n");
            continue;
        }

        out.heading("Address Information");
        out.field("Expression", arg);
        out.field("Address", formatAddress(address));

        MEMORY_BASIC_INFORMATION64 info = {};
        if (!session.queryVirtual(address, info)) {
            out.field("Mapping", "unavailable");
            continue;
        }

        const ULONG64 end = info.RegionSize > std::numeric_limits<ULONG64>::max() - info.BaseAddress
            ? std::numeric_limits<ULONG64>::max()
            : info.BaseAddress + info.RegionSize;
        out.field("Region", formatAddress(info.BaseAddress) + "-" + formatAddress(end));
        out.field("Size", "0x" + formatHex(info.RegionSize));
        out.field("State", stateToString(info.State));
        out.field("Protection", protectionToString(info.Protect));
        out.field("Type", typeToString(info.Type));

        const std::string module = session.moduleNameForOffset(address);
        const std::string symbol = session.resolveSymbol(address);
        const std::string preview = previewString(session, address);
        out.field("Module", module.empty() ? "<none>" : module);
        out.field("Symbol", symbol.empty() ? "<none>" : symbol);
        if (!preview.empty()) {
            out.field("Preview", preview);
        }
        out.dmlLine(
            "  [hexdump] [telescope] [vmmap]",
            "  " +
                dmlCommandLink("hexdump", "!wef.hexdump " + formatAddress(address) + " L80") + " " +
                dmlCommandLink("telescope", "!wef.telescope " + formatAddress(address) + " L8") + " " +
                dmlCommandLink("vmmap", "!wef.vmmap -contains " + formatAddress(address)));
    }
    return S_OK;
}

HRESULT runXfiles(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() > 2) {
        out.line("usage: !wef.xfiles [module [section]]");
        return S_OK;
    }

    if (args.empty()) {
        ULONG loaded = 0;
        ULONG unloaded = 0;
        if (FAILED(session.symbols()->GetNumberModules(&loaded, &unloaded))) {
            out.error("could not enumerate modules\n");
            return S_OK;
        }

        out.heading("Loaded Modules");
        out.line("  base               end                size        module");
        out.line("  -----------------  -----------------  ----------  ------------------------------");
        for (ULONG index = 0; index < loaded; ++index) {
            ULONG64 base = 0;
            if (FAILED(session.symbols()->GetModuleByIndex(index, &base))) {
                continue;
            }
            DEBUG_MODULE_PARAMETERS params = {};
            if (FAILED(session.symbols()->GetModuleParameters(1, &base, 0, &params))) {
                continue;
            }
            out.line(
                "  " + formatAddress(base) + "  " +
                formatAddress(base + params.Size) + "  " +
                padLeft("0x" + formatHex(params.Size), 10) + "  " +
                moduleNameByIndex(session, index, base));
        }
        if (unloaded != 0) {
            out.field("Unloaded modules", std::to_string(unloaded));
        }
        return S_OK;
    }

    ULONG index = 0;
    ULONG64 base = 0;
    if (!findModule(session, args[0], index, base)) {
        out.error("could not locate module: " + args[0] + "\n");
        return S_OK;
    }

    IMAGE_DOS_HEADER dos = {};
    if (!readStruct(session, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        out.error("could not read valid DOS header\n");
        return S_OK;
    }
    const ULONG64 ntAddress = base + static_cast<ULONG>(dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader = {};
    if (!readStruct(session, ntAddress, signature) ||
        signature != IMAGE_NT_SIGNATURE ||
        !readStruct(session, ntAddress + sizeof(DWORD), fileHeader)) {
        out.error("could not read valid PE headers\n");
        return S_OK;
    }

    const ULONG64 sectionAddress =
        ntAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
    const ULONG sectionCount = std::min<ULONG>(fileHeader.NumberOfSections, 96);
    out.heading("PE Sections");
    out.field("Module", moduleNameByIndex(session, index, base));
    out.field("Base", formatAddress(base));
    out.line("  name      start               end                 size        perms");
    out.line("  --------  -----------------   -----------------   ----------  -----");

    bool printed = false;
    for (ULONG i = 0; i < sectionCount; ++i) {
        IMAGE_SECTION_HEADER section = {};
        if (!readStruct(session, sectionAddress + (i * sizeof(section)), section)) {
            break;
        }
        char nameBuffer[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
        std::memcpy(nameBuffer, section.Name, IMAGE_SIZEOF_SHORT_NAME);
        const std::string name(nameBuffer);
        if (args.size() == 2 && !containsInsensitive(name, args[1])) {
            continue;
        }

        const ULONG64 start = base + section.VirtualAddress;
        const ULONG64 size = std::max<ULONG>(section.Misc.VirtualSize, section.SizeOfRawData);
        const ULONG64 end = start + size;
        out.line(
            "  " + padRight(name, 8) + "  " +
            formatAddress(start) + "  " +
            formatAddress(end) + "  " +
            padLeft("0x" + formatHex(size), 10) + "  " +
            sectionProtection(section.Characteristics));
        printed = true;
    }
    if (!printed) {
        out.warning("no matching PE sections found\n");
    }
    return S_OK;
}

HRESULT runArch(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty() || args[0] == "get") {
        if (args.size() > 1) {
            out.line("usage: !wef.arch get|list|set <x86|x64|arm64>");
            return S_OK;
        }
        ULONG actual = 0;
        session.control()->GetActualProcessorType(&actual);
        out.heading("Architecture");
        out.field("Actual", processorName(actual));
        out.field("Effective", processorName(session.effectiveProcessor()));
        out.field("Pointer size", std::to_string(session.pointerSize() * 8) + "-bit");
        return S_OK;
    }

    if (args[0] == "list" && args.size() == 1) {
        out.heading("Supported Architectures");
        out.line("  x86");
        out.line("  x64");
        out.line("  arm64");
        return S_OK;
    }

    if (args[0] == "set" && args.size() == 2) {
        std::string machine;
        if (args[1] == "x86" || args[1] == "i386") {
            machine = "x86";
        } else if (args[1] == "x64" || args[1] == "amd64") {
            machine = "amd64";
        } else if (args[1] == "arm64") {
            machine = "arm64";
        } else {
            out.error("unsupported architecture: " + args[1] + "\n");
            return S_OK;
        }
        const HRESULT hr = session.control()->Execute(
            DEBUG_OUTCTL_ALL_CLIENTS,
            (".effmach " + machine).c_str(),
            DEBUG_EXECUTE_DEFAULT);
        if (FAILED(hr)) {
            out.error("failed to set effective architecture: " + formatHResult(hr) + "\n");
        }
        return S_OK;
    }

    out.line("usage: !wef.arch get|list|set <x86|x64|arm64>");
    return S_OK;
}

HRESULT runEval(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty() || args.size() > 2) {
        out.line("usage: !wef.eval <expression> [expression]");
        return S_OK;
    }

    std::vector<ULONG64> values;
    values.reserve(args.size());
    out.heading("Evaluate");
    for (const auto& arg : args) {
        ULONG64 value = 0;
        if (!evalAddress(session, arg, value)) {
            out.error("could not evaluate expression: " + arg + "\n");
            return S_OK;
        }
        values.push_back(value);
        out.field(arg, formatAddress(value) + "  unsigned=" + std::to_string(value));
    }

    if (values.size() == 2) {
        const bool negative = values[1] < values[0];
        const ULONG64 magnitude = negative ? values[0] - values[1] : values[1] - values[0];
        out.field("Distance", std::string(negative ? "-" : "+") + "0x" + formatHex(magnitude) + " (" + std::to_string(magnitude) + ")");
    }
    return S_OK;
}

HRESULT runProcessStatus(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!args.empty()) {
        out.line("usage: !wef.process_status");
        return S_OK;
    }

    ULONG processEngineId = 0;
    ULONG processSystemId = 0;
    ULONG threadEngineId = 0;
    ULONG threadSystemId = 0;
    ULONG processCount = 0;
    ULONG64 peb = 0;
    ULONG64 teb = 0;
    session.systemObjects()->GetCurrentProcessId(&processEngineId);
    session.systemObjects()->GetCurrentProcessSystemId(&processSystemId);
    session.systemObjects()->GetCurrentThreadId(&threadEngineId);
    session.systemObjects()->GetCurrentThreadSystemId(&threadSystemId);
    session.systemObjects()->GetNumberProcesses(&processCount);
    session.systemObjects()->GetCurrentProcessPeb(&peb);
    session.systemObjects()->GetCurrentThreadTeb(&teb);

    ULONG64 imageBase = 0;
    std::string image = "<unknown>";
    if (SUCCEEDED(session.symbols()->GetModuleByIndex(0, &imageBase))) {
        image = moduleNameByIndex(session, 0, imageBase);
    }

    const TargetInfo target = session.targetInfo();
    out.heading("Process Status");
    out.field("Target", target.description);
    out.field("Image", image);
    out.field("Engine process", std::to_string(processEngineId));
    out.field("System PID", std::to_string(processSystemId));
    out.field("Engine thread", std::to_string(threadEngineId));
    out.field("System TID", std::to_string(threadSystemId));
    out.field("Process count", std::to_string(processCount));
    out.field("PEB", formatAddress(peb));
    out.field("TEB", formatAddress(teb));
    return S_OK;
}

HRESULT runPie(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        out.line("usage: !wef.pie info [module]|breakpoint <offset> [module] [name]|list|delete <name|id>");
        return S_OK;
    }
    if (args[0] == "list") {
        return runNameBreak(session, out, {"list"});
    }
    if (args[0] == "delete") {
        if (args.size() != 2) {
            out.line("usage: !wef.pie delete <name|id>");
            return S_OK;
        }
        return runNameBreak(session, out, {"delete", args[1]});
    }

    const bool info = args[0] == "info";
    const bool breakpoint = args[0] == "breakpoint" || args[0] == "break";
    if ((!info && !breakpoint) ||
        (info && args.size() > 2) ||
        (breakpoint && (args.size() < 2 || args.size() > 4))) {
        out.line("usage: !wef.pie info [module]|breakpoint <offset> [module] [name]|list|delete <name|id>");
        return S_OK;
    }

    ULONG index = 0;
    ULONG64 base = 0;
    const std::string moduleArgument =
        info ? (args.size() == 2 ? args[1] : std::string()) :
        (args.size() >= 3 ? args[2] : std::string());
    if (moduleArgument.empty()) {
        if (FAILED(session.symbols()->GetModuleByIndex(0, &base))) {
            out.error("could not resolve the main module\n");
            return S_OK;
        }
    } else if (!findModule(session, moduleArgument, index, base)) {
        out.error("could not resolve module: " + moduleArgument + "\n");
        return S_OK;
    }
    const std::string module = moduleNameByIndex(session, index, base);

    if (info) {
        out.heading("PIE");
        out.field("Module", module);
        out.field("Base", formatAddress(base));
        out.field("Rebase expression", module + "+<offset>");
        return S_OK;
    }

    ULONG64 offset = 0;
    if (!parseNumber(args[1], offset)) {
        out.error("invalid module-relative offset: " + args[1] + "\n");
        return S_OK;
    }
    if (offset > std::numeric_limits<ULONG64>::max() - base) {
        out.error("module-relative address overflows\n");
        return S_OK;
    }
    const ULONG64 address = base + offset;
    const std::string name =
        args.size() == 4 ? args[3] :
        "pie_" + module + "_" + formatHex(offset);
    out.heading("PIE Breakpoint");
    out.field("Module", module);
    out.field("Base", formatAddress(base));
    out.field("Offset", "0x" + formatHex(offset));
    return addNamedBreakpoint(session, out, name, address);
}

}
