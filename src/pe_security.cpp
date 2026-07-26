#include "pe_security.hpp"

#include "config.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <sstream>
#include <type_traits>

namespace wef {

namespace {

template <typename T>
bool readStruct(DbgSession& session, ULONG64 address, T& value) {
    ULONG bytesRead = 0;
    const HRESULT hr = session.readVirtual(address, &value, sizeof(T), &bytesRead);
    return SUCCEEDED(hr) && bytesRead == sizeof(T);
}

std::string machineName(USHORT machine) {
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

std::string subsystemName(USHORT subsystem) {
    switch (subsystem) {
    case IMAGE_SUBSYSTEM_NATIVE:
        return "native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        return "windows-gui";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        return "windows-cui";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        return "efi-application";
    default:
        return "0x" + formatHex(subsystem);
    }
}

std::string yesNo(bool value) {
    return value ? "yes" : "no";
}

bool containsInsensitive(std::string text, std::string needle) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return text.find(needle) != std::string::npos;
}

std::string readAscii(DbgSession& session, ULONG64 address, size_t maxLength = 512) {
    std::string result;
    result.reserve(std::min<size_t>(maxLength, 64));
    for (size_t i = 0; i < maxLength; ++i) {
        char ch = '\0';
        ULONG read = 0;
        if (FAILED(session.readVirtual(address + i, &ch, 1, &read)) || read != 1 || ch == '\0') {
            break;
        }
        if (static_cast<unsigned char>(ch) < 0x20 || static_cast<unsigned char>(ch) > 0x7e) {
            break;
        }
        result.push_back(ch);
    }
    return result;
}

bool moduleBase(DbgSession& session, const std::vector<std::string>& args, ULONG& index, ULONG64& base) {
    if (args.empty()) {
        return SUCCEEDED(session.symbols()->GetModuleByIndex(0, &base));
    }
    return SUCCEEDED(session.symbols()->GetModuleByModuleName(args[0].c_str(), 0, &index, &base));
}

std::string moduleName(DbgSession& session, ULONG index, ULONG64 base) {
    char module[512] = {};
    if (SUCCEEDED(session.symbols()->GetModuleNames(index, base, nullptr, 0, nullptr, module, sizeof(module), nullptr, nullptr, 0, nullptr))) {
        return module;
    }
    return "<unknown>";
}

bool imageHeaders(
    DbgSession& session,
    std::string_view requestedModule,
    ULONG& index,
    ULONG64& base,
    IMAGE_FILE_HEADER& fileHeader,
    ULONG64& optionalAddress,
    USHORT& magic) {
    if (requestedModule.empty()) {
        if (FAILED(session.symbols()->GetModuleByIndex(0, &base))) {
            return false;
        }
    } else {
        const std::string copy(requestedModule);
        if (FAILED(session.symbols()->GetModuleByModuleName(copy.c_str(), 0, &index, &base))) {
            return false;
        }
    }

    IMAGE_DOS_HEADER dos = {};
    if (!readStruct(session, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        return false;
    }
    const ULONG64 ntAddress = base + static_cast<ULONG>(dos.e_lfanew);
    DWORD signature = 0;
    if (!readStruct(session, ntAddress, signature) ||
        signature != IMAGE_NT_SIGNATURE ||
        !readStruct(session, ntAddress + sizeof(DWORD), fileHeader)) {
        return false;
    }
    optionalAddress = ntAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    return readStruct(session, optionalAddress, magic);
}

template <typename OptionalHeader, typename LoadConfig>
HRESULT reportImage(DbgSession& session, const Output& out, ULONG index, ULONG64 base, const IMAGE_FILE_HEADER& fileHeader, const OptionalHeader& optional) {
    const USHORT dll = optional.DllCharacteristics;
    const bool dynamicBase = (dll & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    const bool nxCompat = (dll & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    const bool guardCf = (dll & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    const bool highEntropy = (dll & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;

    out.heading("WEF Checksec");
    out.field("Module", moduleName(session, index, base));
    out.field("ImageBase", formatAddress(base));
    out.field("PreferredImageBase", formatAddress(optional.ImageBase));
    out.field("Machine", machineName(fileHeader.Machine));
    out.field("Subsystem", subsystemName(optional.Subsystem));
    out.field("Timestamp", "0x" + formatHex(fileHeader.TimeDateStamp));
    out.field("DYNAMICBASE / ASLR", yesNo(dynamicBase));
    out.field("NX compatible", yesNo(nxCompat));
    out.field("High entropy VA", yesNo(highEntropy));

    const auto& loadConfigDir = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    LoadConfig loadConfig = {};
    bool loadConfigRead = false;
    if (loadConfigDir.VirtualAddress != 0 && loadConfigDir.Size >= sizeof(ULONG)) {
        loadConfigRead = readStruct(session, base + loadConfigDir.VirtualAddress, loadConfig);
    }

    if (guardCf) {
        if (loadConfigRead) {
            out.field("Control Flow Guard", "yes (GuardFlags=0x" + formatHex(loadConfig.GuardFlags) + ")");
        } else {
            out.field("Control Flow Guard", "yes (metadata unreadable)");
        }
    } else {
        out.field("Control Flow Guard", "no");
    }

    if constexpr (std::is_same_v<LoadConfig, IMAGE_LOAD_CONFIG_DIRECTORY32>) {
        if ((dll & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0) {
            out.field("SafeSEH", "not applicable (/NOSEH)");
        } else if (loadConfigRead && loadConfig.SEHandlerCount != 0) {
            out.field("SafeSEH", "yes");
        } else {
            out.field("SafeSEH", "no or unavailable");
        }
    } else {
        out.field("SafeSEH", "not applicable");
    }

    return S_OK;
}

template <typename OptionalHeader>
HRESULT reportPeInfo(
    DbgSession& session,
    const Output& out,
    ULONG index,
    ULONG64 base,
    const IMAGE_FILE_HEADER& fileHeader,
    const OptionalHeader& optional) {
    out.heading("PE Information");
    out.field("Module", moduleName(session, index, base));
    out.field("Loaded base", formatAddress(base));
    out.field("Preferred base", formatAddress(optional.ImageBase));
    out.field(
        "Entry point",
        optional.AddressOfEntryPoint == 0 ? "none" : formatAddress(base + optional.AddressOfEntryPoint));
    out.field("Machine", machineName(fileHeader.Machine));
    out.field("Subsystem", subsystemName(optional.Subsystem));
    out.field("Image size", "0x" + formatHex(optional.SizeOfImage));
    out.field("Headers size", "0x" + formatHex(optional.SizeOfHeaders));
    out.field("Section alignment", "0x" + formatHex(optional.SectionAlignment));
    out.field("File alignment", "0x" + formatHex(optional.FileAlignment));
    out.field("Sections", std::to_string(fileHeader.NumberOfSections));
    out.field("Characteristics", "0x" + formatHex(fileHeader.Characteristics));
    out.field("DLL characteristics", "0x" + formatHex(optional.DllCharacteristics));

    const auto& imports = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    const auto& relocations = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    const auto& loadConfig = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    out.field("Imports", imports.VirtualAddress == 0 ? "none" : "RVA 0x" + formatHex(imports.VirtualAddress));
    out.field("Relocations", relocations.VirtualAddress == 0 ? "none" : "RVA 0x" + formatHex(relocations.VirtualAddress));
    out.field("Load config", loadConfig.VirtualAddress == 0 ? "none" : "RVA 0x" + formatHex(loadConfig.VirtualAddress));
    return S_OK;
}

template <typename OptionalHeader, typename Thunk>
HRESULT reportIat(
    DbgSession& session,
    const Output& out,
    ULONG index,
    ULONG64 base,
    const OptionalHeader& optional,
    std::string_view filter) {
    const auto& importDir = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) {
        out.warning("module has no import directory\n");
        return S_OK;
    }

    out.heading("Import Address Table");
    out.field("Module", moduleName(session, index, base));
    out.line("  slot                target              import");
    out.line("  -----------------   -----------------   ----------------------------------------");

    const ULONG64 maxEntries = configGetNumber("iat.max_entries", 4096);
    ULONG64 entries = 0;
    for (ULONG descriptorIndex = 0; descriptorIndex < 256 && entries < maxEntries; ++descriptorIndex) {
        IMAGE_IMPORT_DESCRIPTOR descriptor = {};
        if (!readStruct(
                session,
                base + importDir.VirtualAddress + (descriptorIndex * sizeof(descriptor)),
                descriptor)) {
            break;
        }
        if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 && descriptor.Name == 0) {
            break;
        }

        const std::string dllName = readAscii(session, base + descriptor.Name);
        const bool hasLookupMetadata = descriptor.OriginalFirstThunk != 0;
        const ULONG64 lookupBase = base + descriptor.OriginalFirstThunk;
        const ULONG64 iatBase = base + descriptor.FirstThunk;
        for (ULONG64 thunkIndex = 0; thunkIndex < 65536 && entries < maxEntries; ++thunkIndex) {
            Thunk lookup = {};
            Thunk slot = {};
            const ULONG64 offset = thunkIndex * sizeof(Thunk);
            if (!readStruct(session, iatBase + offset, slot) || slot.u1.Function == 0) {
                break;
            }
            if (hasLookupMetadata && !readStruct(session, lookupBase + offset, lookup)) {
                break;
            }

            std::string importName = "<name unavailable>";
            if (hasLookupMetadata) {
                if (lookup.u1.AddressOfData == 0) {
                    break;
                }
                const ULONG64 ordinalFlag = sizeof(Thunk) == sizeof(IMAGE_THUNK_DATA64)
                    ? IMAGE_ORDINAL_FLAG64
                    : IMAGE_ORDINAL_FLAG32;
                if ((lookup.u1.Ordinal & ordinalFlag) != 0) {
                    importName = "#" + std::to_string(static_cast<USHORT>(lookup.u1.Ordinal & 0xffff));
                } else {
                    importName = readAscii(session, base + lookup.u1.AddressOfData + sizeof(USHORT));
                }
            }

            const ULONG64 slotAddress = iatBase + offset;
            const ULONG64 target = slot.u1.Function;
            const std::string symbol = session.resolveSymbol(target);
            const std::string qualified = dllName + "!" + importName;
            if (!filter.empty() &&
                !containsInsensitive(qualified, std::string(filter)) &&
                !containsInsensitive(symbol, std::string(filter))) {
                continue;
            }
            out.line(
                "  " + formatAddress(slotAddress) + "   " +
                formatAddress(target) + "   " +
                qualified + (symbol.empty() ? "" : " -> " + symbol));
            ++entries;
        }
    }
    if (entries == 0) {
        out.warning("no matching imports found\n");
    } else if (entries >= maxEntries) {
        out.warning("IAT output truncated; increase iat.max_entries\n");
    }
    return S_OK;
}

template <typename OptionalHeader, typename LoadConfig>
HRESULT reportCanary(
    DbgSession& session,
    const Output& out,
    ULONG index,
    ULONG64 base,
    const OptionalHeader& optional) {
    const auto& directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (directory.VirtualAddress == 0) {
        out.warning("module has no load-config directory\n");
        return S_OK;
    }

    LoadConfig loadConfig = {};
    constexpr size_t requiredSize =
        offsetof(LoadConfig, SecurityCookie) + sizeof(loadConfig.SecurityCookie);
    if (static_cast<size_t>(directory.Size) < requiredSize) {
        out.warning("load-config directory predates the security-cookie field\n");
        return S_OK;
    }
    const ULONG readLength = std::min<ULONG>(directory.Size, static_cast<ULONG>(sizeof(loadConfig)));
    ULONG bytesRead = 0;
    if (FAILED(session.readVirtual(
            base + directory.VirtualAddress,
            &loadConfig,
            readLength,
            &bytesRead)) ||
        static_cast<size_t>(bytesRead) < requiredSize ||
        static_cast<size_t>(loadConfig.Size) < requiredSize ||
        loadConfig.SecurityCookie == 0) {
        out.warning("module does not expose a /GS security cookie\n");
        return S_OK;
    }

    const ULONG64 cookieAddress = loadConfig.SecurityCookie;
    ULONG64 cookieValue = 0;
    bool read = false;
    if constexpr (std::is_same_v<LoadConfig, IMAGE_LOAD_CONFIG_DIRECTORY64>) {
        read = readStruct(session, cookieAddress, cookieValue);
    } else {
        ULONG value32 = 0;
        read = readStruct(session, cookieAddress, value32);
        cookieValue = value32;
    }

    out.heading("Security Cookie");
    out.field("Module", moduleName(session, index, base));
    out.field("Address", formatAddress(cookieAddress));
    out.field("Value", read ? formatAddress(cookieValue) : "<unreadable>");
    return S_OK;
}

}

HRESULT runChecksec(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() > 1) {
        out.line("usage: !wef.checksec [module]");
        return S_OK;
    }

    ULONG index = 0;
    ULONG64 base = 0;
    if (!moduleBase(session, args, index, base)) {
        out.error("could not locate module\n");
        return S_OK;
    }

    IMAGE_DOS_HEADER dos = {};
    if (!readStruct(session, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        out.error("could not read valid DOS header at " + formatAddress(base) + "\n");
        return S_OK;
    }

    const ULONG64 ntAddress = base + static_cast<ULONG>(dos.e_lfanew);
    DWORD signature = 0;
    if (!readStruct(session, ntAddress, signature) || signature != IMAGE_NT_SIGNATURE) {
        out.error("could not read valid NT headers at " + formatAddress(ntAddress) + "\n");
        return S_OK;
    }

    IMAGE_FILE_HEADER fileHeader = {};
    if (!readStruct(session, ntAddress + sizeof(DWORD), fileHeader)) {
        out.error("could not read PE file header\n");
        return S_OK;
    }

    USHORT magic = 0;
    const ULONG64 optionalAddress = ntAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!readStruct(session, optionalAddress, magic)) {
        out.error("could not read PE optional header magic\n");
        return S_OK;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32+ optional header\n");
            return S_OK;
        }
        return reportImage<IMAGE_OPTIONAL_HEADER64, IMAGE_LOAD_CONFIG_DIRECTORY64>(session, out, index, base, fileHeader, optional);
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32 optional header\n");
            return S_OK;
        }
        return reportImage<IMAGE_OPTIONAL_HEADER32, IMAGE_LOAD_CONFIG_DIRECTORY32>(session, out, index, base, fileHeader, optional);
    }

    out.error("unsupported PE optional header magic: 0x" + formatHex(magic) + "\n");
    return S_OK;
}

HRESULT runPeInfo(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() > 1) {
        out.line("usage: !wef.pe_info [module]");
        return S_OK;
    }

    ULONG index = 0;
    ULONG64 base = 0;
    IMAGE_FILE_HEADER fileHeader = {};
    ULONG64 optionalAddress = 0;
    USHORT magic = 0;
    if (!imageHeaders(
            session,
            args.empty() ? std::string_view() : std::string_view(args[0]),
            index,
            base,
            fileHeader,
            optionalAddress,
            magic)) {
        out.error("could not read PE headers\n");
        return S_OK;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32+ optional header\n");
            return S_OK;
        }
        return reportPeInfo(session, out, index, base, fileHeader, optional);
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32 optional header\n");
            return S_OK;
        }
        return reportPeInfo(session, out, index, base, fileHeader, optional);
    }
    out.error("unsupported PE optional header magic\n");
    return S_OK;
}

HRESULT runIat(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() > 2) {
        out.line("usage: !wef.iat [module] [filter]");
        return S_OK;
    }

    ULONG index = 0;
    ULONG64 base = 0;
    IMAGE_FILE_HEADER fileHeader = {};
    ULONG64 optionalAddress = 0;
    USHORT magic = 0;
    const std::string_view requestedModule = args.empty() ? std::string_view() : std::string_view(args[0]);
    if (!imageHeaders(session, requestedModule, index, base, fileHeader, optionalAddress, magic)) {
        out.error("could not read PE headers\n");
        return S_OK;
    }
    const std::string_view filter = args.size() == 2 ? std::string_view(args[1]) : std::string_view();

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32+ optional header\n");
            return S_OK;
        }
        return reportIat<IMAGE_OPTIONAL_HEADER64, IMAGE_THUNK_DATA64>(session, out, index, base, optional, filter);
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32 optional header\n");
            return S_OK;
        }
        return reportIat<IMAGE_OPTIONAL_HEADER32, IMAGE_THUNK_DATA32>(session, out, index, base, optional, filter);
    }
    out.error("unsupported PE optional header magic\n");
    return S_OK;
}

HRESULT runCanary(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() > 1) {
        out.line("usage: !wef.canary [module]");
        return S_OK;
    }

    ULONG index = 0;
    ULONG64 base = 0;
    IMAGE_FILE_HEADER fileHeader = {};
    ULONG64 optionalAddress = 0;
    USHORT magic = 0;
    if (!imageHeaders(
            session,
            args.empty() ? std::string_view() : std::string_view(args[0]),
            index,
            base,
            fileHeader,
            optionalAddress,
            magic)) {
        out.error("could not read PE headers\n");
        return S_OK;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32+ optional header\n");
            return S_OK;
        }
        return reportCanary<IMAGE_OPTIONAL_HEADER64, IMAGE_LOAD_CONFIG_DIRECTORY64>(session, out, index, base, optional);
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optional = {};
        if (!readStruct(session, optionalAddress, optional)) {
            out.error("could not read PE32 optional header\n");
            return S_OK;
        }
        return reportCanary<IMAGE_OPTIONAL_HEADER32, IMAGE_LOAD_CONFIG_DIRECTORY32>(session, out, index, base, optional);
    }
    out.error("unsupported PE optional header magic\n");
    return S_OK;
}

}
