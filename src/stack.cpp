#include "stack.hpp"

#include "config.hpp"
#include "memory.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <optional>
#include <type_traits>
#include <vector>

namespace wef {

namespace {

constexpr ULONG kMaxWalkFrames = 96;
constexpr ULONG64 kDefaultCookieScanBytes = 0x100000;

struct StackFrameInfo {
    ULONG number = 0;
    ULONG64 returnAddress = 0;
    ULONG64 framePointer = 0;
    ULONG64 stackPointer = 0;
};

struct SecurityCookie {
    ULONG64 value = 0;
    ULONG64 address = 0;
    std::string module;
};

struct StackRange {
    ULONG64 base = 0;
    ULONG64 limit = 0;
    bool valid = false;
};

bool evalAddress(DbgSession& session, const std::string& text, ULONG64& value) {
    return session.evaluate(text, value) || parseNumber(text, value);
}

template <typename T>
bool readValue(DbgSession& session, ULONG64 address, T& value) {
    ULONG bytesRead = 0;
    const HRESULT hr = session.readVirtual(address, &value, sizeof(T), &bytesRead);
    return SUCCEEDED(hr) && bytesRead == sizeof(T);
}

bool fieldOffset(DbgSession& session, PCSTR type, PCSTR field, ULONG& offset) {
    const std::string qualified(type);
    const size_t bang = qualified.find('!');
    if (bang == std::string::npos || bang == 0 || bang + 1 >= qualified.size()) {
        return false;
    }

    const std::string moduleName = qualified.substr(0, bang);
    const std::string typeName = qualified.substr(bang + 1);

    ULONG64 moduleBase = 0;
    if (FAILED(session.symbols()->GetModuleByModuleName(moduleName.c_str(), 0, nullptr, &moduleBase))) {
        return false;
    }

    ULONG typeId = 0;
    if (FAILED(session.symbols()->GetTypeId(moduleBase, typeName.c_str(), &typeId))) {
        return false;
    }

    return SUCCEEDED(session.symbols()->GetFieldOffset(moduleBase, typeId, field, &offset));
}

std::string padRight(std::string text, size_t width) {
    if (text.size() >= width) {
        return text;
    }
    text.append(width - text.size(), ' ');
    return text;
}

std::string dmlColor(std::string_view text, std::string_view color) {
    return "<col fg=\"" + std::string(color) + "\">" + dmlEscape(text) + "</col>";
}

void usage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.stack [<addr|expression>] [L<count>]");
    out.line("  !wef.stack cookie [L<max-scan-bytes>]      (also: !wef.canary scan)");
    out.line("  alias after !wef.install: stack");
}

std::vector<StackFrameInfo> walkFrames(DbgSession& session) {
    std::vector<StackFrameInfo> result;
    std::vector<DEBUG_STACK_FRAME> raw(kMaxWalkFrames);
    const HRESULT hr =
        session.control()->GetStackTrace(0, 0, 0, raw.data(), static_cast<ULONG>(raw.size()));
    if (FAILED(hr)) {
        return result;
    }

    ULONG filled = static_cast<ULONG>(raw.size());
    if (hr > S_OK && static_cast<ULONG>(hr) <= static_cast<ULONG>(raw.size())) {
        filled = static_cast<ULONG>(hr);
    }
    while (filled > 0 &&
           raw[filled - 1].InstructionOffset == 0 &&
           raw[filled - 1].ReturnOffset == 0) {
        --filled;
    }

    result.reserve(filled);
    for (ULONG i = 0; i < filled; ++i) {
        StackFrameInfo frame;
        frame.number = i;
        frame.returnAddress = raw[i].ReturnOffset;
        frame.framePointer = raw[i].FrameOffset;
        frame.stackPointer = raw[i].StackOffset;
        result.push_back(frame);
    }
    return result;
}

StackRange threadStackRange(DbgSession& session) {
    StackRange range;

    ULONG64 teb = 0;
    if (!session.evaluate("@$teb", teb) || teb == 0) {
        return range;
    }

    ULONG baseOffset = 0;
    ULONG limitOffset = 0;
    if (!fieldOffset(session, "ntdll!_NT_TIB", "StackBase", baseOffset) ||
        !fieldOffset(session, "ntdll!_NT_TIB", "StackLimit", limitOffset)) {
        const ULONG size = session.pointerSize();
        baseOffset = size == 8 ? 0x08 : 0x04;
        limitOffset = size == 8 ? 0x10 : 0x08;
    }

    if (!readValue(session, teb + baseOffset, range.base) ||
        !readValue(session, teb + limitOffset, range.limit)) {
        return range;
    }

    range.valid = range.base != 0 && range.limit != 0 && range.base > range.limit;
    return range;
}

std::string moduleNameAt(DbgSession& session, ULONG index, ULONG64 base) {
    char name[512] = {};
    if (FAILED(session.symbols()->GetModuleNameString(
            DEBUG_MODNAME_MODULE,
            index,
            base,
            name,
            sizeof(name),
            nullptr))) {
        return {};
    }
    return name;
}

template <typename OptionalHeader>
std::optional<SecurityCookie> cookieFromOptionalHeader(
    DbgSession& session,
    const std::string& module,
    ULONG64 loadConfigAddress,
    ULONG loadConfigSize) {
    using LoadConfig = std::conditional_t<
        sizeof(OptionalHeader) == sizeof(IMAGE_OPTIONAL_HEADER64),
        IMAGE_LOAD_CONFIG_DIRECTORY64,
        IMAGE_LOAD_CONFIG_DIRECTORY32>;

    if (loadConfigAddress == 0 || static_cast<size_t>(loadConfigSize) < sizeof(WORD)) {
        return std::nullopt;
    }

    WORD declaredSize = 0;
    if (!readValue(session, loadConfigAddress, declaredSize)) {
        return std::nullopt;
    }

    LoadConfig loadConfig = {};
    const size_t securityCookieOffset = offsetof(LoadConfig, SecurityCookie);
    const size_t requiredSize = securityCookieOffset + sizeof(loadConfig.SecurityCookie);
    if (static_cast<size_t>(declaredSize) < requiredSize) {
        return std::nullopt;
    }

    ULONG bytesRead = 0;
    const HRESULT hr = session.readVirtual(
        loadConfigAddress,
        &loadConfig,
        static_cast<ULONG>(requiredSize),
        &bytesRead);
    if (FAILED(hr) || bytesRead < requiredSize) {
        return std::nullopt;
    }

    SecurityCookie cookie;
    cookie.module = module;
    cookie.address = loadConfig.SecurityCookie;
    if (cookie.address == 0) {
        return std::nullopt;
    }
    if (!readValue(session, cookie.address, cookie.value) || cookie.value == 0) {
        return std::nullopt;
    }
    return cookie;
}

std::vector<SecurityCookie> collectSecurityCookies(DbgSession& session) {
    std::vector<SecurityCookie> cookies;

    ULONG loaded = 0;
    ULONG unloaded = 0;
    if (FAILED(session.symbols()->GetNumberModules(&loaded, &unloaded))) {
        return cookies;
    }

    for (ULONG index = 0; index < loaded; ++index) {
        ULONG64 base = 0;
        if (FAILED(session.symbols()->GetModuleByIndex(index, &base)) || base == 0) {
            continue;
        }

        IMAGE_DOS_HEADER dos = {};
        if (!readValue(session, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        DWORD ntSignature = 0;
        const ULONG64 ntAddress = base + static_cast<ULONG>(dos.e_lfanew);
        if (!readValue(session, ntAddress, ntSignature) || ntSignature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        USHORT magic = 0;
        const ULONG64 optionalAddress = ntAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (!readValue(session, optionalAddress, magic)) {
            continue;
        }

        std::optional<SecurityCookie> cookie;
        const std::string module = moduleNameAt(session, index, base);
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            IMAGE_OPTIONAL_HEADER64 optional = {};
            if (readValue(session, optionalAddress, optional)) {
                const auto& directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
                cookie = cookieFromOptionalHeader<IMAGE_OPTIONAL_HEADER64>(
                    session,
                    module,
                    base + directory.VirtualAddress,
                    directory.Size);
            }
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            IMAGE_OPTIONAL_HEADER32 optional = {};
            if (readValue(session, optionalAddress, optional)) {
                const auto& directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
                cookie = cookieFromOptionalHeader<IMAGE_OPTIONAL_HEADER32>(
                    session,
                    module,
                    base + directory.VirtualAddress,
                    directory.Size);
            }
        }

        if (cookie.has_value()) {
            cookies.push_back(*cookie);
        }
    }

    return cookies;
}

std::vector<unsigned char> littleEndianPattern(ULONG64 value, ULONG width) {
    std::vector<unsigned char> bytes(width, 0);
    for (ULONG i = 0; i < width; ++i) {
        bytes[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xff);
    }
    return bytes;
}

struct CookieHit {
    ULONG64 address = 0;
    const SecurityCookie* cookie = nullptr;
};

std::vector<CookieHit> scanStackForCookies(
    DbgSession& session,
    const std::vector<SecurityCookie>& cookies,
    const StackRange& range,
    ULONG64 maxScanBytes) {
    std::vector<CookieHit> hits;
    if (!range.valid || cookies.empty()) {
        return hits;
    }

    const ULONG ptrSize = session.pointerSize();
    const ULONG64 spanStart = range.limit;
    const ULONG64 spanEnd = std::min<ULONG64>(range.base, range.limit + maxScanBytes);

    std::vector<std::vector<unsigned char>> patterns;
    patterns.reserve(cookies.size());
    for (const auto& cookie : cookies) {
        patterns.push_back(littleEndianPattern(cookie.value, ptrSize));
    }

    constexpr ULONG64 kPageSize = 0x1000;
    std::vector<unsigned char> buffer(static_cast<size_t>(kPageSize) + ptrSize, 0);
    for (ULONG64 page = spanStart; page < spanEnd; page += kPageSize) {
        ULONG64 want = std::min<ULONG64>(kPageSize + (ptrSize - 1), spanEnd - page);
        ULONG got = 0;
        if (FAILED(session.readVirtual(page, buffer.data(), static_cast<ULONG>(want), &got))) {
            want = std::min<ULONG64>(kPageSize, spanEnd - page);
            if (FAILED(session.readVirtual(page, buffer.data(), static_cast<ULONG>(want), &got))) {
                continue;
            }
        }
        if (got < ptrSize) {
            continue;
        }

        for (size_t p = 0; p < patterns.size(); ++p) {
            const auto& pattern = patterns[p];
            for (ULONG64 offset = 0; offset + ptrSize <= got; ++offset) {
                if (std::memcmp(buffer.data() + offset, pattern.data(), ptrSize) != 0) {
                    continue;
                }
                CookieHit hit;
                hit.address = page + offset;
                hit.cookie = &cookies[p];
                hits.push_back(hit);
            }
        }
    }

    std::sort(hits.begin(), hits.end(), [](const CookieHit& left, const CookieHit& right) {
        return left.address < right.address;
    });
    hits.erase(std::unique(hits.begin(), hits.end(), [](const CookieHit& left, const CookieHit& right) {
        return left.address == right.address;
    }), hits.end());
    return hits;
}

void printAnnotatedStack(DbgSession& session, const Output& out, ULONG64 sp, ULONG64 count) {
    out.heading("Stack");

    const StackRange range = threadStackRange(session);
    if (range.valid) {
        out.line(
            "  thread stack: " + formatAddress(range.limit) + " - " + formatAddress(range.base));
    } else {
        out.line("  thread stack range unavailable");
    }

    const auto frames = walkFrames(session);
    if (frames.empty()) {
        out.line("  stack walk unavailable; annotations limited");
    }

    const auto cookies = collectSecurityCookies(session);
    std::map<ULONG64, const SecurityCookie*> cookieByValue;
    for (const auto& cookie : cookies) {
        cookieByValue.emplace(cookie.value, &cookie);
    }

    std::map<ULONG64, ULONG> retByValue;
    std::map<ULONG64, ULONG> fpByAddress;
    for (const auto& frame : frames) {
        if (frame.returnAddress != 0) {
            retByValue.emplace(frame.returnAddress, frame.number);
        }
        if (frame.framePointer != 0) {
            fpByAddress.emplace(frame.framePointer, frame.number);
        }
    }

    const ULONG ptrSize = session.pointerSize();
    const ULONG64 depth = configGetNumber("dereference.depth", 3);
    out.line("  #    address             value               annotation");
    out.line("  --   -----------------   -----------------   ----------------------------------------");
    for (ULONG64 i = 0; i < count; ++i) {
        const ULONG64 current = sp + (i * ptrSize);
        ULONG64 value = 0;
        const std::string slot = formatHex(i, 2);
        const std::string currentText = formatAddress(current);

        std::string plain = "  " + padRight(slot, 4) + " " + currentText + "  ";
        std::string dml =
            "  " + dmlColor(padRight(slot, 4), "gray") +
            dmlColor(currentText, "yellow") + "  ";

        if (!session.readPointer(current, value)) {
            plain += "<read failed>";
            dml += dmlColor("<read failed>", "red");
            out.dmlLine(plain, dml);
            continue;
        }

        const std::string valueText = formatAddress(value);
        plain += valueText;
        dml += dmlCommandLink(valueText, "!wef.xinfo " + valueText);

        std::vector<std::pair<std::string, std::string>> tags;

        const auto ret = retByValue.find(value);
        if (ret != retByValue.end()) {
            const std::string symbol = session.resolveSymbol(value);
            tags.emplace_back(
                "ret#" + formatHex(static_cast<ULONG64>(ret->second)) +
                    (symbol.empty() ? "" : " -> " + symbol),
                "green");
        }
        const auto fp = fpByAddress.find(current);
        if (fp != fpByAddress.end()) {
            tags.emplace_back("frame #" + formatHex(static_cast<ULONG64>(fp->second)), "cyan");
        }
        const auto cookie = cookieByValue.find(value);
        if (cookie != cookieByValue.end()) {
            tags.emplace_back("cookie " + cookie->second->module, "magenta");
        }
        if (range.valid && value >= range.limit && value < range.base) {
            tags.emplace_back("stack ptr", "blue");
        }

        const std::string desc = describePointerChain(session, value, depth);
        if (!desc.empty() && desc != "NULL") {
            tags.emplace_back(desc, "gray");
        }

        if (tags.empty()) {
            out.dmlLine(plain, dml);
            continue;
        }

        bool first = true;
        for (const auto& tag : tags) {
            plain += first ? "   [" : " | [";
            plain += tag.first;
            plain += "]";
            dml += first ? "   [" : " | [";
            dml += dmlColor(tag.first, tag.second);
            dml += "]";
            first = false;
        }
        out.dmlLine(plain, dml);
    }

    if (frames.empty()) {
        return;
    }
    out.blank();
    std::string backtracePlain = "  frames: ";
    std::string backtraceDml = "  " + dmlColor("frames", "gray") + ": ";
    ULONG shown = 0;
    for (const auto& frame : frames) {
        const std::string symbol = session.resolveSymbol(frame.returnAddress);
        if (symbol.empty()) {
            continue;
        }
        if (shown != 0) {
            backtracePlain += " ";
            backtraceDml += " ";
        }
        backtracePlain += "#" + formatHex(static_cast<ULONG64>(frame.number)) + " " + symbol;
        backtraceDml +=
            dmlColor("#" + formatHex(static_cast<ULONG64>(frame.number)), "gray") + " " +
            dmlCommandLink(symbol, "!wef.xinfo " + formatAddress(frame.returnAddress));
        ++shown;
        if (shown >= 12) {
            break;
        }
    }
    if (shown != 0) {
        out.dmlLine(backtracePlain, backtraceDml);
    }
}

HRESULT runCanaryScanImpl(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    const TargetInfo target = session.targetInfo();
    if (!target.userMode) {
        out.error("canary scan requires a user-mode target\n");
        return S_OK;
    }

    ULONG64 maxScan = configGetNumber("stack.cookie.max_scan", kDefaultCookieScanBytes);
    for (const auto& arg : args) {
        ULONG64 parsed = 0;
        if (parseLengthToken(arg, parsed)) {
            maxScan = parsed;
            continue;
        }
        usage(out);
        return S_OK;
    }

    const auto cookies = collectSecurityCookies(session);
    if (cookies.empty()) {
        out.warning("no /GS security cookies found among loaded modules\n");
        return S_OK;
    }

    out.heading("Stack Cookies");
    for (const auto& cookie : cookies) {
        out.dmlLine(
            "  " + padRight(cookie.module, 24) + " cookie@" + formatAddress(cookie.address) +
                " = " + formatAddress(cookie.value),
            "  " + dmlColor(padRight(cookie.module, 24), "white") +
                " cookie@" + dmlColor(formatAddress(cookie.address), "yellow") +
                " = " + dmlCommandLink(formatAddress(cookie.value), "!wef.xinfo " + formatAddress(cookie.value)));
    }

    const StackRange range = threadStackRange(session);
    if (!range.valid) {
        out.error("thread stack range unavailable; cannot scan\n");
        return S_OK;
    }

    const ULONG64 actualSpan = std::min<ULONG64>(range.base - range.limit, maxScan);
    out.line(
        "  scanning " + formatAddress(range.limit) + " - " + formatAddress(range.limit + actualSpan));

    const auto hits = scanStackForCookies(session, cookies, range, maxScan);
    if (hits.empty()) {
        out.warning("no security-cookie instances found on the scanned stack range\n");
        return S_OK;
    }

    ULONG64 sp = 0;
    if (!session.readRegister("rsp", sp)) {
        session.readRegister("esp", sp);
    }

    for (const auto& hit : hits) {
        std::string relative;
        if (sp != 0) {
            const char* sign = hit.address >= sp ? "+" : "-";
            const ULONG64 delta =
                hit.address >= sp ? hit.address - sp : sp - hit.address;
            relative = " (rsp" + std::string(sign) + "0x" + formatHex(delta) + ")";
        }
        const std::string line = "  " + formatAddress(hit.address) + "  " +
            formatAddress(hit.cookie->value) + "  " + hit.cookie->module + relative;
        const std::string dml =
            "  " + dmlColor(formatAddress(hit.address), "yellow") + "  " +
                dmlColor(formatAddress(hit.cookie->value), "magenta") + "  " +
                dmlColor(hit.cookie->module, "white") + dmlColor(relative, "gray") + "  " +
                dmlCommandLink("[dump]", "!wef.hexdump " + formatAddress(hit.address) + " L32");
        out.dmlLine(line, dml);
    }

    out.field("Instances", formatHex(static_cast<ULONG64>(hits.size())));
    return S_OK;
}

}

HRESULT runStack(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!args.empty()) {
        if (args[0] == "help" || args[0] == "-h" || args[0] == "/?") {
            usage(out);
            return S_OK;
        }
        if (args[0] == "cookie" || args[0] == "canary" || args[0] == "scan") {
            const std::vector<std::string> rest(args.begin() + 1, args.end());
            return runCanaryScanImpl(session, out, rest);
        }
    }

    ULONG64 address = 0;
    if (!session.readRegister("rsp", address) && !session.readRegister("esp", address)) {
        out.error("default stack pointer is unavailable; provide an explicit address\n");
        return S_OK;
    }

    ULONG64 count = configGetNumber("stack.count", configGetNumber("ctx.stack.count", 20));
    for (const auto& arg : args) {
        ULONG64 parsed = 0;
        if (parseLengthToken(arg, parsed)) {
            count = parsed;
            continue;
        }
        if (!evalAddress(session, arg, parsed)) {
            out.error("could not evaluate argument: " + arg + "\n");
            usage(out);
            return S_OK;
        }
        address = parsed;
    }

    printAnnotatedStack(session, out, address, count);
    return S_OK;
}

HRESULT runCanaryScan(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    return runCanaryScanImpl(session, out, args);
}

}
