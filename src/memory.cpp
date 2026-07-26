#include "memory.hpp"

#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string_view>
#include <vector>

namespace wef {

namespace {

bool evalAddress(DbgSession& session, std::string_view text, ULONG64& value) {
    return session.evaluate(text, value) || parseNumber(text, value);
}

bool isPrintableAscii(unsigned char ch) {
    return ch >= 0x20 && ch <= 0x7e;
}

void telescopeUsage(const Output& out) {
    out.line("usage: !wef.telescope [<addr>] [L<count>]");
}

void hexdumpUsage(const Output& out) {
    out.line("usage: !wef.hexdump <addr> [L<size>] [-force]");
}

void searchUsage(const Output& out) {
    out.line("usage: !wef.search_pattern <text|addr|hex:414243> [start] [L<size>] [-max <count>] [-x|-w|-rwx] [-image|-mapped|-private]");
}

std::string byteToHex(unsigned char value) {
    std::ostringstream stream;
    stream << std::hex << std::nouppercase << std::setfill('0') << std::setw(2) << static_cast<unsigned>(value);
    return stream.str();
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

bool isHexDigit(char ch) {
    return std::isxdigit(static_cast<unsigned char>(ch)) != 0;
}

bool hexValue(char ch, unsigned char& value) {
    if (ch >= '0' && ch <= '9') {
        value = static_cast<unsigned char>(ch - '0');
        return true;
    }
    if (ch >= 'a' && ch <= 'f') {
        value = static_cast<unsigned char>(ch - 'a' + 10);
        return true;
    }
    if (ch >= 'A' && ch <= 'F') {
        value = static_cast<unsigned char>(ch - 'A' + 10);
        return true;
    }
    return false;
}

bool parseHexBytes(std::string_view text, std::vector<unsigned char>& bytes) {
    std::string cleaned;
    cleaned.reserve(text.size());
    for (char ch : text) {
        if (ch == '`' || ch == '_' || ch == ' ') {
            continue;
        }
        if (!isHexDigit(ch)) {
            return false;
        }
        cleaned.push_back(ch);
    }
    if (cleaned.empty() || (cleaned.size() % 2) != 0) {
        return false;
    }

    bytes.clear();
    bytes.reserve(cleaned.size() / 2);
    for (size_t i = 0; i + 1 < cleaned.size(); i += 2) {
        unsigned char hi = 0;
        unsigned char lo = 0;
        if (!hexValue(cleaned[i], hi) || !hexValue(cleaned[i + 1], lo)) {
            return false;
        }
        bytes.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::vector<unsigned char> numberBytes(ULONG64 value, ULONG width) {
    std::vector<unsigned char> bytes(width, 0);
    for (ULONG i = 0; i < width; ++i) {
        bytes[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xff);
    }
    return bytes;
}

bool parseSearchPattern(DbgSession& session, const std::string& token, std::vector<unsigned char>& bytes) {
    if (token.starts_with("hex:")) {
        return parseHexBytes(std::string_view(token).substr(4), bytes);
    }
    if (token.starts_with("str:")) {
        bytes.assign(token.begin() + 4, token.end());
        return !bytes.empty();
    }

    ULONG64 value = 0;
    const bool numericLooking =
        token.starts_with("0x") ||
        token.starts_with("0X") ||
        token.starts_with("@") ||
        token.find('`') != std::string::npos;
    if (numericLooking && evalAddress(session, token, value)) {
        bytes = numberBytes(value, session.pointerSize());
        return true;
    }

    bytes.assign(token.begin(), token.end());
    return !bytes.empty();
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::string result;
    for (unsigned char byte : bytes) {
        if (!result.empty()) {
            result += ' ';
        }
        result += byteToHex(byte);
    }
    return result;
}

bool isReadableProtect(ULONG protect) {
    const ULONG base = protect & 0xff;
    return base == PAGE_READONLY ||
        base == PAGE_READWRITE ||
        base == PAGE_WRITECOPY ||
        base == PAGE_EXECUTE_READ ||
        base == PAGE_EXECUTE_READWRITE ||
        base == PAGE_EXECUTE_WRITECOPY;
}

bool hasWriteProtect(ULONG protect) {
    const ULONG base = protect & 0xff;
    return base == PAGE_READWRITE || base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool hasExecuteProtect(ULONG protect) {
    const ULONG base = protect & 0xff;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

bool hasGuardOrNoAccess(ULONG protect) {
    return (protect & PAGE_GUARD) != 0 || (protect & 0xff) == PAGE_NOACCESS;
}

std::vector<MemoryWatch>& watchStore() {
    static std::vector<MemoryWatch> watches;
    return watches;
}

std::mutex& watchMutex() {
    static std::mutex mutex;
    return mutex;
}

ULONG& nextWatchId() {
    static ULONG id = 1;
    return id;
}

bool parseCountValue(std::string_view text, ULONG64& value) {
    const std::string copy(text);
    try {
        size_t used = 0;
        const int base = copy.starts_with("0x") || copy.starts_with("0X") ? 16 : 10;
        value = std::stoull(copy, &used, base);
        return used == copy.size();
    } catch (...) {
        return false;
    }
}

std::string escapedBytes(const std::vector<unsigned char>& bytes) {
    std::string result;
    result.reserve(bytes.size() * 4);
    for (const unsigned char byte : bytes) {
        result += "\\x" + byteToHex(byte);
    }
    return result;
}

bool readBytes(DbgSession& session, const Output& out, ULONG64 address, ULONG64 length, std::vector<unsigned char>& bytes) {
    if (length == 0 || length > std::numeric_limits<ULONG>::max()) {
        out.error("invalid byte count\n");
        return false;
    }
    bytes.assign(static_cast<size_t>(length), 0);
    ULONG read = 0;
    const HRESULT hr = session.readVirtual(address, bytes.data(), static_cast<ULONG>(length), &read);
    if (FAILED(hr) || static_cast<ULONG64>(read) != length) {
        out.error(
            "read failed at " + formatAddress(address) + ": " + formatHResult(hr) +
            " (" + std::to_string(read) + "/" + std::to_string(length) + " bytes)\n");
        return false;
    }
    return true;
}

bool writeVerified(DbgSession& session, const Output& out, ULONG64 address, const std::vector<unsigned char>& bytes) {
    ULONG written = 0;
    const HRESULT hr = session.writeVirtual(address, bytes.data(), static_cast<ULONG>(bytes.size()), &written);
    if (FAILED(hr) || static_cast<size_t>(written) != bytes.size()) {
        out.error("write failed at " + formatAddress(address) + ": " + formatHResult(hr) + "\n");
        return false;
    }

    std::vector<unsigned char> verification;
    if (!readBytes(session, out, address, bytes.size(), verification) || verification != bytes) {
        out.error("write verification failed at " + formatAddress(address) + "\n");
        return false;
    }
    return true;
}

}

std::string previewString(DbgSession& session, ULONG64 address) {
    if (address == 0) {
        return {};
    }

    unsigned char buffer[96] = {};
    ULONG bytesRead = 0;
    if (FAILED(session.readVirtual(address, buffer, sizeof(buffer), &bytesRead)) || bytesRead < 4) {
        return {};
    }

    std::string ascii;
    for (ULONG i = 0; i < bytesRead; ++i) {
        if (buffer[i] == 0) {
            break;
        }
        if (!isPrintableAscii(buffer[i])) {
            ascii.clear();
            break;
        }
        ascii.push_back(static_cast<char>(buffer[i]));
        if (ascii.size() >= 48) {
            break;
        }
    }
    if (ascii.size() >= 4) {
        return "\"" + ascii + "\"";
    }

    std::string wide;
    for (ULONG i = 0; i + 1 < bytesRead; i += 2) {
        const unsigned char lo = buffer[i];
        const unsigned char hi = buffer[i + 1];
        if (lo == 0 && hi == 0) {
            break;
        }
        if (hi != 0 || !isPrintableAscii(lo)) {
            wide.clear();
            break;
        }
        wide.push_back(static_cast<char>(lo));
        if (wide.size() >= 48) {
            break;
        }
    }
    if (wide.size() >= 4) {
        return "L\"" + wide + "\"";
    }

    return {};
}

std::string describePointer(DbgSession& session, ULONG64 value) {
    if (value == 0) {
        return "NULL";
    }

    const std::string symbol = session.resolveSymbol(value);
    if (!symbol.empty()) {
        return symbol;
    }

    const std::string stringPreview = previewString(session, value);
    if (!stringPreview.empty()) {
        return stringPreview;
    }

    MEMORY_BASIC_INFORMATION64 info = {};
    if (session.queryVirtual(value, info)) {
        std::string region = stateToString(info.State);
        const std::string protection = protectionToString(info.Protect);
        const std::string type = typeToString(info.Type);
        if (!protection.empty()) {
            region += " " + protection;
        }
        if (!type.empty()) {
            region += " " + type;
        }

        const std::string moduleName = session.moduleNameForOffset(value);
        if (!moduleName.empty()) {
            region += " " + moduleName;
        }
        return region;
    }

    return "unmapped or unreadable";
}

std::string describePointerChain(DbgSession& session, ULONG64 value, ULONG64 depth) {
    std::string result = describePointer(session, value);
    ULONG64 current = value;

    for (ULONG64 i = 0; i < depth; ++i) {
        ULONG64 next = 0;
        if (!session.readPointer(current, next) || next == 0 || next == current) {
            break;
        }

        result += " -> " + formatAddress(next);
        const std::string final = describePointer(session, next);
        if (!final.empty() && final != "unmapped or unreadable") {
            result += " (" + final + ")";
            break;
        }
        current = next;
    }

    return result;
}

HRESULT runTelescope(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    ULONG64 address = 0;
    if (!session.readRegister("rsp", address) && !session.readRegister("esp", address)) {
        out.error("default stack pointer is unavailable; provide an explicit address\n");
        return S_OK;
    }

    ULONG64 count = configGetNumber("telescope.count", 20);
    bool gotAddress = false;
    for (const auto& arg : args) {
        ULONG64 parsed = 0;
        if (parseLengthToken(arg, parsed)) {
            count = parsed;
            continue;
        }
        if (gotAddress) {
            telescopeUsage(out);
            return S_OK;
        }
        if (!evalAddress(session, arg, parsed)) {
            out.error("could not evaluate address: " + arg + "\n");
            return S_OK;
        }
        address = parsed;
        gotAddress = true;
    }

    const ULONG ptrSize = session.pointerSize();
    out.heading("Telescope");
    out.line("  #    address             value               dereference");
    out.line("  --   -----------------   -----------------   ----------------------------------------");
    for (ULONG64 i = 0; i < count; ++i) {
        const ULONG64 current = address + (i * ptrSize);
        ULONG64 value = 0;
        const std::string slot = formatHex(i, 2);
        const std::string currentText = formatAddress(current);
        std::string line = "  " + padRight(slot, 4) + " " + currentText + "  ";
        if (!session.readPointer(current, value)) {
            line += "<read failed>";
            out.dmlLine(
                line,
                std::string("  <col fg=\"gray\">") + dmlEscape(padRight(slot, 4)) + "</col> " +
                    "<col fg=\"yellow\">" + dmlEscape(currentText) + "</col>  " +
                    "<col fg=\"red\">&lt;read failed&gt;</col>");
            continue;
        }
        const std::string desc = describePointerChain(session, value, configGetNumber("dereference.depth", 3));
        const std::string valueText = formatAddress(value);
        line += valueText + "  " + desc;
        const std::string dml =
            std::string("  <col fg=\"gray\">") + dmlEscape(padRight(slot, 4)) + "</col> " +
            "<col fg=\"yellow\">" + dmlEscape(currentText) + "</col>  " +
            "<col fg=\"white\">" + dmlEscape(valueText) + "</col>  " +
            "<col fg=\"cyan\">" + dmlEscape(desc) + "</col>";
        out.dmlLine(
            line,
            dml);
    }
    return S_OK;
}

HRESULT runHexdump(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        hexdumpUsage(out);
        return S_OK;
    }

    ULONG64 address = 0;
    ULONG64 size = configGetNumber("hexdump.size", 0x100);
    bool force = false;
    bool gotAddress = false;

    for (const auto& arg : args) {
        if (arg == "-force") {
            force = true;
            continue;
        }

        ULONG64 parsed = 0;
        if (parseLengthToken(arg, parsed)) {
            size = parsed;
            continue;
        }

        if (gotAddress) {
            hexdumpUsage(out);
            return S_OK;
        }
        if (!evalAddress(session, arg, parsed)) {
            out.error("could not evaluate address: " + arg + "\n");
            return S_OK;
        }
        address = parsed;
        gotAddress = true;
    }

    if (!gotAddress) {
        hexdumpUsage(out);
        return S_OK;
    }

    if (!force && size > 0x1000) {
        out.error("read size exceeds 0x1000 bytes; pass -force to override\n");
        return S_OK;
    }

    out.heading("Hexdump");
    for (ULONG64 offset = 0; offset < size; offset += 16) {
        const ULONG lineSize = static_cast<ULONG>(std::min<ULONG64>(16, size - offset));
        unsigned char bytes[16] = {};
        ULONG bytesRead = 0;
        const HRESULT hr = session.readVirtual(address + offset, bytes, lineSize, &bytesRead);

        std::ostringstream line;
        line << formatAddress(address + offset) << "  ";
        for (ULONG i = 0; i < 16; ++i) {
            if (i < bytesRead) {
                line << byteToHex(bytes[i]);
            } else if (i < lineSize) {
                line << "??";
            } else {
                line << "  ";
            }
            line << ' ';
        }

        line << " ";
        for (ULONG i = 0; i < bytesRead; ++i) {
            line << (isPrintableAscii(bytes[i]) ? static_cast<char>(bytes[i]) : '.');
        }
        if (FAILED(hr) || bytesRead < lineSize) {
            line << "  <read failed at " << formatAddress(address + offset + bytesRead)
                 << " for 0x" << formatHex(lineSize - bytesRead) << " bytes>";
        }
        const std::string plain = line.str();
        const std::string dml =
            std::string("<col fg=\"yellow\">") + dmlEscape(formatAddress(address + offset)) + "</col>  " +
            dmlEscape(plain.substr(20));
        out.dmlLine(
            plain,
            dml);
    }
    return S_OK;
}

HRESULT runSearchPattern(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        searchUsage(out);
        return S_OK;
    }

    const TargetInfo target = session.targetInfo();
    if (!target.userMode) {
        out.error("search-pattern requires a user-mode target\n");
        return S_OK;
    }

    std::vector<unsigned char> pattern;
    if (!parseSearchPattern(session, args[0], pattern)) {
        out.error("could not parse search pattern\n");
        return S_OK;
    }

    ULONG64 start = 0;
    ULONG64 size = session.pointerSize() == 8 ? 0x0000800000000000ULL : 0xffffffffULL;
    ULONG64 maxHits = configGetNumber("search.max_hits", 80);
    bool gotStart = false;
    bool wantExecute = false;
    bool wantWrite = false;
    bool onlyImage = false;
    bool onlyMapped = false;
    bool onlyPrivate = false;

    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "-x") {
            wantExecute = true;
            continue;
        }
        if (args[i] == "-w") {
            wantWrite = true;
            continue;
        }
        if (args[i] == "-rwx") {
            wantExecute = true;
            wantWrite = true;
            continue;
        }
        if (args[i] == "-image") {
            onlyImage = true;
            continue;
        }
        if (args[i] == "-mapped") {
            onlyMapped = true;
            continue;
        }
        if (args[i] == "-private") {
            onlyPrivate = true;
            continue;
        }
        if (args[i] == "-max" && i + 1 < args.size()) {
            ULONG64 parsed = 0;
            if (!parseNumber(args[i + 1], parsed)) {
                searchUsage(out);
                return S_OK;
            }
            maxHits = parsed;
            ++i;
            continue;
        }

        ULONG64 parsed = 0;
        if (parseLengthToken(args[i], parsed)) {
            size = parsed;
            continue;
        }
        if (!gotStart && evalAddress(session, args[i], parsed)) {
            start = parsed;
            gotStart = true;
            continue;
        }
        searchUsage(out);
        return S_OK;
    }

    out.heading("Search Pattern");
    out.field("pattern", bytesToHex(pattern));
    out.line("  hit                protect      type      module/preview                          actions");
    out.line("  -----------------  -----------  --------  ----------------------------------------  ------------------------------");

    ULONG64 address = start;
    ULONG64 endLimit = size >= (std::numeric_limits<ULONG64>::max() - start) ? std::numeric_limits<ULONG64>::max() : start + size;
    ULONG64 hits = 0;
    ULONG64 regions = 0;
    while (address < endLimit && regions < 200000 && hits < maxHits) {
        MEMORY_BASIC_INFORMATION64 info = {};
        if (!session.queryVirtual(address, info)) {
            if (address == 0) {
                out.error("QueryVirtual failed at " + formatAddress(address) + "\n");
                return S_OK;
            }
            break;
        }

        const ULONG64 base = info.BaseAddress;
        const ULONG64 regionSize = info.RegionSize;
        const ULONG64 regionEnd = regionSize == 0 ? base : base + regionSize;
        if (info.State == MEM_COMMIT &&
            !hasGuardOrNoAccess(info.Protect) &&
            isReadableProtect(info.Protect) &&
            (!wantExecute || hasExecuteProtect(info.Protect)) &&
            (!wantWrite || hasWriteProtect(info.Protect)) &&
            (!onlyImage || info.Type == MEM_IMAGE) &&
            (!onlyMapped || info.Type == MEM_MAPPED) &&
            (!onlyPrivate || info.Type == MEM_PRIVATE)) {
            ULONG64 searchBase = std::max(base, start);
            ULONG64 searchEnd = std::min(regionEnd, endLimit);
            while (searchBase < searchEnd && hits < maxHits) {
                ULONG64 match = 0;
                const ULONG64 searchSize = searchEnd - searchBase;
                const HRESULT hr = session.dataSpaces()->SearchVirtual(
                    searchBase,
                    searchSize,
                    const_cast<unsigned char*>(pattern.data()),
                    static_cast<ULONG>(pattern.size()),
                    1,
                    &match);
                if (FAILED(hr)) {
                    break;
                }

                const std::string module = session.moduleNameForOffset(match);
                const std::string preview = previewString(session, match);
                std::string note = module;
                if (!preview.empty()) {
                    if (!note.empty()) {
                        note += " ";
                    }
                    note += preview;
                }
                const std::string plain =
                    "  " + formatAddress(match) + "  " +
                    padRight(protectionToString(info.Protect), 11) + "  " +
                    padRight(typeToString(info.Type), 8) + "  " +
                    padRight(note, 40) + "  " +
                    "[dump] [tel] [chunk]";
                const std::string dml =
                    "  " + dmlColor(formatAddress(match), "yellow") + "  " +
                    dmlColor(padRight(protectionToString(info.Protect), 11), "cyan") + "  " +
                    dmlColor(padRight(typeToString(info.Type), 8), "magenta") + "  " +
                    dmlColor(padRight(note, 40), "white") + "  " +
                    dmlCommandLink("dump", "!wef.hexdump " + formatAddress(match) + " L80") + " " +
                    dmlCommandLink("tel", "!wef.telescope " + formatAddress(match) + " L8") + " " +
                    dmlCommandLink("chunk", "!wef.chunk " + formatAddress(match));
                out.dmlLine(plain, dml);
                ++hits;
                searchBase = match + 1;
            }
        }

        if (regionSize == 0 || regionEnd <= address) {
            address += 0x1000;
        } else {
            address = regionEnd;
        }
        ++regions;
    }

    if (hits == 0) {
        out.warning("no matches found\n");
    } else if (hits >= maxHits) {
        out.warning("search results truncated; increase -max or search.max_hits\n");
    }
    return S_OK;
}

HRESULT runPrintFormat(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        out.line("usage: !wef.print_format [--lang <format>] [-l <length>] <address> [length]");
        return S_OK;
    }

    ULONG64 address = 0;
    ULONG64 length = 32;
    std::string language = "hex";
    bool gotAddress = false;
    bool gotLength = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--lang" && i + 1 < args.size()) {
            language = args[++i];
            continue;
        }
        if ((args[i] == "-l" || args[i] == "--length") && i + 1 < args.size()) {
            if (!parseCountValue(args[++i], length)) {
                out.error("invalid byte count: " + args[i] + "\n");
                return S_OK;
            }
            gotLength = true;
            continue;
        }
        ULONG64 parsed = 0;
        if (!gotAddress && evalAddress(session, args[i], parsed)) {
            address = parsed;
            gotAddress = true;
            continue;
        }
        if (gotAddress && !gotLength && parseCountValue(args[i], parsed)) {
            length = parsed;
            gotLength = true;
            continue;
        }
        out.line("usage: !wef.print_format [--lang <format>] [-l <length>] <address> [length]");
        return S_OK;
    }
    if (!gotAddress) {
        out.error("an address is required\n");
        return S_OK;
    }

    if (length > configGetNumber("print.max_length", 4096)) {
        out.error("byte count exceeds print.max_length\n");
        return S_OK;
    }
    std::vector<unsigned char> bytes;
    if (!readBytes(session, out, address, length, bytes)) {
        return S_OK;
    }

    std::string formatted;
    if (language == "hex") {
        for (const unsigned char byte : bytes) {
            formatted += byteToHex(byte);
        }
    } else if (language == "python") {
        formatted = "b\"" + escapedBytes(bytes) + "\"";
    } else if (language == "bytearray") {
        formatted = "bytearray(b\"" + escapedBytes(bytes) + "\")";
    } else if (language == "c" || language == "js" || language == "asm") {
        formatted = language == "c" ? "{ " : language == "js" ? "new Uint8Array([" : "db ";
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i != 0) {
                formatted += ", ";
            }
            formatted += "0x" + byteToHex(bytes[i]);
        }
        formatted += language == "c" ? " }" : language == "js" ? "])" : "";
    } else {
        out.error("unsupported language: " + language + "\n");
        return S_OK;
    }

    out.heading("Print Format");
    out.field("Address", formatAddress(address));
    out.field("Length", std::to_string(length));
    out.line(formatted);
    return S_OK;
}

HRESULT runXorMemory(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() != 4 || (args[0] != "display" && args[0] != "patch")) {
        out.line("usage: !wef.xor_memory display|patch <address> <length> <key|hex:bytes>");
        return S_OK;
    }

    ULONG64 address = 0;
    ULONG64 length = 0;
    if (!evalAddress(session, args[1], address)) {
        out.error("could not evaluate address: " + args[1] + "\n");
        return S_OK;
    }
    if (!parseCountValue(args[2], length) || length == 0) {
        out.error("invalid byte count: " + args[2] + "\n");
        return S_OK;
    }
    if (length > configGetNumber("xor.max_length", 65536)) {
        out.error("byte count exceeds xor.max_length\n");
        return S_OK;
    }

    std::vector<unsigned char> key;
    if (args[3].starts_with("hex:")) {
        if (!parseHexBytes(std::string_view(args[3]).substr(4), key)) {
            out.error("invalid hexadecimal XOR key\n");
            return S_OK;
        }
    } else {
        key.assign(args[3].begin(), args[3].end());
    }
    if (key.empty()) {
        out.error("XOR key cannot be empty\n");
        return S_OK;
    }

    std::vector<unsigned char> bytes;
    if (!readBytes(session, out, address, length, bytes)) {
        return S_OK;
    }
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] ^= key[i % key.size()];
    }

    if (args[0] == "patch") {
        const TargetInfo target = session.targetInfo();
        if (!target.userMode || !target.live) {
            out.error("xor-memory patch requires a live user-mode target\n");
            return S_OK;
        }
        if (!writeVerified(session, out, address, bytes)) {
            return S_OK;
        }
    }

    out.heading(args[0] == "patch" ? "XOR Memory Patch" : "XOR Memory Display");
    out.field("Address", formatAddress(address));
    out.field("Length", std::to_string(length));
    out.field("Result", bytesToHex(bytes));
    if (args[0] == "patch") {
        out.dmlLine(
            "  [hexdump]",
            "  " + dmlCommandLink("hexdump", "!wef.hexdump " + formatAddress(address) + " L" + formatHex(length)));
    }
    return S_OK;
}

std::vector<MemoryWatch> memoryWatches() {
    std::lock_guard<std::mutex> lock(watchMutex());
    return watchStore();
}

HRESULT runMemory(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        out.line("usage: !wef.memory watch <address> [L<size>]|unwatch <id>|list|reset");
        return S_OK;
    }

    if (args[0] == "list") {
        if (args.size() != 1) {
            out.line("usage: !wef.memory watch <address> [L<size>]|unwatch <id>|list|reset");
            return S_OK;
        }
        out.heading("Memory Watches");
        const auto watches = memoryWatches();
        if (watches.empty()) {
            out.line("  none");
            return S_OK;
        }
        for (const auto& watch : watches) {
            out.line(
                "  id=" + std::to_string(watch.id) +
                "  address=" + formatAddress(watch.address) +
                "  size=0x" + formatHex(watch.size));
        }
        return S_OK;
    }

    if (args[0] == "reset") {
        if (args.size() != 1) {
            out.line("usage: !wef.memory watch <address> [L<size>]|unwatch <id>|list|reset");
            return S_OK;
        }
        std::lock_guard<std::mutex> lock(watchMutex());
        watchStore().clear();
        out.line("memory watches cleared");
        return S_OK;
    }

    if (args[0] == "unwatch") {
        ULONG64 id = 0;
        if (args.size() != 2 || !parseCountValue(args[1], id) || id > std::numeric_limits<ULONG>::max()) {
            out.line("usage: !wef.memory unwatch <id>");
            return S_OK;
        }
        const ULONG watchId = static_cast<ULONG>(id);
        std::lock_guard<std::mutex> lock(watchMutex());
        const auto found = std::find_if(
            watchStore().begin(),
            watchStore().end(),
            [watchId](const MemoryWatch& watch) { return watch.id == watchId; });
        if (found == watchStore().end()) {
            out.error("unknown memory watch id\n");
            return S_OK;
        }
        watchStore().erase(found);
        out.line("memory watch removed");
        return S_OK;
    }

    if (args[0] == "watch") {
        if (args.size() < 2 || args.size() > 3) {
            out.line("usage: !wef.memory watch <address> [L<size>]");
            return S_OK;
        }
        ULONG64 address = 0;
        if (!evalAddress(session, args[1], address)) {
            out.error("could not evaluate address: " + args[1] + "\n");
            return S_OK;
        }
        ULONG64 size = 0x40;
        if (args.size() == 3 && !parseLengthToken(args[2], size) && !parseCountValue(args[2], size)) {
            out.error("invalid watch size: " + args[2] + "\n");
            return S_OK;
        }
        if (size == 0 || size > configGetNumber("memory.watch.max_size", 4096)) {
            out.error("watch size exceeds memory.watch.max_size\n");
            return S_OK;
        }

        std::lock_guard<std::mutex> lock(watchMutex());
        if (static_cast<ULONG64>(watchStore().size()) >= configGetNumber("memory.watch.max_count", 16)) {
            out.error("memory watch count exceeds memory.watch.max_count\n");
            return S_OK;
        }
        const MemoryWatch watch = {nextWatchId()++, address, size};
        watchStore().push_back(watch);
        out.heading("Memory Watch");
        out.field("ID", std::to_string(watch.id));
        out.field("Address", formatAddress(watch.address));
        out.field("Size", "0x" + formatHex(watch.size));
        return S_OK;
    }

    out.line("usage: !wef.memory watch <address> [L<size>]|unwatch <id>|list|reset");
    return S_OK;
}

}
