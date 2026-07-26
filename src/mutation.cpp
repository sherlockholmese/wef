#include "mutation.hpp"

#include <cctype>
#include <cstdlib>
#include <limits>
#include <string_view>
#include <vector>

namespace wef {

namespace {

bool evalAddress(DbgSession& session, std::string_view text, ULONG64& value) {
    return session.evaluate(text, value) || parseNumber(text, value);
}

bool requireLiveUserTarget(DbgSession& session, const Output& out, std::string_view command) {
    const TargetInfo target = session.targetInfo();
    if (!target.userMode || !target.live) {
        out.error(std::string(command) + " requires a live user-mode target\n");
        return false;
    }
    return true;
}

bool parseCount(std::string_view text, ULONG64& value) {
    const std::string copy(text);
    const int base = copy.starts_with("0x") || copy.starts_with("0X") ? 16 : 10;
    char* end = nullptr;
    value = std::strtoull(copy.c_str(), &end, base);
    return end != nullptr && end != copy.c_str() && *end == '\0';
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
    for (const char ch : text) {
        if (ch == ' ' || ch == '\t' || ch == '_' || ch == '`') {
            continue;
        }
        if (std::isxdigit(static_cast<unsigned char>(ch)) == 0) {
            return false;
        }
        cleaned.push_back(ch);
    }
    if (cleaned.empty() || (cleaned.size() % 2) != 0) {
        return false;
    }

    bytes.clear();
    bytes.reserve(cleaned.size() / 2);
    for (size_t i = 0; i < cleaned.size(); i += 2) {
        unsigned char high = 0;
        unsigned char low = 0;
        if (!hexValue(cleaned[i], high) || !hexValue(cleaned[i + 1], low)) {
            return false;
        }
        bytes.push_back(static_cast<unsigned char>((high << 4) | low));
    }
    return true;
}

std::vector<unsigned char> littleEndianBytes(ULONG64 value, ULONG width) {
    std::vector<unsigned char> bytes(width);
    for (ULONG i = 0; i < width; ++i) {
        bytes[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xff);
    }
    return bytes;
}

bool writeBytes(DbgSession& session, const Output& out, ULONG64 address, const std::vector<unsigned char>& bytes) {
    if (bytes.empty()) {
        out.error("no bytes to write\n");
        return false;
    }
    if (bytes.size() > std::numeric_limits<ULONG>::max()) {
        out.error("patch is too large\n");
        return false;
    }

    ULONG written = 0;
    const HRESULT hr = session.writeVirtual(address, bytes.data(), static_cast<ULONG>(bytes.size()), &written);
    if (FAILED(hr) || static_cast<size_t>(written) != bytes.size()) {
        out.error(
            "write failed at " + formatAddress(address) + ": " + formatHResult(hr) +
            " (" + std::to_string(written) + "/" + std::to_string(bytes.size()) + " bytes)\n");
        return false;
    }

    std::vector<unsigned char> verification(bytes.size());
    ULONG read = 0;
    const HRESULT readHr = session.readVirtual(
        address,
        verification.data(),
        static_cast<ULONG>(verification.size()),
        &read);
    if (FAILED(readHr) || static_cast<size_t>(read) != bytes.size() || verification != bytes) {
        out.error("write verification failed at " + formatAddress(address) + "\n");
        return false;
    }
    return true;
}

void patchUsage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.patch byte|word|dword|qword <addr> <value>");
    out.line("  !wef.patch string <addr> <text> [-z]");
    out.line("  !wef.patch hex <addr> <hex-bytes>");
}

void nopUsage(const Output& out) {
    out.line("usage: !wef.nop [addr] [L<byte-count>|--n <count>|--b <count>]");
}

void skipiUsage(const Output& out) {
    out.line("usage: !wef.skipi [addr] [-n <instruction-count>]");
}

bool currentInstructionPointer(DbgSession& session, ULONG64& value, std::string_view& name) {
    name = "rip";
    if (session.readRegister(name, value)) {
        return true;
    }
    name = "eip";
    return session.readRegister(name, value);
}

}

HRESULT runPatch(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        patchUsage(out);
        return S_OK;
    }
    if (!requireLiveUserTarget(session, out, "patch")) {
        return S_OK;
    }

    ULONG64 address = 0;
    if (!evalAddress(session, args[1], address)) {
        out.error("could not evaluate address: " + args[1] + "\n");
        return S_OK;
    }

    std::vector<unsigned char> bytes;
    if (args[0] == "byte" || args[0] == "word" || args[0] == "dword" || args[0] == "qword") {
        if (args.size() != 3) {
            patchUsage(out);
            return S_OK;
        }
        ULONG64 value = 0;
        if (!evalAddress(session, args[2], value)) {
            out.error("could not evaluate value: " + args[2] + "\n");
            return S_OK;
        }
        const ULONG width =
            args[0] == "byte" ? 1 :
            args[0] == "word" ? 2 :
            args[0] == "dword" ? 4 : 8;
        bytes = littleEndianBytes(value, width);
    } else if (args[0] == "string") {
        bool zeroTerminate = false;
        std::vector<std::string> textParts;
        for (size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "-z") {
                zeroTerminate = true;
            } else {
                textParts.push_back(args[i]);
            }
        }
        const std::string text = joinArgs(textParts, 0, textParts.size());
        bytes.assign(text.begin(), text.end());
        if (zeroTerminate) {
            bytes.push_back(0);
        }
    } else if (args[0] == "hex") {
        const std::string text = joinArgs(args, 2, args.size());
        if (!parseHexBytes(text, bytes)) {
            out.error("invalid hexadecimal byte string\n");
            return S_OK;
        }
    } else {
        patchUsage(out);
        return S_OK;
    }

    if (!writeBytes(session, out, address, bytes)) {
        return S_OK;
    }
    out.heading("Patch");
    out.field("Address", formatAddress(address));
    out.field("Written", std::to_string(bytes.size()) + " bytes");
    out.dmlLine(
        "  [hexdump]",
        "  " + dmlCommandLink("hexdump", "!wef.hexdump " + formatAddress(address) + " L" + formatHex(bytes.size())));
    return S_OK;
}

HRESULT runNop(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!requireLiveUserTarget(session, out, "nop")) {
        return S_OK;
    }

    ULONG64 address = 0;
    std::string_view ipName;
    if (!currentInstructionPointer(session, address, ipName)) {
        out.error("instruction pointer is unavailable\n");
        return S_OK;
    }

    ULONG64 byteCount = 0;
    bool explicitCount = false;
    bool gotAddress = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--n" || args[i] == "-n" || args[i] == "--b" || args[i] == "-b") {
            if (i + 1 >= args.size() || !parseCount(args[++i], byteCount)) {
                nopUsage(out);
                return S_OK;
            }
            explicitCount = true;
            continue;
        }

        ULONG64 parsed = 0;
        if (parseLengthToken(args[i], parsed)) {
            byteCount = parsed;
            explicitCount = true;
            continue;
        }
        if (!gotAddress && evalAddress(session, args[i], parsed)) {
            address = parsed;
            gotAddress = true;
            continue;
        }
        nopUsage(out);
        return S_OK;
    }

    if (!explicitCount) {
        ULONG64 next = address;
        if (session.disassembleLine(address, next).empty() || next <= address) {
            out.error("could not determine instruction size at " + formatAddress(address) + "\n");
            return S_OK;
        }
        byteCount = next - address;
    }
    if (byteCount == 0 || byteCount > std::numeric_limits<ULONG>::max()) {
        out.error("invalid nop byte count\n");
        return S_OK;
    }

    std::vector<unsigned char> bytes(static_cast<size_t>(byteCount), 0x90);
    if (!writeBytes(session, out, address, bytes)) {
        return S_OK;
    }
    out.heading("NOP Patch");
    out.field("Address", formatAddress(address));
    out.field("Written", std::to_string(byteCount) + " bytes");
    return S_OK;
}

HRESULT runSkipi(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!requireLiveUserTarget(session, out, "skipi")) {
        return S_OK;
    }

    ULONG64 count = 1;
    ULONG64 current = 0;
    std::string_view ipName;
    if (!currentInstructionPointer(session, current, ipName)) {
        out.error("instruction pointer is unavailable\n");
        return S_OK;
    }

    bool gotAddress = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "-n" || args[i] == "--n") {
            if (i + 1 >= args.size() || !parseCount(args[++i], count) || count == 0) {
                skipiUsage(out);
                return S_OK;
            }
            continue;
        }

        ULONG64 address = 0;
        if (!gotAddress && evalAddress(session, args[i], address)) {
            current = address;
            gotAddress = true;
            continue;
        }
        skipiUsage(out);
        return S_OK;
    }

    const ULONG64 original = current;
    for (ULONG64 i = 0; i < count; ++i) {
        ULONG64 next = current;
        if (session.disassembleLine(current, next).empty() || next <= current) {
            out.error("could not determine instruction size at " + formatAddress(current) + "\n");
            return S_OK;
        }
        current = next;
    }

    if (!session.writeRegister(ipName, current)) {
        out.error("failed to update instruction pointer\n");
        return S_OK;
    }
    out.heading("Skip Instruction");
    out.field("From", formatAddress(original));
    out.field("To", formatAddress(current));
    out.field("Skipped", std::to_string(count) + " instruction(s)");
    return S_OK;
}

}
