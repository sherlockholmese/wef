#include "pattern.hpp"

#include "config.hpp"

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

namespace wef {

namespace {

std::string cyclicPattern(ULONG64 length) {
    static constexpr char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static constexpr char lower[] = "abcdefghijklmnopqrstuvwxyz";
    static constexpr char digits[] = "0123456789";

    std::string pattern;
    pattern.reserve(static_cast<size_t>(length));
    for (char a : upper) {
        for (char b : lower) {
            for (char c : digits) {
                if (pattern.size() >= length) {
                    return pattern;
                }
                pattern.push_back(a);
                if (pattern.size() >= length) {
                    return pattern;
                }
                pattern.push_back(b);
                if (pattern.size() >= length) {
                    return pattern;
                }
                pattern.push_back(c);
            }
        }
    }
    return pattern.substr(0, static_cast<size_t>(std::min<ULONG64>(length, pattern.size())));
}

std::vector<unsigned char> valueBytes(ULONG64 value, ULONG width) {
    std::vector<unsigned char> bytes(width, 0);
    for (ULONG i = 0; i < width; ++i) {
        bytes[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xff);
    }
    return bytes;
}

std::vector<unsigned char> needleBytes(DbgSession& session, const std::string& token) {
    ULONG64 value = 0;
    if (session.evaluate(token, value) || parseNumber(token, value)) {
        return valueBytes(value, session.pointerSize());
    }
    return std::vector<unsigned char>(token.begin(), token.end());
}

void usage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.pattern create <length>");
    out.line("  !wef.pattern search|offset <value|ascii> [L<max-length>]");
}

bool parseCount(std::string_view text, ULONG64& value) {
    const std::string copy(text);
    const int base = copy.starts_with("0x") || copy.starts_with("0X") ? 16 : 10;
    char* end = nullptr;
    value = std::strtoull(copy.c_str(), &end, base);
    return end != nullptr && *end == '\0';
}

HRESULT createPattern(const Output& out, const std::vector<std::string>& args) {
    if (args.size() != 2) {
        usage(out);
        return S_OK;
    }

    ULONG64 length = 0;
    if (!parseCount(args[1], length)) {
        out.error("invalid pattern length: " + args[1] + "\n");
        return S_OK;
    }

    const ULONG64 maxLength = configGetNumber("pattern.max_length", 8192);
    if (length > maxLength) {
        out.error("pattern length exceeds pattern.max_length\n");
        return S_OK;
    }

    out.heading("Cyclic Pattern");
    out.line(cyclicPattern(length));
    return S_OK;
}

HRESULT offsetPattern(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() < 2 || args.size() > 3) {
        usage(out);
        return S_OK;
    }

    ULONG64 maxLength = configGetNumber("pattern.max_length", 8192);
    if (args.size() == 3 && !parseLengthToken(args[2], maxLength)) {
        usage(out);
        return S_OK;
    }

    const std::string haystack = cyclicPattern(maxLength);
    const auto needle = needleBytes(session, args[1]);
    const auto found = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
    if (found == haystack.end()) {
        out.warning("pattern not found within L" + formatHex(maxLength) + "\n");
        return S_OK;
    }

    out.heading("Cyclic Pattern Offset");
    out.field("value", args[1]);
    out.field("offset", "0x" + formatHex(static_cast<ULONG64>(found - haystack.begin())) + " (" + std::to_string(found - haystack.begin()) + ")");
    return S_OK;
}

}

HRESULT runPattern(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty() || args[0] == "help" || args[0] == "-h" || args[0] == "/?") {
        usage(out);
        return S_OK;
    }

    if (args[0] == "create") {
        return createPattern(out, args);
    }
    if (args[0] == "search" || args[0] == "offset") {
        return offsetPattern(session, out, args);
    }

    usage(out);
    return S_OK;
}

}
