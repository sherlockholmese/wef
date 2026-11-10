#include "pattern.hpp"

#include "config.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <limits>

namespace wef {
namespace {

constexpr ULONG64 kHardLimit = 16 * 1024 * 1024;
constexpr ULONG64 kLegacyCapacity = 26 * 26 * 10 * 3;

struct PatternOptions {
    ULONG64 length = 0;
    ULONG width = 8;
    std::string alphabet = "abcdefghijklmnopqrstuvwxyz";
    std::string value;
    bool legacy = false;
};

void usage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.pattern create [-n <width>] [-a <alphabet>] [--legacy] <length>");
    out.line("  !wef.pattern search|offset [-n <width>] [-a <alphabet>] [--legacy] <value|str:text> [L<max-length>|--max-length <length>]");
    out.line("  !wef.cyclic [-n <width>] [-a <alphabet>] [<length>|-l <value>|-o <value>]");
    out.line("Counts are decimal or 0x-prefixed; L lengths use WinDbg hexadecimal notation.");
}

ULONG64 capacity(const PatternOptions& options) {
    if (options.legacy) {
        return kLegacyCapacity;
    }
    ULONG64 result = 1;
    for (ULONG i = 0; i < options.width; ++i) {
        if (result > std::numeric_limits<ULONG64>::max() / options.alphabet.size()) {
            return std::numeric_limits<ULONG64>::max();
        }
        result *= options.alphabet.size();
    }
    return result;
}

std::string makePattern(const PatternOptions& options) {
    std::string pattern;
    pattern.reserve(static_cast<size_t>(options.length));
    if (options.legacy) {
        for (char a = 'A'; a <= 'Z'; ++a) {
            for (char b = 'a'; b <= 'z'; ++b) {
                for (char c = '0'; c <= '9'; ++c) {
                    for (const char ch : {a, b, c}) {
                        if (pattern.size() == options.length) {
                            return pattern;
                        }
                        pattern.push_back(ch);
                    }
                }
            }
        }
        return pattern;
    }

    // Emit only the prefix of the FKM De Bruijn sequence; never allocate 26^8.
    std::vector<size_t> state(options.width + 1, 0);
    std::function<void(ULONG, ULONG)> emit = [&](ULONG t, ULONG period) {
        if (pattern.size() >= options.length) {
            return;
        }
        if (t > options.width) {
            if (options.width % period == 0) {
                for (ULONG i = 1; i <= period && pattern.size() < options.length; ++i) {
                    pattern.push_back(options.alphabet[state[i]]);
                }
            }
            return;
        }
        state[t] = state[t - period];
        emit(t + 1, period);
        for (size_t j = state[t - period] + 1; j < options.alphabet.size() && pattern.size() < options.length; ++j) {
            state[t] = j;
            emit(t + 1, t);
        }
    };
    emit(1, 1);
    return pattern;
}

bool parseOptions(DbgSession& session, const Output& out, const std::vector<std::string>& args,
                  bool search, PatternOptions& options) {
    options.width = session.pointerSize();
    options.length = search ? configGetNumber("pattern.max_length", 8192) : 0;
    bool positional = false;
    for (size_t i = 1; i < args.size(); ++i) {
        const auto& arg = args[i];
        if ((arg == "-n" || arg == "--length") && i + 1 < args.size()) {
            ULONG64 width = 0;
            if (!parseDecimalCount(args[++i], width) || width == 0 || width > 8) {
                out.error("pattern width must be between 1 and 8\n");
                return false;
            }
            options.width = static_cast<ULONG>(width);
        } else if ((arg == "-a" || arg == "--alphabet") && i + 1 < args.size()) {
            options.alphabet = args[++i];
        } else if (arg == "--legacy" || arg == "--metasploit") {
            options.legacy = true;
        } else if (search && arg == "--max-length" && i + 1 < args.size()) {
            if (!parseDecimalCount(args[++i], options.length)) {
                return false;
            }
        } else if (search && positional && parseLengthToken(arg, options.length)) {
            continue;
        } else if (!arg.empty() && arg[0] == '-') {
            return false;
        } else if (!positional) {
            positional = true;
            if (search) {
                options.value = arg;
            } else if (!parseDecimalCount(arg, options.length)) {
                return false;
            }
        } else {
            return false;
        }
    }

    std::array<bool, 256> seen = {};
    for (const unsigned char ch : options.alphabet) {
        if (seen[ch]) {
            out.error("pattern alphabet must contain unique characters\n");
            return false;
        }
        seen[ch] = true;
    }
    if (options.alphabet.empty()) {
        out.error("pattern alphabet cannot be empty\n");
        return false;
    }
    if (!positional || options.length == 0 || options.length > kHardLimit ||
        options.length > configGetNumber("pattern.max_length", 8192)) {
        out.error("pattern length must be positive and within pattern.max_length (hard limit: 16 MiB)\n");
        return false;
    }
    if (!search && options.length > capacity(options)) {
        out.error("requested length exceeds the unique pattern capacity\n");
        return false;
    }
    options.length = std::min(options.length, capacity(options));
    return true;
}

std::string lookupBytes(DbgSession& session, const PatternOptions& options) {
    if (options.value.starts_with("str:")) {
        return options.value.substr(4);
    }
    ULONG64 value = 0;
    const auto& token = options.value;
    const bool expression = token.starts_with("0x") || token.starts_with("0X") || token.starts_with("@") ||
        token.find('!') != std::string::npos || token.find('`') != std::string::npos ||
        (!token.empty() && token[0] >= '0' && token[0] <= '9');
    if (session.readRegister(token, value) || (expression && (session.evaluate(token, value) || parseNumber(token, value)))) {
        const ULONG width = options.legacy ? (value <= 0xffffffffULL ? 4 : 8) : options.width;
        if (width < 8 && (value >> (width * 8)) != 0) {
            return {}; // Do not silently truncate a wider crash value.
        }
        std::string bytes(width, '\0');
        for (ULONG i = 0; i < width; ++i) {
            bytes[i] = static_cast<char>((value >> (i * 8)) & 0xff);
        }
        return bytes;
    }
    return token;
}

}

HRESULT runPattern(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty() || (args[0] != "create" && args[0] != "search" && args[0] != "offset")) {
        usage(out);
        return S_OK;
    }
    const bool search = args[0] != "create";
    PatternOptions options;
    if (!parseOptions(session, out, args, search, options)) {
        usage(out);
        return S_OK;
    }
    const std::string pattern = makePattern(options);
    out.heading(search ? "Cyclic Pattern Offset" : "Cyclic Pattern");
    out.field("Format", options.legacy ? "Metasploit (legacy)" : "De Bruijn, n=" + std::to_string(options.width));
    if (!search) {
        out.line(pattern);
        return S_OK;
    }

    std::string needle = lookupBytes(session, options);
    if (needle.empty() || (!options.legacy && needle.size() > options.width)) {
        out.error("lookup value must contain 1..n bytes; use str: for literal text or select a wider -n\n");
        return S_OK;
    }
    if (!options.legacy && needle.size() < options.width) {
        out.warning("lookup is shorter than n; the first match may be ambiguous\n");
    }
    bool found = false;
    for (const char* endian : {"little-endian", "big-endian"}) {
        const size_t offset = pattern.find(needle);
        if (offset != std::string::npos) {
            found = true;
            out.field(endian, "offset 0x" + formatHex(offset) + " (" + std::to_string(offset) + ")");
        }
        std::reverse(needle.begin(), needle.end());
    }
    if (!found) {
        out.warning("pattern not found within L" + formatHex(options.length) + "\n");
    }
    return S_OK;
}

HRESULT runCyclic(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    std::vector<std::string> translated = {"create"};
    bool positional = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "-l" || args[i] == "-o" || args[i] == "--lookup") {
            if (i + 1 == args.size() || positional) {
                usage(out);
                return S_OK;
            }
            translated[0] = "search";
            translated.push_back(args[++i]);
            positional = true;
        } else if (args[i] == "-n" || args[i] == "--length" || args[i] == "-a" ||
                   args[i] == "--alphabet" || args[i] == "--max-length") {
            if (i + 1 == args.size()) {
                usage(out);
                return S_OK;
            }
            translated.push_back(args[i]);
            translated.push_back(args[++i]);
        } else {
            translated.push_back(args[i]);
            if (args[i].empty() || args[i][0] != '-') {
                positional = true;
            }
        }
    }
    if (!positional) {
        translated.push_back("100");
    }
    return runPattern(session, out, translated);
}

}
