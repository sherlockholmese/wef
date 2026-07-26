#include "command_router.hpp"

#include "aliases.hpp"
#include "config.hpp"
#include "context.hpp"
#include "heap.hpp"
#include "memory.hpp"
#include "modules.hpp"
#include "pattern.hpp"
#include "pe_security.hpp"
#include "ttd.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace wef {

namespace {

HRESULT runHelp(DbgSession&, const Output& out, const std::vector<std::string>&) {
    out.heading("WEF WinDbg Extension");
    out.blank();
    out.heading("Canonical commands:");
    out.line("  !wef");
    out.line("  !wef.install");
    out.line("  !wef.uninstall");
    out.line("  !wef.aliases");
    out.line("  !wef.ctx [-full] [-regs] [-stack L<count>] [-code L<count>]");
    out.line("  !wef.registers");
    out.line("  !wef.telescope [<addr>] [L<count>]");
    out.line("  !wef.dereference [<addr>] [L<count>]");
    out.line("  !wef.hexdump <addr> [L<size>] [-force]");
    out.line("  !wef.search_pattern <text|addr|hex:bytes> [start] [L<size>]");
    out.line("  !wef.vmmap [-x|-w|-image|-private|-contains <addr>] [L<count>]");
    out.line("  !wef.pattern create|search|offset ...");
    out.line("  !wef.checksec [module]");
    out.line("  !wef.heaps [L<count>|heap-address]    (alias: wef-heap)");
    out.line("  !wef.heaps flags|segments|chunks|chunk|find|validate ...");
    out.line("  !wef.chunk <addr>");
    out.line("  !wef.vis [L<count>|heap-address]");
    out.line("  !vis [L<count>|heap-address]");
    out.line("  !wef.ttd calls|exceptions|memory|allocs|timeline|gui ...");
    out.line("  !wef.config get [key]");
    out.line("  !wef.config set <key> <value>");
    out.blank();
    out.dmlLine(
        "Quick actions: [ctx] [vmmap] [heaps] [vis] [ttd gui] [config]",
        "Quick actions: " +
            dmlCommandLink("ctx", "!wef.ctx") + " " +
            dmlCommandLink("vmmap", "!wef.vmmap") + " " +
            dmlCommandLink("heaps", "!wef.heaps") + " " +
            dmlCommandLink("vis", "!wef.vis") + " " +
            dmlCommandLink("ttd gui", "!wef.ttd gui") + " " +
            dmlCommandLink("config", "!wef.config get"));
    out.line("Run !wef.install to add opt-in bare aliases, including ctx, registers, dereference, telescope, vmmap, pattern, checksec, and heap helpers.");
    return S_OK;
}

bool startsWithLengthPrefix(std::string_view token) {
    return !token.empty() && (token[0] == 'L' || token[0] == 'l');
}

}

HRESULT executeCommand(IDebugClient* client, PCSTR args, CommandHandler handler) {
    try {
        DbgSession session(client);
        Output out(session.control());
        return handler(session, out, splitArgs(args));
    } catch (const HResultError& error) {
        if (client != nullptr) {
            IDebugControl* rawControl = nullptr;
            if (SUCCEEDED(client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(&rawControl))) && rawControl != nullptr) {
                Output out(rawControl);
                out.error(std::string(error.what()) + ": " + formatHResult(error.hr()) + "\n");
                rawControl->Release();
            }
        }
        return error.hr();
    } catch (const std::exception& error) {
        if (client != nullptr) {
            IDebugControl* rawControl = nullptr;
            if (SUCCEEDED(client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(&rawControl))) && rawControl != nullptr) {
                Output out(rawControl);
                out.error(std::string("internal error: ") + error.what() + "\n");
                rawControl->Release();
            }
        }
        return S_OK;
    }
}

std::vector<std::string> splitArgs(PCSTR args) {
    std::vector<std::string> result;
    if (args == nullptr) {
        return result;
    }

    std::string current;
    char quote = '\0';
    bool tokenStarted = false;
    for (size_t i = 0; args[i] != '\0'; ++i) {
        const char ch = args[i];
        if (quote != '\0') {
            if (ch == quote) {
                quote = '\0';
                continue;
            }
            if (ch == '\\' && args[i + 1] != '\0' && (args[i + 1] == quote || args[i + 1] == '\\')) {
                current.push_back(args[++i]);
                continue;
            }
            current.push_back(ch);
            continue;
        }

        if (ch == '"' || ch == '\'') {
            quote = ch;
            tokenStarted = true;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            if (tokenStarted) {
                result.push_back(current);
                current.clear();
                tokenStarted = false;
            }
            continue;
        }

        current.push_back(ch);
        tokenStarted = true;
    }

    if (tokenStarted) {
        result.push_back(current);
    }
    return result;
}

bool parseNumber(std::string_view text, ULONG64& value) {
    std::string cleaned;
    cleaned.reserve(text.size());
    for (const char ch : text) {
        if (ch != '`') {
            cleaned.push_back(ch);
        }
    }
    if (cleaned.empty()) {
        return false;
    }

    int base = 16;
    if (cleaned.size() > 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
        base = 16;
    }

    char* end = nullptr;
    value = std::strtoull(cleaned.c_str(), &end, base);
    return end != nullptr && *end == '\0';
}

bool parseLengthToken(std::string_view token, ULONG64& value) {
    if (!startsWithLengthPrefix(token)) {
        return false;
    }
    return parseNumber(token.substr(1), value);
}

std::string joinArgs(const std::vector<std::string>& args, size_t start, size_t end) {
    if (start >= args.size() || start >= end) {
        return {};
    }

    end = std::min(end, args.size());
    std::string joined;
    for (size_t i = start; i < end; ++i) {
        if (!joined.empty()) {
            joined += ' ';
        }
        joined += args[i];
    }
    return joined;
}

namespace commands {

HRESULT WefHelp(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runHelp);
}

HRESULT Install(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runInstall);
}

HRESULT Uninstall(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runUninstall);
}

HRESULT Aliases(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runAliases);
}

HRESULT Ctx(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runCtx);
}

HRESULT Registers(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runRegisters);
}

HRESULT Telescope(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runTelescope);
}

HRESULT Dereference(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runTelescope);
}

HRESULT Hexdump(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runHexdump);
}

HRESULT SearchPattern(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runSearchPattern);
}

HRESULT Vmmap(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runVmmap);
}

HRESULT Checksec(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runChecksec);
}

HRESULT Pattern(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runPattern);
}

HRESULT Heaps(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runHeap);
}

HRESULT Vis(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runHeapVis);
}

HRESULT Ttd(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runTtd);
}

HRESULT Config(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runConfig);
}

}

}
