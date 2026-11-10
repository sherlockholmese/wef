#include "command_router.hpp"

#include "aliases.hpp"
#include "breakpoints.hpp"
#include "config.hpp"
#include "context.hpp"
#include "exploit.hpp"
#include "heap.hpp"
#include "memory.hpp"
#include "modules.hpp"
#include "mutation.hpp"
#include "pattern.hpp"
#include "pe_security.hpp"
#include "stack.hpp"
#include "ttd.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
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
    out.line("  !wef.ctx auto <on|off|status>       (also: !wef.context)");
    out.line("  !wef.registers");
    out.line("  !wef.telescope [<addr>] [L<count>]");
    out.line("  !wef.dereference [<addr>] [L<count>]");
    out.line("  !wef.hexdump <addr> [L<size>] [-force]");
    out.line("  !wef.search_pattern <text|addr|hex:bytes> [start] [L<size>]");
    out.line("  !wef.search [-t <type>|-1|-2|-4|-8|-p] <value> [start] [L<size>] [-x|-e|-w]");
    out.line("  !wef.scan <source-mapping> <target-mapping> [-unaligned] [-max <count>]");
    out.line("  !wef.rop [\"pop rcx; ret\"] [-module <name>|-range <start:end>] [-depth <count>]");
    out.line("  !wef.nearpc [address] [L<count>] [-before <count>]");
    out.line("  !wef.distance <from> <to>");
    out.line("  !wef.dumpargs [L<count>] [--entry]");
    out.line("  !wef.hex2ptr <hex-bytes>");
    out.line("  !wef.print_format [--lang <format>] [-l <length>] <address>");
    out.line("  !wef.xor_memory display|patch <address> <length> <key>");
    out.line("  !wef.memory watch|unwatch|list|reset ...");
    out.line("  !wef.vmmap [-x|-w|-image|-private|-contains <addr>] [L<count>]");
    out.line("  !wef.xinfo <address> [address ...]");
    out.line("  !wef.xfiles [module [section]]");
    out.line("  !wef.arch get|list|set <x86|x64|arm64>");
    out.line("  !wef.eval <expression> [expression]");
    out.line("  !wef.process_status");
    out.line("  !wef.pie info|breakpoint|list|delete ...");
    out.line("  !wef.pe_info [module]");
    out.line("  !wef.iat [module] [filter]            (also: !wef.got)");
    out.line("  !wef.canary [module]");
    out.line("  !wef.pattern create|search|offset ...");
    out.line("  !wef.cyclic [-n <width>] [-a <alphabet>] [<length>|-l <value>]");
    out.line("  !wef.patch byte|word|dword|qword|string|hex ...");
    out.line("  !wef.patch list|revert [all]");
    out.line("  !wef.stub <function-entry> [integer-return-value]");
    out.line("  !wef.nop [addr] [L<byte-count>|--n <count>|--b <count>]");
    out.line("  !wef.skipi [addr] [-n <instruction-count>]");
    out.line("  !wef.edit_flags <[+|-|~]FLAG> [...]");
    out.line("  !wef.stepover");
    out.line("  !wef.nextcall | !wef.nextret | !wef.stepout");
    out.line("  !wef.entry_break");
    out.line("  !wef.name_break <name> [address]|list|delete ...");
    out.line("  !wef.checksec [module]");
    out.line("  !wef.heaps [L<count>|heap-address]    (alias: wef-heap)");
    out.line("  !wef.heaps flags|segments|chunks|chunk|find|validate ...");
    out.line("  !wef.heaps stats [heap] | xref <addr>  (statistics, cross references)");
    out.line("  !wef.heaps snapshot|diff|snapshot-clear ...");
    out.line("  !wef.heaps native [summary|chunks|stats|chunk|validate|freelist|lfh|leaks|pageheap] [addr]");
    out.line("  !wef.heaps lfh|freelist|triage|pageheap [addr]");
    out.line("  !wef.chunk <addr>");
    out.line("  !wef.vis [L<count>|heap-address]");
    out.line("  !vis [L<count>|heap-address]");
    out.line("  !wef.stack [<addr>] [L<count>]        (annotated stack, also: !wef.stack cookie)");
    out.line("  !wef.canary scan [L<max-scan-bytes>]  (find cookies on the stack)");
    out.line("  !wef.registers [-plain|-reset|<reg>]  (annotated registers, change tracking)");
    out.line("  !wef.colors                           (DML color self-test)");
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
    if (cleaned.empty() || cleaned[0] == '-' || cleaned[0] == '+' ||
        std::isspace(static_cast<unsigned char>(cleaned[0])) != 0) {
        return false;
    }

    int base = 16;
    if (cleaned.size() > 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
        base = 16;
    }

    char* end = nullptr;
    errno = 0;
    value = std::strtoull(cleaned.c_str(), &end, base);
    return errno != ERANGE && end != cleaned.c_str() && *end == '\0';
}

bool parseDecimalCount(std::string_view text, ULONG64& value) {
    if (text.empty() || text[0] == '-' || text[0] == '+' ||
        std::isspace(static_cast<unsigned char>(text[0])) != 0) {
        return false;
    }
    const std::string copy(text);
    char* end = nullptr;
    errno = 0;
    value = std::strtoull(copy.c_str(), &end, copy.starts_with("0x") || copy.starts_with("0X") ? 16 : 10);
    return errno != ERANGE && end != copy.c_str() && *end == '\0';
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

HRESULT Search(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runSearch);
}

HRESULT Cyclic(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runCyclic);
}

HRESULT Scan(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runScan);
}

HRESULT Rop(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runRop);
}

HRESULT Nearpc(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runNearpc);
}

HRESULT Distance(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runDistance);
}

HRESULT Dumpargs(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runDumpargs);
}

HRESULT Hex2ptr(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runHex2ptr);
}

HRESULT Stub(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runStub);
}

HRESULT Nextcall(IDebugClient* client, PCSTR args) {
    const std::string fullArgs = std::string("nextcall ") + (args != nullptr ? args : "");
    return executeCommand(client, fullArgs.c_str(), runExecution);
}

HRESULT Nextret(IDebugClient* client, PCSTR args) {
    const std::string fullArgs = std::string("nextret ") + (args != nullptr ? args : "");
    return executeCommand(client, fullArgs.c_str(), runExecution);
}

HRESULT Stepout(IDebugClient* client, PCSTR args) {
    const std::string fullArgs = std::string("stepout ") + (args != nullptr ? args : "");
    return executeCommand(client, fullArgs.c_str(), runExecution);
}

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

HRESULT PrintFormat(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runPrintFormat);
}

HRESULT XorMemory(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runXorMemory);
}

HRESULT Memory(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runMemory);
}

HRESULT Vmmap(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runVmmap);
}

HRESULT Xinfo(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runXinfo);
}

HRESULT Xfiles(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runXfiles);
}

HRESULT Arch(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runArch);
}

HRESULT Eval(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runEval);
}

HRESULT ProcessStatus(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runProcessStatus);
}

HRESULT Pie(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runPie);
}

HRESULT Checksec(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runChecksec);
}

HRESULT PeInfo(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runPeInfo);
}

HRESULT Iat(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runIat);
}

HRESULT Canary(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runCanary);
}

HRESULT Pattern(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runPattern);
}

HRESULT Patch(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runPatch);
}

HRESULT Nop(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runNop);
}

HRESULT Skipi(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runSkipi);
}

HRESULT EditFlags(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runEditFlags);
}

HRESULT Stepover(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runStepover);
}

HRESULT EntryBreak(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runEntryBreak);
}

HRESULT NameBreak(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runNameBreak);
}

HRESULT Heaps(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runHeap);
}

HRESULT Vis(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runHeapVis);
}

HRESULT Stack(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runStack);
}

HRESULT Colors(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runColors);
}

HRESULT Ttd(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runTtd);
}

HRESULT Config(IDebugClient* client, PCSTR args) {
    return executeCommand(client, args, runConfig);
}

}

}
