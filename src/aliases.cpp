#include "aliases.hpp"

#include <array>

namespace wef {

namespace {

struct AliasMapping {
    const char* alias;
    const char* target;
};

constexpr std::array<AliasMapping, 29> kAliases = {{
    {"ctx", "!wef.ctx"},
    {"context", "!wef.context"},
    {"registers", "!wef.registers"},
    {"telescope", "!wef.telescope"},
    {"dereference", "!wef.dereference"},
    {"hexdump", "!wef.hexdump"},
    {"search-pattern", "!wef.search_pattern"},
    {"print-format", "!wef.print_format"},
    {"xor-memory", "!wef.xor_memory"},
    {"vmmap", "!wef.vmmap"},
    {"xinfo", "!wef.xinfo"},
    {"xfiles", "!wef.xfiles"},
    {"arch", "!wef.arch"},
    {"wef-eval", "!wef.eval"},
    {"process-status", "!wef.process_status"},
    {"pattern", "!wef.pattern"},
    {"patch", "!wef.patch"},
    {"nop", "!wef.nop"},
    {"skipi", "!wef.skipi"},
    {"edit-flags", "!wef.edit_flags"},
    {"stepover", "!wef.stepover"},
    {"entry-break", "!wef.entry_break"},
    {"name-break", "!wef.name_break"},
    {"checksec", "!wef.checksec"},
    {"wef-heap", "!wef.heaps"},
    {"chunk", "!wef.chunk"},
    {"vis", "!vis"},
    {"ttd-events", "!wef.ttd"},
    {"wef-config", "!wef.config"},
}};

}

HRESULT runInstall(DbgSession& session, const Output& out, const std::vector<std::string>&) {
    bool ok = true;
    for (const auto& mapping : kAliases) {
        const HRESULT hr = session.control2()->SetTextReplacement(mapping.alias, mapping.target);
        if (FAILED(hr)) {
            ok = false;
            out.error(std::string("failed to install alias ") + mapping.alias + " -> " + mapping.target + ": " + formatHResult(hr) + "\n");
        } else {
            out.line(std::string("installed: ") + mapping.alias + " -> " + mapping.target);
        }
    }

    if (ok) {
        out.line("WEF aliases installed.");
    }
    return S_OK;
}

HRESULT runUninstall(DbgSession& session, const Output& out, const std::vector<std::string>&) {
    bool ok = true;
    for (const auto& mapping : kAliases) {
        const HRESULT hr = session.control2()->SetTextReplacement(mapping.alias, nullptr);
        if (FAILED(hr)) {
            ok = false;
            out.error(std::string("failed to remove alias ") + mapping.alias + ": " + formatHResult(hr) + "\n");
        } else {
            out.line(std::string("removed: ") + mapping.alias);
        }
    }

    if (ok) {
        out.line("WEF aliases removed.");
    }
    return S_OK;
}

HRESULT runAliases(DbgSession&, const Output& out, const std::vector<std::string>&) {
    out.heading("WEF alias mappings:");
    for (const auto& mapping : kAliases) {
        out.line(std::string("  ") + mapping.alias + " -> " + mapping.target);
    }
    out.warning("installed-state query is not implemented in this milestone; run WinDbg's al command to inspect current aliases.\n");
    return S_OK;
}

}
