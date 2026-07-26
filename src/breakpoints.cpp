#include "breakpoints.hpp"

#include <cstdlib>
#include <map>
#include <mutex>

namespace wef {

namespace {

std::map<std::string, ULONG>& namedBreakpoints() {
    static std::map<std::string, ULONG> values;
    return values;
}

std::mutex& breakpointMutex() {
    static std::mutex mutex;
    return mutex;
}

void usage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.name_break <name> [address]");
    out.line("  !wef.name_break add <name> <address>");
    out.line("  !wef.name_break list");
    out.line("  !wef.name_break delete <name|id>");
}

bool evalAddress(DbgSession& session, std::string_view text, ULONG64& value) {
    return session.evaluate(text, value) || parseNumber(text, value);
}

bool currentInstructionPointer(DbgSession& session, ULONG64& value) {
    return session.readRegister("rip", value) || session.readRegister("eip", value);
}

bool parseId(std::string_view text, ULONG& value) {
    const std::string copy(text);
    const int base = copy.starts_with("0x") || copy.starts_with("0X") ? 16 : 10;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(copy.c_str(), &end, base);
    if (end == nullptr || end == copy.c_str() || *end != '\0') {
        return false;
    }
    value = static_cast<ULONG>(parsed);
    return true;
}

HRESULT addBreakpointImpl(DbgSession& session, const Output& out, std::string_view name, ULONG64 address) {
    const TargetInfo target = session.targetInfo();
    if (!target.userMode || !target.live) {
        out.error("name-break requires a live user-mode target\n");
        return S_OK;
    }

    std::lock_guard<std::mutex> lock(breakpointMutex());
    if (namedBreakpoints().contains(std::string(name))) {
        out.error("a breakpoint named " + std::string(name) + " already exists\n");
        return S_OK;
    }

    IDebugBreakpoint* breakpoint = nullptr;
    HRESULT hr = session.control()->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &breakpoint);
    if (FAILED(hr) || breakpoint == nullptr) {
        out.error("failed to create breakpoint: " + formatHResult(hr) + "\n");
        return S_OK;
    }

    hr = breakpoint->SetOffset(address);
    if (SUCCEEDED(hr)) {
        hr = breakpoint->AddFlags(DEBUG_BREAKPOINT_ENABLED);
    }
    ULONG id = DEBUG_ANY_ID;
    if (SUCCEEDED(hr)) {
        hr = breakpoint->GetId(&id);
    }
    if (FAILED(hr)) {
        session.control()->RemoveBreakpoint(breakpoint);
        breakpoint->Release();
        out.error("failed to configure breakpoint: " + formatHResult(hr) + "\n");
        return S_OK;
    }

    namedBreakpoints()[std::string(name)] = id;
    breakpoint->Release();
    out.heading("Named Breakpoint");
    out.field("Name", std::string(name));
    out.field("ID", std::to_string(id));
    out.field("Address", formatAddress(address));
    return S_OK;
}

}

HRESULT addNamedBreakpoint(
    DbgSession& session,
    const Output& out,
    std::string_view name,
    ULONG64 address) {
    return addBreakpointImpl(session, out, name, address);
}

HRESULT runNameBreak(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        usage(out);
        return S_OK;
    }

    if (args[0] == "list") {
        if (args.size() != 1) {
            usage(out);
            return S_OK;
        }
        std::lock_guard<std::mutex> lock(breakpointMutex());
        out.heading("Named Breakpoints");
        if (namedBreakpoints().empty()) {
            out.line("  none");
            return S_OK;
        }
        for (const auto& [name, id] : namedBreakpoints()) {
            IDebugBreakpoint* breakpoint = nullptr;
            if (FAILED(session.control()->GetBreakpointById(id, &breakpoint)) || breakpoint == nullptr) {
                out.line("  " + name + "  id=" + std::to_string(id) + "  <unavailable>");
                continue;
            }
            ULONG64 offset = 0;
            ULONG flags = 0;
            breakpoint->GetOffset(&offset);
            breakpoint->GetFlags(&flags);
            breakpoint->Release();
            out.line(
                "  " + name +
                "  id=" + std::to_string(id) +
                "  address=" + formatAddress(offset) +
                ((flags & DEBUG_BREAKPOINT_ENABLED) != 0 ? "  enabled" : "  disabled"));
        }
        return S_OK;
    }

    if (args[0] == "delete") {
        if (args.size() != 2) {
            usage(out);
            return S_OK;
        }
        std::lock_guard<std::mutex> lock(breakpointMutex());
        ULONG id = 0;
        const auto named = namedBreakpoints().find(args[1]);
        if (named != namedBreakpoints().end()) {
            id = named->second;
        } else if (!parseId(args[1], id)) {
            out.error("unknown breakpoint: " + args[1] + "\n");
            return S_OK;
        }

        IDebugBreakpoint* breakpoint = nullptr;
        const HRESULT getHr = session.control()->GetBreakpointById(id, &breakpoint);
        if (FAILED(getHr) || breakpoint == nullptr) {
            out.error("could not locate breakpoint id " + std::to_string(id) + "\n");
            return S_OK;
        }
        const HRESULT removeHr = session.control()->RemoveBreakpoint(breakpoint);
        breakpoint->Release();
        if (FAILED(removeHr)) {
            out.error("failed to remove breakpoint: " + formatHResult(removeHr) + "\n");
            return S_OK;
        }
        for (auto it = namedBreakpoints().begin(); it != namedBreakpoints().end();) {
            if (it->second == id) {
                it = namedBreakpoints().erase(it);
            } else {
                ++it;
            }
        }
        out.line("removed breakpoint id " + std::to_string(id));
        return S_OK;
    }

    std::string name;
    std::string addressExpression;
    if (args[0] == "add") {
        if (args.size() != 3) {
            usage(out);
            return S_OK;
        }
        name = args[1];
        addressExpression = args[2];
    } else {
        if (args.size() > 2) {
            usage(out);
            return S_OK;
        }
        name = args[0];
        if (args.size() == 2) {
            addressExpression = args[1];
        }
    }

    ULONG64 address = 0;
    if (addressExpression.empty()) {
        if (!currentInstructionPointer(session, address)) {
            out.error("instruction pointer is unavailable\n");
            return S_OK;
        }
    } else if (!evalAddress(session, addressExpression, address)) {
        out.error("could not evaluate address: " + addressExpression + "\n");
        return S_OK;
    }
    return addNamedBreakpoint(session, out, name, address);
}

}
