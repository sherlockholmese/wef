#include "config.hpp"

#include <map>
#include <mutex>

namespace wef {

namespace {

std::map<std::string, std::string>& store() {
    static std::map<std::string, std::string> values = {
        {"ctx.stack.count", "20"},
        {"ctx.code.lines", "8"},
        {"ctx.auto", "false"},
        {"ctx.regs.show_flags", "true"},
        {"dereference.depth", "3"},
        {"heap.max_count", "80"},
        {"heap.chunk.max_search_chunks", "4096"},
        {"heap.find.max_chunk_read", "65536"},
        {"heap.find.max_hits", "80"},
        {"heap.vis.max_chunks", "160"},
        {"heap.vis.peek_bytes", "32"},
        {"heap.vis.detail_count", "8"},
        {"heap.vis.max_segments", "16"},
        {"heap.vis.width", "80"},
        {"heap.stats.top_count", "5"},
        {"iat.max_entries", "4096"},
        {"memory.watch.max_count", "16"},
        {"memory.watch.max_size", "4096"},
        {"output.use_dml", "true"},
        {"pattern.max_length", "8192"},
        {"patch.max_size", "1048576"},
        {"print.max_length", "4096"},
        {"regs.annotate", "true"},
        {"regs.show_diff", "true"},
        {"search.max_hits", "80"},
        {"scan.max_bytes", "268435456"},
        {"stack.count", "20"},
        {"stack.cookie.max_scan", "1048576"},
        {"telescope.count", "20"},
        {"ttd.max_events", "200"},
        {"xor.max_length", "65536"},
        {"hexdump.size", "100"},
    };
    return values;
}

std::mutex& storeMutex() {
    static std::mutex mutex;
    return mutex;
}

void usage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.config get [key]");
    out.line("  !wef.config set <key> <value>");
}

}

std::optional<std::string> configGet(std::string_view key) {
    std::lock_guard<std::mutex> lock(storeMutex());
    const auto found = store().find(std::string(key));
    if (found == store().end()) {
        return std::nullopt;
    }
    return found->second;
}

ULONG64 configGetNumber(std::string_view key, ULONG64 fallback) {
    const auto value = configGet(key);
    if (!value) {
        return fallback;
    }

    try {
        size_t used = 0;
        const int base = value->starts_with("0x") || value->starts_with("0X") ? 16 : 10;
        const ULONG64 parsed = std::stoull(*value, &used, base);
        return used == value->size() ? parsed : fallback;
    } catch (...) {
        return fallback;
    }
}

bool configGetBool(std::string_view key, bool fallback) {
    const auto value = configGet(key);
    if (!value) {
        return fallback;
    }

    if (*value == "true" || *value == "1" || *value == "yes" || *value == "on") {
        return true;
    }
    if (*value == "false" || *value == "0" || *value == "no" || *value == "off") {
        return false;
    }
    return fallback;
}

bool configSet(std::string_view key, std::string_view value) {
    std::lock_guard<std::mutex> lock(storeMutex());
    const auto found = store().find(std::string(key));
    if (found == store().end()) {
        return false;
    }
    found->second = std::string(value);
    if (key == "output.use_dml") {
        setOutputUseDml(value == "true" || value == "1" || value == "yes" || value == "on");
    }
    return true;
}

std::vector<std::pair<std::string, std::string>> configItems() {
    std::lock_guard<std::mutex> lock(storeMutex());
    std::vector<std::pair<std::string, std::string>> items;
    for (const auto& item : store()) {
        items.push_back(item);
    }
    return items;
}

HRESULT runConfig(DbgSession&, const Output& out, const std::vector<std::string>& args) {
    if (args.empty() || args[0] == "get") {
        if (args.size() <= 1) {
            for (const auto& [key, value] : configItems()) {
                out.line("  " + key + " = " + value);
            }
            return S_OK;
        }

        if (args.size() == 2) {
            const auto value = configGet(args[1]);
            if (!value) {
                out.error("unknown config key: " + args[1] + "\n");
                return S_OK;
            }
            out.line(args[1] + " = " + *value);
            return S_OK;
        }

        usage(out);
        return S_OK;
    }

    if (args[0] == "set") {
        if (args.size() != 3) {
            usage(out);
            return S_OK;
        }
        if (!configSet(args[1], args[2])) {
            out.error("unknown config key: " + args[1] + "\n");
            return S_OK;
        }
        out.line(args[1] + " = " + args[2]);
        return S_OK;
    }

    usage(out);
    return S_OK;
}

}
