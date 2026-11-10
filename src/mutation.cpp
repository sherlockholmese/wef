#include "mutation.hpp"

#include "instruction.hpp"
#include "config.hpp"

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <string_view>
#include <vector>

namespace wef {

namespace {

struct SavedPatch {
    ULONG process = 0;
    ULONG systemProcess = 0;
    ULONG64 address = 0;
    std::vector<unsigned char> before;
    std::vector<unsigned char> after;
};

std::vector<SavedPatch>& patchStore() {
    static std::vector<SavedPatch> patches;
    return patches;
}

std::mutex& patchMutex() {
    static std::mutex mutex;
    return mutex;
}

bool processIdentity(DbgSession& session, ULONG& process, ULONG& systemProcess) {
    return SUCCEEDED(session.systemObjects()->GetCurrentProcessId(&process)) &&
        SUCCEEDED(session.systemObjects()->GetCurrentProcessSystemId(&systemProcess));
}

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
    std::lock_guard<std::mutex> lock(patchMutex());
    if (bytes.empty()) {
        out.error("no bytes to write\n");
        return false;
    }
    if (bytes.size() > std::min<ULONG64>(configGetNumber("patch.max_size", 1048576), 16 * 1024 * 1024) ||
        address > std::numeric_limits<ULONG64>::max() - bytes.size()) {
        out.error("patch is too large\n");
        return false;
    }

    SavedPatch saved;
    saved.address = address;
    saved.before.resize(bytes.size());
    saved.after = bytes;
    ULONG originalRead = 0;
    if (!processIdentity(session, saved.process, saved.systemProcess) ||
        FAILED(session.readVirtual(address, saved.before.data(), static_cast<ULONG>(bytes.size()), &originalRead)) ||
        originalRead != bytes.size()) {
        out.error("could not save original bytes; patch was not applied\n");
        return false;
    }

    const auto rollback = [&]() {
        ULONG restored = 0;
        const HRESULT restoreHr = session.writeVirtual(address, saved.before.data(), static_cast<ULONG>(saved.before.size()), &restored);
        std::vector<unsigned char> verify(saved.before.size());
        ULONG read = 0;
        const bool ok = SUCCEEDED(restoreHr) && restored == saved.before.size() &&
            SUCCEEDED(session.readVirtual(address, verify.data(), static_cast<ULONG>(verify.size()), &read)) &&
            read == verify.size() && verify == saved.before;
        if (ok) {
            out.warning("original bytes restored after failed patch\n");
        } else {
            ULONG captured = 0;
            std::vector<unsigned char> actual(saved.after.size());
            if (SUCCEEDED(session.readVirtual(address, actual.data(), static_cast<ULONG>(actual.size()), &captured)) && captured == actual.size()) {
                saved.after = std::move(actual);
            }
            if (patchStore().size() >= 128) {
                patchStore().erase(patchStore().begin());
            }
            patchStore().push_back(saved);
            out.error("rollback failed; inspect target memory and patch history before continuing\n");
        }
    };

    ULONG written = 0;
    const HRESULT hr = session.writeVirtual(address, bytes.data(), static_cast<ULONG>(bytes.size()), &written);
    if (FAILED(hr) || static_cast<size_t>(written) != bytes.size()) {
        out.error(
            "write failed at " + formatAddress(address) + ": " + formatHResult(hr) +
            " (" + std::to_string(written) + "/" + std::to_string(bytes.size()) + " bytes)\n");
        rollback();
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
        rollback();
        return false;
    }
    if (patchStore().size() >= 128) {
        out.warning("patch history full; oldest saved patch discarded\n");
        patchStore().erase(patchStore().begin());
    }
    patchStore().push_back(std::move(saved));
    return true;
}

HRESULT patchHistory(DbgSession& session, const Output& out, bool revert, bool all) {
    std::lock_guard<std::mutex> lock(patchMutex());
    ULONG process = 0;
    ULONG systemProcess = 0;
    if (!processIdentity(session, process, systemProcess)) {
        out.error("process identity unavailable\n");
        return S_OK;
    }
    auto& patches = patchStore();
    size_t matched = 0;
    for (size_t i = patches.size(); i > 0; --i) {
        auto& patch = patches[i - 1];
        if (patch.process != process || patch.systemProcess != systemProcess) {
            continue;
        }
        ++matched;
        if (!revert) {
            out.line(formatAddress(patch.address) + "  " + std::to_string(patch.before.size()) + " bytes (newest first)");
            continue;
        }
        std::vector<unsigned char> current(patch.after.size());
        ULONG read = 0;
        if (FAILED(session.readVirtual(patch.address, current.data(), static_cast<ULONG>(current.size()), &read)) ||
            read != current.size() || current != patch.after) {
            out.error("saved patch differs from current memory at " + formatAddress(patch.address) + "; revert stopped\n");
            return S_OK;
        }
        ULONG written = 0;
        const HRESULT hr = session.writeVirtual(patch.address, patch.before.data(), static_cast<ULONG>(patch.before.size()), &written);
        read = 0;
        if (FAILED(hr) || written != patch.before.size() ||
            FAILED(session.readVirtual(patch.address, current.data(), static_cast<ULONG>(current.size()), &read)) ||
            read != current.size() || current != patch.before) {
            out.error("patch revert failed at " + formatAddress(patch.address) + "\n");
            return S_OK;
        }
        out.line("Restored " + std::to_string(patch.before.size()) + " bytes at " + formatAddress(patch.address));
        patches.erase(patches.begin() + static_cast<std::ptrdiff_t>(i - 1));
        if (!all) {
            break;
        }
    }
    if (matched == 0) {
        out.line("No saved patches for the current process.");
    }
    return S_OK;
}

void patchUsage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.patch byte|word|dword|qword <addr> <value>");
    out.line("  !wef.patch string <addr> <text> [-z]");
    out.line("  !wef.patch hex <addr> <hex-bytes>");
    out.line("  !wef.patch list|revert [all]          (patch/nop/stub history)");
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

bool flagMask(std::string_view name, ULONG64& mask) {
    struct Flag {
        const char* name;
        ULONG64 mask;
    };
    static constexpr std::array<Flag, 16> flags = {{
        {"CF", 1ULL << 0},
        {"PF", 1ULL << 2},
        {"AF", 1ULL << 4},
        {"ZF", 1ULL << 6},
        {"SF", 1ULL << 7},
        {"TF", 1ULL << 8},
        {"IF", 1ULL << 9},
        {"DF", 1ULL << 10},
        {"OF", 1ULL << 11},
        {"NT", 1ULL << 14},
        {"RF", 1ULL << 16},
        {"VM", 1ULL << 17},
        {"AC", 1ULL << 18},
        {"VIF", 1ULL << 19},
        {"VIP", 1ULL << 20},
        {"ID", 1ULL << 21},
    }};

    std::string upper(name);
    for (char& ch : upper) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    for (const auto& flag : flags) {
        if (upper == flag.name) {
            mask = flag.mask;
            return true;
        }
    }
    return false;
}

}

HRESULT runPatch(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!args.empty() && (args[0] == "list" || args[0] == "revert")) {
        const bool revert = args[0] == "revert";
        if (args.size() > 2 || (args.size() == 2 && (!revert || args[1] != "all"))) {
            patchUsage(out);
            return S_OK;
        }
        if (revert && !requireLiveUserTarget(session, out, "patch revert")) {
            return S_OK;
        }
        return patchHistory(session, out, revert, args.size() == 2);
    }
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
        if (width < 8 && (value >> (width * 8)) != 0) {
            out.error("value does not fit the selected patch width\n");
            return S_OK;
        }
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
    const ULONG machine = session.effectiveProcessor();
    if (machine != IMAGE_FILE_MACHINE_AMD64 && machine != IMAGE_FILE_MACHINE_I386) {
        out.error("nop requires an x86/x64 target\n");
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
    bool instructionCount = false;
    bool gotAddress = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--n" || args[i] == "-n" || args[i] == "--b" || args[i] == "-b") {
            if (i + 1 >= args.size() || !parseDecimalCount(args[++i], byteCount)) {
                nopUsage(out);
                return S_OK;
            }
            explicitCount = true;
            instructionCount = args[i - 1] == "--n" || args[i - 1] == "-n";
            continue;
        }

        ULONG64 parsed = 0;
        if (parseLengthToken(args[i], parsed)) {
            byteCount = parsed;
            explicitCount = true;
            instructionCount = false;
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

    if (!explicitCount || instructionCount) {
        const ULONG64 count = explicitCount ? byteCount : 1;
        if (count == 0 || count > 65536) {
            out.error("instruction count must be between 1 and 65536\n");
            return S_OK;
        }
        byteCount = 0;
        for (ULONG64 i = 0; i < count; ++i) {
            DecodedInstruction instruction;
            if (session.control()->GetInterrupt() == S_OK || !decodeInstruction(session, address + byteCount, instruction)) {
                out.error("could not determine instruction size at " + formatAddress(address + byteCount) + "\n");
                return S_OK;
            }
            byteCount += instruction.length;
        }
    }
    if (byteCount == 0 || byteCount > std::min<ULONG64>(configGetNumber("patch.max_size", 1048576), 16 * 1024 * 1024)) {
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

HRESULT runStub(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    ULONG64 address = 0;
    ULONG64 value = 0;
    if (args.empty() || args.size() > 2 || !evalAddress(session, args[0], address) ||
        (args.size() == 2 && !evalAddress(session, args[1], value))) {
        out.line("usage: !wef.stub <function-entry> [integer-return-value] (x64, default return: 0)");
        return S_OK;
    }
    if (!requireLiveUserTarget(session, out, "stub")) {
        return S_OK;
    }
    if (session.effectiveProcessor() != IMAGE_FILE_MACHINE_AMD64) {
        out.error("stub requires an x64 target\n");
        return S_OK;
    }
    std::vector<unsigned char> bytes = {0x48, 0xb8}; // mov rax, imm64; ret
    const auto immediate = littleEndianBytes(value, 8);
    bytes.insert(bytes.end(), immediate.begin(), immediate.end());
    bytes.push_back(0xc3);
    if (writeBytes(session, out, address, bytes)) {
        out.line("Stubbed " + formatAddress(address) + " to return 0x" + formatHex(value));
        out.line("Use !wef.patch revert to restore the 11 original bytes.");
    }
    return S_OK;
}

HRESULT runExecution(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        return E_INVALIDARG;
    }
    const std::string command = args[0] == "nextcall" ? "pc" : args[0] == "nextret" ? "pt" : "gu";
    if (args.size() != 1) {
        out.line("usage: !wef." + args[0]);
        return S_OK;
    }
    if (!requireLiveUserTarget(session, out, args[0])) {
        return S_OK;
    }
    const HRESULT hr = session.control()->Execute(DEBUG_OUTCTL_ALL_CLIENTS, command.c_str(), DEBUG_EXECUTE_DEFAULT);
    if (FAILED(hr)) {
        out.error(args[0] + " failed: " + formatHResult(hr) + "\n");
    }
    return hr;
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
            if (i + 1 >= args.size() || !parseDecimalCount(args[++i], count) || count == 0 || count > 65536) {
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
        DecodedInstruction instruction;
        if (session.control()->GetInterrupt() == S_OK || !decodeInstruction(session, current, instruction) ||
            current > std::numeric_limits<ULONG64>::max() - instruction.length) {
            out.error("could not determine instruction size at " + formatAddress(current) + "\n");
            return S_OK;
        }
        current += instruction.length;
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

HRESULT runEditFlags(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.empty()) {
        out.line("usage: !wef.edit_flags <[+|-|~]CF> [[+|-|~]ZF ...]");
        return S_OK;
    }
    if (!requireLiveUserTarget(session, out, "edit-flags")) {
        return S_OK;
    }

    ULONG64 value = 0;
    if (!session.readRegister("efl", value)) {
        out.error("flags register is unavailable\n");
        return S_OK;
    }
    const ULONG64 original = value;

    for (const auto& arg : args) {
        char operation = '~';
        std::string_view name = arg;
        if (!arg.empty() && (arg[0] == '+' || arg[0] == '-' || arg[0] == '~')) {
            operation = arg[0];
            name = std::string_view(arg).substr(1);
        }

        ULONG64 mask = 0;
        if (!flagMask(name, mask)) {
            out.error("unknown flag: " + std::string(name) + "\n");
            return S_OK;
        }
        if (operation == '+') {
            value |= mask;
        } else if (operation == '-') {
            value &= ~mask;
        } else {
            value ^= mask;
        }
    }

    if (!session.writeRegister("efl", value)) {
        out.error("failed to update flags register\n");
        return S_OK;
    }
    ULONG64 verification = 0;
    if (!session.readRegister("efl", verification) || verification != value) {
        out.error("flags update verification failed\n");
        return S_OK;
    }
    out.heading("Edit Flags");
    out.field("Before", "0x" + formatHex(original));
    out.field("After", "0x" + formatHex(value));
    return S_OK;
}

HRESULT runStepover(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!args.empty()) {
        out.line("usage: !wef.stepover");
        return S_OK;
    }
    if (!requireLiveUserTarget(session, out, "stepover")) {
        return S_OK;
    }
    const HRESULT hr = session.control()->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "p", DEBUG_EXECUTE_DEFAULT);
    if (FAILED(hr)) {
        out.error("step over failed: " + formatHResult(hr) + "\n");
    }
    return S_OK;
}

HRESULT runEntryBreak(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (!args.empty()) {
        out.line("usage: !wef.entry_break");
        return S_OK;
    }
    if (!requireLiveUserTarget(session, out, "entry-break")) {
        return S_OK;
    }

    ULONG64 entry = 0;
    if (!session.evaluate("@$exentry", entry)) {
        out.error("could not resolve the executable entry point\n");
        return S_OK;
    }
    const std::string command = "bp /1 " + formatAddress(entry);
    const HRESULT hr = session.control()->Execute(DEBUG_OUTCTL_ALL_CLIENTS, command.c_str(), DEBUG_EXECUTE_DEFAULT);
    if (FAILED(hr)) {
        out.error("failed to set entry breakpoint: " + formatHResult(hr) + "\n");
        return S_OK;
    }
    out.heading("Entry Breakpoint");
    out.field("Address", formatAddress(entry));
    return S_OK;
}

}
