#include "dbg_session.hpp"

#include <cstdio>
#include <iomanip>
#include <initializer_list>
#include <sstream>

namespace wef {

HResultError::HResultError(HRESULT hr, const char* message) : std::runtime_error(message), hr_(hr) {}

HRESULT HResultError::hr() const noexcept {
    return hr_;
}

DbgSession::DbgSession(IDebugClient* client) : client_(client) {
    if (client == nullptr) {
        throw HResultError(E_POINTER, "IDebugClient is null");
    }

    control_ = queryInterface<IDebugControl>();
    control2_ = queryInterface<IDebugControl2>();
    registers_ = queryInterface<IDebugRegisters>();
    dataSpaces_ = queryInterface<IDebugDataSpaces>();
    dataSpaces2_ = queryInterface<IDebugDataSpaces2>();
    symbols_ = queryInterface<IDebugSymbols>();
    systemObjects_ = queryInterface<IDebugSystemObjects>();
    advanced_ = queryInterface<IDebugAdvanced>();
}

IDebugClient* DbgSession::client() const noexcept {
    return client_.get();
}

IDebugControl* DbgSession::control() const noexcept {
    return control_.get();
}

IDebugControl2* DbgSession::control2() const noexcept {
    return control2_.get();
}

IDebugRegisters* DbgSession::registers() const noexcept {
    return registers_.get();
}

IDebugDataSpaces* DbgSession::dataSpaces() const noexcept {
    return dataSpaces_.get();
}

IDebugDataSpaces2* DbgSession::dataSpaces2() const noexcept {
    return dataSpaces2_.get();
}

IDebugSymbols* DbgSession::symbols() const noexcept {
    return symbols_.get();
}

IDebugSystemObjects* DbgSession::systemObjects() const noexcept {
    return systemObjects_.get();
}

IDebugAdvanced* DbgSession::advanced() const noexcept {
    return advanced_.get();
}

ULONG DbgSession::pointerSize() const {
    const HRESULT hr = control_->IsPointer64Bit();
    if (hr == S_OK) {
        return 8;
    }
    return 4;
}

ULONG DbgSession::effectiveProcessor() const {
    ULONG type = 0;
    if (FAILED(control_->GetEffectiveProcessorType(&type))) {
        return 0;
    }
    return type;
}

TargetInfo DbgSession::targetInfo() const {
    TargetInfo info;
    ULONG cls = 0;
    ULONG qual = 0;
    const HRESULT hr = control_->GetDebuggeeType(&cls, &qual);
    if (FAILED(hr)) {
        info.description = "unavailable (" + formatHResult(hr) + ")";
        return info;
    }

    info.userMode = cls == DEBUG_CLASS_USER_WINDOWS;
    info.kernelMode = cls == DEBUG_CLASS_KERNEL;
    info.dump =
        qual == DEBUG_USER_WINDOWS_SMALL_DUMP ||
        qual == DEBUG_USER_WINDOWS_DUMP ||
        qual == DEBUG_KERNEL_SMALL_DUMP ||
        qual == DEBUG_KERNEL_DUMP ||
        qual == DEBUG_KERNEL_FULL_DUMP;
    info.live = !info.dump;

    if (info.userMode) {
        info.description = info.dump ? "user-mode dump" : "user-mode live process";
    } else if (info.kernelMode) {
        info.description = info.dump ? "kernel dump" : "kernel target";
    } else {
        info.description = "unsupported target class";
    }

    return info;
}

std::string DbgSession::currentThreadText() const {
    ULONG process = 0;
    ULONG thread = 0;
    const HRESULT phr = systemObjects_->GetCurrentProcessSystemId(&process);
    const HRESULT thr = systemObjects_->GetCurrentThreadSystemId(&thread);
    if (FAILED(phr) || FAILED(thr)) {
        return "unavailable";
    }

    char buffer[64] = {};
    std::snprintf(buffer, sizeof(buffer), "%04lx:%04lx", process, thread);
    return buffer;
}

HRESULT DbgSession::readVirtual(ULONG64 address, void* buffer, ULONG size, ULONG* bytesRead) const {
    ULONG actual = 0;
    const HRESULT hr = dataSpaces_->ReadVirtual(address, buffer, size, &actual);
    if (bytesRead != nullptr) {
        *bytesRead = actual;
    }
    return hr;
}

bool DbgSession::readPointer(ULONG64 address, ULONG64& value) const {
    value = 0;
    ULONG bytesRead = 0;
    const ULONG size = pointerSize();
    const HRESULT hr = readVirtual(address, &value, size, &bytesRead);
    return SUCCEEDED(hr) && bytesRead == size;
}

bool DbgSession::readRegister(std::string_view name, ULONG64& value) const {
    std::string copy(name);
    ULONG index = 0;
    if (FAILED(registers_->GetIndexByName(copy.c_str(), &index))) {
        return false;
    }

    DEBUG_VALUE dbgValue = {};
    if (FAILED(registers_->GetValue(index, &dbgValue))) {
        return false;
    }

    switch (dbgValue.Type) {
    case DEBUG_VALUE_INT8:
        value = dbgValue.I8;
        return true;
    case DEBUG_VALUE_INT16:
        value = dbgValue.I16;
        return true;
    case DEBUG_VALUE_INT32:
        value = dbgValue.I32;
        return true;
    case DEBUG_VALUE_INT64:
        value = dbgValue.I64;
        return true;
    default:
        return false;
    }
}

std::vector<RegisterValue> DbgSession::readCommonRegisters() const {
    std::vector<RegisterValue> values;
    const auto append = [&](std::initializer_list<std::string_view> names) {
        for (const auto name : names) {
            ULONG64 value = 0;
            if (readRegister(name, value)) {
                values.push_back({std::string(name), value, true});
            }
        }
    };

    if (pointerSize() == 8) {
        values.reserve(18);
        append({
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
            "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "efl"
        });
    } else {
        values.reserve(10);
        append({"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip", "efl"});
    }

    return values;
}

bool DbgSession::evaluate(std::string_view expression, ULONG64& value) const {
    const std::string copy(expression);
    DEBUG_VALUE dbgValue = {};
    const HRESULT hr = control_->Evaluate(copy.c_str(), DEBUG_VALUE_INT64, &dbgValue, nullptr);
    if (FAILED(hr)) {
        return false;
    }
    value = dbgValue.I64;
    return true;
}

bool DbgSession::queryVirtual(ULONG64 address, MEMORY_BASIC_INFORMATION64& info) const {
    return SUCCEEDED(dataSpaces2_->QueryVirtual(address, &info));
}

std::string DbgSession::resolveSymbol(ULONG64 address) const {
    char buffer[1024] = {};
    ULONG nameSize = 0;
    ULONG64 displacement = 0;
    const HRESULT hr = symbols_->GetNameByOffset(address, buffer, sizeof(buffer), &nameSize, &displacement);
    if (FAILED(hr) || buffer[0] == '\0') {
        return {};
    }

    std::string result(buffer);
    if (displacement != 0) {
        result += "+0x" + formatHex(displacement);
    }
    return result;
}

std::string DbgSession::moduleNameForOffset(ULONG64 address) const {
    ULONG index = 0;
    ULONG64 base = 0;
    if (FAILED(symbols_->GetModuleByOffset(address, 0, &index, &base))) {
        return {};
    }

    char module[512] = {};
    if (FAILED(symbols_->GetModuleNames(index, base, nullptr, 0, nullptr, module, sizeof(module), nullptr, nullptr, 0, nullptr))) {
        return {};
    }

    return module;
}

std::string DbgSession::disassembleLine(ULONG64 address, ULONG64& next) const {
    char buffer[1024] = {};
    ULONG size = 0;
    const HRESULT hr = control_->Disassemble(address, DEBUG_DISASM_EFFECTIVE_ADDRESS, buffer, sizeof(buffer), &size, &next);
    if (FAILED(hr)) {
        next = address;
        return {};
    }
    return buffer;
}

std::string formatHResult(HRESULT hr) {
    char buffer[32] = {};
    std::snprintf(buffer, sizeof(buffer), "0x%08lx", static_cast<unsigned long>(hr));
    return buffer;
}

std::string formatAddress(ULONG64 value) {
    char buffer[32] = {};
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%08llx`%08llx",
        static_cast<unsigned long long>((value >> 32) & 0xffffffffULL),
        static_cast<unsigned long long>(value & 0xffffffffULL));
    return buffer;
}

std::string formatHex(ULONG64 value, ULONG width) {
    std::ostringstream stream;
    stream << std::hex << std::nouppercase << std::setfill('0');
    if (width != 0) {
        stream << std::setw(width);
    }
    stream << value;
    return stream.str();
}

std::string protectionToString(ULONG protect) {
    const ULONG base = protect & 0xff;
    std::string text;
    switch (base) {
    case PAGE_NOACCESS:
        text = "NOACCESS";
        break;
    case PAGE_READONLY:
        text = "R";
        break;
    case PAGE_READWRITE:
        text = "RW";
        break;
    case PAGE_WRITECOPY:
        text = "WC";
        break;
    case PAGE_EXECUTE:
        text = "X";
        break;
    case PAGE_EXECUTE_READ:
        text = "RX";
        break;
    case PAGE_EXECUTE_READWRITE:
        text = "RWX";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        text = "XWC";
        break;
    default:
        text = "0x" + formatHex(protect);
        break;
    }

    if ((protect & PAGE_GUARD) != 0) {
        text += "|GUARD";
    }
    if ((protect & PAGE_NOCACHE) != 0) {
        text += "|NOCACHE";
    }
    if ((protect & PAGE_WRITECOMBINE) != 0) {
        text += "|WRITECOMBINE";
    }
    return text;
}

std::string stateToString(ULONG state) {
    switch (state) {
    case MEM_COMMIT:
        return "COMMIT";
    case MEM_RESERVE:
        return "RESERVE";
    case MEM_FREE:
        return "FREE";
    default:
        return "0x" + formatHex(state);
    }
}

std::string typeToString(ULONG type) {
    switch (type) {
    case MEM_IMAGE:
        return "IMAGE";
    case MEM_MAPPED:
        return "MAPPED";
    case MEM_PRIVATE:
        return "PRIVATE";
    case 0:
        return "";
    default:
        return "0x" + formatHex(type);
    }
}

}
