#pragma once

#include <windows.h>
#include <dbgeng.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace wef {

class HResultError final : public std::runtime_error {
public:
    HResultError(HRESULT hr, const char* message);
    HRESULT hr() const noexcept;

private:
    HRESULT hr_;
};

template <typename T>
class ComPtr {
public:
    ComPtr() = default;

    explicit ComPtr(T* ptr) : ptr_(ptr) {
        if (ptr_ != nullptr) {
            ptr_->AddRef();
        }
    }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }

    ~ComPtr() {
        reset();
    }

    T* get() const noexcept {
        return ptr_;
    }

    T** put() noexcept {
        reset();
        return &ptr_;
    }

    T* operator->() const noexcept {
        return ptr_;
    }

    explicit operator bool() const noexcept {
        return ptr_ != nullptr;
    }

    void reset() noexcept {
        if (ptr_ != nullptr) {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_ = nullptr;
};

struct RegisterValue {
    std::string name;
    ULONG64 value = 0;
    bool available = false;
};

struct TargetInfo {
    std::string description;
    bool userMode = false;
    bool kernelMode = false;
    bool dump = false;
    bool live = false;
};

class DbgSession {
public:
    explicit DbgSession(IDebugClient* client);

    IDebugClient* client() const noexcept;
    IDebugControl* control() const noexcept;
    IDebugControl2* control2() const noexcept;
    IDebugRegisters* registers() const noexcept;
    IDebugDataSpaces* dataSpaces() const noexcept;
    IDebugDataSpaces2* dataSpaces2() const noexcept;
    IDebugSymbols* symbols() const noexcept;
    IDebugSystemObjects* systemObjects() const noexcept;
    IDebugAdvanced* advanced() const noexcept;

    ULONG pointerSize() const;
    ULONG effectiveProcessor() const;
    TargetInfo targetInfo() const;
    std::string currentThreadText() const;

    HRESULT readVirtual(ULONG64 address, void* buffer, ULONG size, ULONG* bytesRead) const;
    HRESULT writeVirtual(ULONG64 address, const void* buffer, ULONG size, ULONG* bytesWritten) const;
    bool readPointer(ULONG64 address, ULONG64& value) const;
    bool readRegister(std::string_view name, ULONG64& value) const;
    bool writeRegister(std::string_view name, ULONG64 value) const;
    std::vector<RegisterValue> readCommonRegisters() const;
    bool evaluate(std::string_view expression, ULONG64& value) const;
    bool queryVirtual(ULONG64 address, MEMORY_BASIC_INFORMATION64& info) const;

    std::string resolveSymbol(ULONG64 address) const;
    std::string moduleNameForOffset(ULONG64 address) const;
    std::string disassembleLine(ULONG64 address, ULONG64& next) const;

private:
    template <typename T>
    ComPtr<T> queryInterface() const {
        ComPtr<T> result;
        const HRESULT hr = client_->QueryInterface(__uuidof(T), reinterpret_cast<void**>(result.put()));
        if (FAILED(hr)) {
            throw HResultError(hr, "required DbgEng interface is unavailable");
        }
        return result;
    }

    ComPtr<IDebugClient> client_;
    ComPtr<IDebugControl> control_;
    ComPtr<IDebugControl2> control2_;
    ComPtr<IDebugRegisters> registers_;
    ComPtr<IDebugDataSpaces> dataSpaces_;
    ComPtr<IDebugDataSpaces2> dataSpaces2_;
    ComPtr<IDebugSymbols> symbols_;
    ComPtr<IDebugSystemObjects> systemObjects_;
    ComPtr<IDebugAdvanced> advanced_;
};

std::string formatHResult(HRESULT hr);
std::string formatAddress(ULONG64 value);
std::string formatHex(ULONG64 value, ULONG width = 0);
std::string protectionToString(ULONG protect);
std::string stateToString(ULONG state);
std::string typeToString(ULONG type);

}
