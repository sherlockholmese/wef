#include <windows.h>

#include <cstdio>
#include <cstring>

extern "C" {
volatile unsigned long long wef_patch_target = 0x1122334455667788ULL;
unsigned char wef_nop_target[8] = {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc};
unsigned char wef_branch_target[8] = {0x74, 0x02, 0x90, 0x90, 0xc3, 0x90, 0x90, 0x90};
unsigned char wef_instruction_target[16] = {0x48, 0x89, 0xc0, 0x66, 0x90, 0xc3};
unsigned char wef_stub_target[16] = {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc};
wchar_t wef_wide_target[] = L"wef wide marker";
const void* wef_pointer_slots[3] = {};
__declspec(align(16)) unsigned char wef_unaligned_pointer[16] = {};
unsigned char* wef_scan_region = nullptr;
unsigned char* wef_gadget_region = nullptr;
HANDLE wef_backend_heap = nullptr;
HANDLE wef_lfh_heap = nullptr;
void* wef_busy_block = nullptr;
void* wef_free_block = nullptr;
void* wef_anchor_block = nullptr;
void* wef_added_block = nullptr;
void* wef_lfh_blocks[128] = {};
}

bool initialize_parity_fixture() {
    wef_pointer_slots[0] = const_cast<const unsigned long long*>(&wef_patch_target);
    wef_pointer_slots[1] = wef_wide_target;
    wef_pointer_slots[2] = wef_instruction_target;
    std::memcpy(wef_unaligned_pointer + 1, &wef_pointer_slots[0], sizeof(void*));

    wef_scan_region = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    wef_gadget_region = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (wef_scan_region == nullptr || wef_gadget_region == nullptr) {
        return false;
    }
    // A pointer and gadget straddle the scanner's 4096-byte window boundary.
    std::memcpy(wef_scan_region + 4093, &wef_pointer_slots[0], sizeof(void*));
    DWORD oldProtection = 0;
    if (!VirtualProtect(wef_scan_region + 0x2000, 0x1000, PAGE_NOACCESS, &oldProtection)) {
        return false;
    }
    std::memset(wef_gadget_region, 0xcc, 0x2000);
    wef_gadget_region[4095] = 0x59; // pop rcx; ret
    wef_gadget_region[4096] = 0xc3;
    FlushInstructionCache(GetCurrentProcess(), wef_gadget_region, 0x2000);

    // HEAP_NO_SERIALIZE keeps this heap on the NT backend (LFH is incompatible).
    wef_backend_heap = HeapCreate(HEAP_NO_SERIALIZE, 0x10000, 0);
    wef_lfh_heap = HeapCreate(0, 0, 0);
    if (wef_backend_heap == nullptr || wef_lfh_heap == nullptr) {
        return false;
    }
    wef_busy_block = HeapAlloc(wef_backend_heap, 0, 0x600);
    wef_free_block = HeapAlloc(wef_backend_heap, 0, 0x500);
    wef_anchor_block = HeapAlloc(wef_backend_heap, 0, 0x100);
    if (wef_busy_block == nullptr || wef_free_block == nullptr || wef_anchor_block == nullptr) {
        return false;
    }
    std::memset(wef_busy_block, 0x41, 0x600);
    if (!HeapFree(wef_backend_heap, 0, wef_free_block)) {
        return false;
    }
    ULONG mode = 2;
    HeapSetInformation(wef_lfh_heap, HeapCompatibilityInformation, &mode, sizeof(mode));
    for (auto& block : wef_lfh_blocks) {
        block = HeapAlloc(wef_lfh_heap, 0, 0x40);
        if (block == nullptr) {
            return false;
        }
    }
    for (size_t i = 0; i < 128; i += 2) {
        HeapFree(wef_lfh_heap, 0, wef_lfh_blocks[i]);
        wef_lfh_blocks[i] = nullptr;
    }
    std::printf("parity targets: stub=%p unaligned=%p wide=%p slots=%p scan=%p gadgets=%p\n",
        static_cast<void*>(wef_stub_target), static_cast<void*>(wef_unaligned_pointer),
        static_cast<void*>(wef_wide_target), static_cast<const void*>(wef_pointer_slots),
        static_cast<void*>(wef_scan_region), static_cast<void*>(wef_gadget_region));
    return true;
}

__declspec(noinline) void wef_breakpoint_fixture() {
    volatile unsigned long long marker = 0x1122334455667788ULL;
    const char ascii[] = "wef stable ascii string";
    const wchar_t wide[] = L"wef stable wide string";
    const void* pointer0 = const_cast<const unsigned long long*>(&marker);
    const void* pointer1 = ascii;
    const void* pointer2 = wide;

    std::printf(
        "marker=%p ascii=%p wide=%p pointers=%p,%p,%p patch=%p nop=%p branch=%p\n",
        const_cast<const unsigned long long*>(&marker),
        static_cast<const void*>(ascii),
        static_cast<const void*>(wide),
        pointer0,
        pointer1,
        pointer2,
        const_cast<const unsigned long long*>(&wef_patch_target),
        static_cast<void*>(wef_nop_target),
        static_cast<void*>(wef_branch_target));
    DebugBreak();
}

int main() {
    if (!initialize_parity_fixture()) {
        std::puts("WEF fixture initialization failed");
        return 1;
    }
    wef_breakpoint_fixture();
    // Resume once to give the snapshot/diff test observable allocator changes.
    wef_added_block = HeapAlloc(wef_backend_heap, 0, 0x900);
    if (wef_added_block == nullptr || !HeapFree(wef_backend_heap, 0, wef_busy_block)) {
        return 1;
    }
    std::puts("WEF fixture second stop");
    DebugBreak();
    HeapDestroy(wef_lfh_heap);
    HeapDestroy(wef_backend_heap);
    VirtualFree(wef_scan_region, 0, MEM_RELEASE);
    VirtualFree(wef_gadget_region, 0, MEM_RELEASE);
    return 0;
}
