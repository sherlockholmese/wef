#include <windows.h>

#include <cstdio>

extern "C" {
volatile unsigned long long wef_patch_target = 0x1122334455667788ULL;
unsigned char wef_nop_target[8] = {0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc};
unsigned char wef_branch_target[8] = {0x74, 0x02, 0x90, 0x90, 0xc3, 0x90, 0x90, 0x90};
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
    wef_breakpoint_fixture();
    return 0;
}
