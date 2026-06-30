// =============================================================================
//  OffsetScanner.cpp  –  Implementation of generic scanners
// =============================================================================
#include "OffsetScanner.hpp"
#include <regex>

// ------------------------------------------------------------------
//  FindFloatOffset
// ------------------------------------------------------------------
uint32_t FindFloatOffset(HANDLE hProc, uintptr_t obj, float target, uint32_t maxOffset, uint32_t align) {
    SIZE_T got;
    for (uint32_t off = 0; off <= maxOffset; off += align) {
        float val = 0.0f;
        if (!SafeRead(hProc, obj + off, &val, sizeof(val), got) || got != sizeof(val))
            continue;
        if (val == target)
            return off;
    }
    return 0;
}

// ------------------------------------------------------------------
//  FindIntOffset
// ------------------------------------------------------------------
uint32_t FindIntOffset(HANDLE hProc, uintptr_t obj, int target, uint32_t maxOffset, uint32_t align) {
    SIZE_T got;
    for (uint32_t off = 0; off <= maxOffset; off += align) {
        int val = 0;
        if (!SafeRead(hProc, obj + off, &val, sizeof(val), got) || got != sizeof(val))
            continue;
        if (val == target)
            return off;
    }
    return 0;
}

// ------------------------------------------------------------------
//  FindBoolOffset
// ------------------------------------------------------------------
uint32_t FindBoolOffset(HANDLE hProc, uintptr_t obj, bool target, uint32_t maxOffset, uint32_t align) {
    SIZE_T got;
    uint8_t targetByte = target ? 1 : 0;
    for (uint32_t off = 0; off <= maxOffset; off += align) {
        uint8_t val = 0;
        if (!SafeRead(hProc, obj + off, &val, sizeof(val), got) || got != sizeof(val))
            continue;
        if (val == targetByte)
            return off;
    }
    return 0;
}

// ------------------------------------------------------------------
//  FindStringOffset
// ------------------------------------------------------------------
uint32_t FindStringOffset(HANDLE hProc, uintptr_t obj, const std::string& target, uint32_t maxOffset) {
    SIZE_T got;
    for (uint32_t off = 0; off <= maxOffset; off += 8) {
        uintptr_t ptr = 0;
        if (!SafeRead(hProc, obj + off, &ptr, sizeof(ptr), got) || got != sizeof(ptr))
            continue;
        if (!IsPointerValid(hProc, ptr))
            continue;
        auto str = ReadRobloxString(hProc, ptr);
        if (str && *str == target)
            return off;
    }
    return 0;
}

// ------------------------------------------------------------------
//  FindStringRegexOffset
// ------------------------------------------------------------------
uint32_t FindStringRegexOffset(HANDLE hProc, uintptr_t obj, const std::regex& pattern, uint32_t maxOffset) {
    SIZE_T got;
    for (uint32_t off = 0; off <= maxOffset; off += 8) {
        uintptr_t ptr = 0;
        if (!SafeRead(hProc, obj + off, &ptr, sizeof(ptr), got) || got != sizeof(ptr))
            continue;
        if (!IsPointerValid(hProc, ptr))
            continue;
        auto str = ReadRobloxString(hProc, ptr);
        if (str && std::regex_match(*str, pattern))
            return off;
    }
    return 0;
}

// ------------------------------------------------------------------
//  FindObjectOffset
// ------------------------------------------------------------------
uint32_t FindObjectOffset(HANDLE hProc, uintptr_t obj, const PEInfo& pe, uintptr_t targetVtable, uint32_t maxOffset) {
    SIZE_T got;
    for (uint32_t off = 0; off <= maxOffset; off += 8) {
        uintptr_t ptr = 0;
        if (!SafeRead(hProc, obj + off, &ptr, sizeof(ptr), got) || got != sizeof(ptr))
            continue;
        if (!IsPointerValid(hProc, ptr))
            continue;
        // Check vtable of the pointed object
        uintptr_t vtable = 0;
        if (!SafeRead(hProc, ptr, &vtable, sizeof(vtable), got) || got != sizeof(vtable))
            continue;
        if (vtable == targetVtable)
            return off;
    }
    return 0;
}

uint64_t FindInt64Offset(HANDLE hProc, uintptr_t obj, uint64_t target, uint32_t maxOffset, uint32_t align) {
    SIZE_T got;
    for (uint32_t off = 0; off <= maxOffset; off += align) {
        uint64_t val = 0;
        if (!SafeRead(hProc, obj + off, &val, sizeof(val), got) || got != sizeof(val))
            continue;
        if (val == target)
            return off;
    }
    return 0;
}