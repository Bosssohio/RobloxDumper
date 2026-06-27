// =============================================================================
//  Script.cpp  –  Official target‑size method, hash reused
// =============================================================================
#include "Script.hpp"
#include "Instance.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <iomanip>
#include <sstream>

// ------------------------------------------------------------------
//  Helpers (unchanged)
// ------------------------------------------------------------------
static bool IsPointerValid(HANDLE hProc, uintptr_t ptr) {
    if (ptr < 0x10000 || ptr > 0x00007FFFFFFFFFFF) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProc, (LPCVOID)ptr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    return true;
}

static bool HasValidVTable(HANDLE hProc, uintptr_t objectPtr, const PEInfo& pe) {
    if (!IsPointerValid(hProc, objectPtr)) return false;
    uintptr_t vtable = 0;
    SIZE_T got;
    if (!SafeRead(hProc, objectPtr, &vtable, sizeof(vtable), got) || got != sizeof(vtable))
        return false;
    for (const auto& sec : pe.sections) {
        uintptr_t secStart = pe.moduleBase + sec.rva;
        uintptr_t secEnd = secStart + sec.virtualSize;
        if (vtable >= secStart && vtable < secEnd)
            return true;
    }
    return false;
}

static std::optional<std::string> ReadStringSafe(HANDLE hProc, uintptr_t ptr) {
    if (!IsPointerValid(hProc, ptr)) return std::nullopt;
    return ReadRobloxString(hProc, ptr);
}

static std::optional<PEInfo> GetPEInfo(HANDLE hProc, uintptr_t moduleBase) {
    static std::optional<PEInfo> cached;
    static uintptr_t cachedModuleBase = 0;
    if (cached.has_value() && cachedModuleBase == moduleBase)
        return cached;
    auto pe = ParsePE(hProc, moduleBase);
    if (pe) {
        cached = pe;
        cachedModuleBase = moduleBase;
    }
    return cached;
}

static uintptr_t GetModuleBase(HANDLE hProc) {
    HMODULE hMod;
    DWORD cb;
    if (!EnumProcessModules(hProc, &hMod, sizeof(hMod), &cb)) return 0;
    MODULEINFO mi;
    if (!GetModuleInformation(hProc, hMod, &mi, sizeof(mi))) return 0;
    return (uintptr_t)mi.lpBaseOfDll;
}

//#define VERBOSE_LOG(msg) LOG_INFO(msg)

// ------------------------------------------------------------------
//  Find a direct child by name
// ------------------------------------------------------------------
static uintptr_t FindFirstChildByName(
    HANDLE hProc,
    uintptr_t parentPtr,
    const InstanceOffsets& offsets,
    const PEInfo& pe,
    const std::string& name)
{
    if (!parentPtr || !offsets.ChildrenStart || !offsets.ChildrenEnd || !offsets.Name)
        return 0;

    SIZE_T got;
    uintptr_t startPtr = 0;
    if (!SafeRead(hProc, parentPtr + offsets.ChildrenStart, &startPtr, sizeof(startPtr), got) || got != sizeof(startPtr) || !startPtr)
        return 0;
    uintptr_t firstChild = 0;
    if (!SafeRead(hProc, startPtr, &firstChild, sizeof(firstChild), got) || got != sizeof(firstChild) || !firstChild)
        return 0;

    uintptr_t endPtrA = 0, endPtrB = 0;
    bool okA = false, okB = false;
    size_t countA = 0, countB = 0;

    if (SafeRead(hProc, firstChild + offsets.ChildrenEnd, &endPtrA, sizeof(endPtrA), got) && got == sizeof(endPtrA) && endPtrA > firstChild) {
        if (IsPointerValid(hProc, endPtrA)) {
            countA = (endPtrA - firstChild) / 0x10;
            if (countA > 0 && countA <= 500) okA = true;
        }
    }
    if (SafeRead(hProc, startPtr + offsets.ChildrenEnd, &endPtrB, sizeof(endPtrB), got) && got == sizeof(endPtrB) && endPtrB > firstChild) {
        if (IsPointerValid(hProc, endPtrB)) {
            countB = (endPtrB - firstChild) / 0x10;
            if (countB > 0 && countB <= 500) okB = true;
        }
    }

    uintptr_t endPtr = 0;
    size_t count = 0;
    if (okA && okB) {
        if (countB <= countA) { endPtr = endPtrB; count = countB; }
        else { endPtr = endPtrA; count = countA; }
    }
    else if (okA) {
        endPtr = endPtrA; count = countA;
    }
    else if (okB) {
        endPtr = endPtrB; count = countB;
    }
    else {
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        uintptr_t child = 0;
        if (!SafeRead(hProc, firstChild + i * 0x10, &child, sizeof(child), got) || got != sizeof(child) || !child)
            continue;
        if (!HasValidVTable(hProc, child, pe))
            continue;

        uintptr_t namePtr = 0;
        if (!SafeRead(hProc, child + offsets.Name, &namePtr, sizeof(namePtr), got) || got != sizeof(namePtr) || !namePtr)
            continue;
        auto str = ReadStringSafe(hProc, namePtr);
        if (str && *str == name) {
            return child;
        }
    }
    return 0;
}

// ------------------------------------------------------------------
//  Official find_offset_in_pointer
// ------------------------------------------------------------------
static std::optional<std::pair<uint32_t, uint32_t>> find_offset_in_pointer(
    HANDLE hProc,
    uintptr_t objectPtr,
    uint32_t targetValue,
    uint32_t maxOffset,
    uint32_t maxInnerOffset,
    uint32_t pointerStride = 8,
    uint32_t valueStride = 4)
{
    SIZE_T got;
    for (uint32_t ptrOff = 0; ptrOff < maxOffset; ptrOff += pointerStride) {
        uintptr_t ptr = 0;
        if (!SafeRead(hProc, objectPtr + ptrOff, &ptr, sizeof(ptr), got) || got != sizeof(ptr))
            continue;
        if (!IsPointerValid(hProc, ptr))
            continue;
        for (uint32_t valOff = 0; valOff < maxInnerOffset; valOff += valueStride) {
            uint32_t val = 0;
            if (!SafeRead(hProc, ptr + valOff, &val, sizeof(val), got) || got != sizeof(val))
                continue;
            if (val == targetValue) {
                return std::make_pair(ptrOff, valOff);
            }
        }
    }
    return std::nullopt;
}

// ------------------------------------------------------------------
//  Discover bytecode offsets using target size
// ------------------------------------------------------------------
static bool DiscoverBytecodeOffsetsForType(
    HANDLE hProc,
    uintptr_t scriptPtr,
    const std::string& typeName,
    uint32_t targetSize,
    uint32_t& outPointerOffset,
    uint32_t& outSizeOffset)
{
    LOG_INFO("Scanning " + typeName + " for bytecode offsets (target size: " + std::to_string(targetSize) + ")...");

    auto result = find_offset_in_pointer(hProc, scriptPtr, targetSize, 0x300, 0x100);
    if (!result) {
        LOG_ERR("Could not find " + typeName + " bytecode offsets (target size " + std::to_string(targetSize) + ")");
        return false;
    }

    outPointerOffset = result->first;
    outSizeOffset = result->second;

    LOG_OK("Found " + typeName + " bytecode: pointer offset 0x" + ToHex(outPointerOffset) +
        ", size offset 0x" + ToHex(outSizeOffset) + " (size=" + std::to_string(targetSize) + ")");
    return true;
}

// ------------------------------------------------------------------
//  Discover hash offset – uses same offset for both types
// ------------------------------------------------------------------
static bool DiscoverHashOffsetForType(
    HANDLE hProc,
    uintptr_t scriptPtr,
    const std::string& typeName,
    uint32_t& outHashOffset,
    uint32_t bytecodeOffset = 0)
{
    const uint32_t TARGET_HASH = 1680946276;
    const uint32_t MAX_OFF = 0x300;
    SIZE_T got;

    LOG_INFO("Scanning " + typeName + " for hash offset...");

    for (uint32_t ptrOff = 0x20; ptrOff < MAX_OFF; ptrOff += 8) {
        if (bytecodeOffset != 0 && ptrOff == bytecodeOffset) continue;
        uintptr_t ptr = 0;
        if (!SafeRead(hProc, scriptPtr + ptrOff, &ptr, sizeof(ptr), got) || got != sizeof(ptr)) continue;
        if (!IsPointerValid(hProc, ptr)) continue;
        // Try inner offsets (hash is often at offset 0)
        uint32_t val = 0;
        if (!SafeRead(hProc, ptr, &val, sizeof(val), got) || got != sizeof(val)) continue;
        if (val == TARGET_HASH) {
            outHashOffset = ptrOff;
            LOG_OK("Found " + typeName + " hash offset = 0x" + ToHex(ptrOff) + " (hash=0x" + ToHex(val) + ")");
            return true;
        }
    }
    LOG_WARN("Could not find " + typeName + " hash offset");
    return false;
}

// ------------------------------------------------------------------
//  Main entry point
// ------------------------------------------------------------------
ScriptOffsets FindScriptOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const InstanceOffsets& instanceOffsets)
{
    ScriptOffsets res;
    res.Valid = false;

    if (!dataModelPtr || !instanceOffsets.Valid) {
        LOG_ERR("DataModel or Instance offsets not available");
        return res;
    }

    uintptr_t moduleBase = GetModuleBase(hProc);
    if (!moduleBase) {
        LOG_ERR("Could not get module base");
        return res;
    }
    auto pe = GetPEInfo(hProc, moduleBase);
    if (!pe) {
        LOG_ERR("Could not parse PE");
        return res;
    }

    LOG_INFO("Searching for ModuleScript and LocalScript in Workspace and ReplicatedStorage...");

    uintptr_t workspacePtr = instanceOffsets.WorkspacePtr;
    if (!workspacePtr) {
        LOG_WARN("Workspace pointer not available");
    }

    uintptr_t replicatedStorage = FindFirstChildByName(hProc, dataModelPtr, instanceOffsets, *pe, "ReplicatedStorage");
    if (!replicatedStorage) {
        LOG_WARN("ReplicatedStorage not found");
    }

    uintptr_t moduleScript = 0;
    uintptr_t localScript = 0;

    if (replicatedStorage) {
        moduleScript = FindFirstChildByName(hProc, replicatedStorage, instanceOffsets, *pe, "ModuleScript");
        localScript = FindFirstChildByName(hProc, replicatedStorage, instanceOffsets, *pe, "LocalScript");

        if (!moduleScript) {
            uintptr_t scriptsFolder = FindFirstChildByName(hProc, replicatedStorage, instanceOffsets, *pe, "Scripts");
            if (scriptsFolder) {
                moduleScript = FindFirstChildByName(hProc, scriptsFolder, instanceOffsets, *pe, "ModuleScript");
                localScript = FindFirstChildByName(hProc, scriptsFolder, instanceOffsets, *pe, "LocalScript");
            }
        }
    }

    if (!moduleScript && workspacePtr) {
        moduleScript = FindFirstChildByName(hProc, workspacePtr, instanceOffsets, *pe, "ModuleScript");
        localScript = FindFirstChildByName(hProc, workspacePtr, instanceOffsets, *pe, "LocalScript");
    }

    if (moduleScript) {
        LOG_INFO("ModuleScript found at 0x" + ToHex(moduleScript));
    }
    else {
        LOG_WARN("ModuleScript not found (add a test ModuleScript to ReplicatedStorage)");
    }

    if (localScript) {
        LOG_INFO("LocalScript found at 0x" + ToHex(localScript));
    }
    else {
        LOG_WARN("LocalScript not found (add a test LocalScript to ReplicatedStorage)");
    }

    if (!moduleScript && !localScript) {
        LOG_ERR("Could not find any ModuleScript or LocalScript for testing");
        return res;
    }

    // ---- ModuleScript ----
    if (moduleScript) {
        uint32_t bytecodePtrOff = 0, sizeOff = 0;
        if (DiscoverBytecodeOffsetsForType(hProc, moduleScript, "ModuleScript", 61, bytecodePtrOff, sizeOff)) {
            res.ModuleScriptBytecode = bytecodePtrOff;
            res.ByteCodeSize = sizeOff;
            uint32_t hashOff = 0;
            if (DiscoverHashOffsetForType(hProc, moduleScript, "ModuleScript", hashOff, bytecodePtrOff)) {
                res.ModuleScriptHash = hashOff;
            }
        }
    }

    // ---- LocalScript ----
    if (localScript) {
        uint32_t bytecodePtrOff = 0, sizeOff = 0;
        if (DiscoverBytecodeOffsetsForType(hProc, localScript, "LocalScript", 86, bytecodePtrOff, sizeOff)) {
            res.LocalScriptBytecode = bytecodePtrOff;
            if (res.ByteCodeSize == 0) {
                res.ByteCodeSize = sizeOff;
            }
            // Reuse ModuleScript hash offset if available
            if (res.ModuleScriptHash != 0) {
                // Verify it works for LocalScript
                uintptr_t hashPtr = 0;
                uint32_t hashVal = 0;
                SIZE_T got;
                if (SafeRead(hProc, localScript + res.ModuleScriptHash, &hashPtr, sizeof(hashPtr), got) && got == sizeof(hashPtr) && IsPointerValid(hProc, hashPtr)) {
                    if (SafeRead(hProc, hashPtr, &hashVal, sizeof(hashVal), got) && got == sizeof(hashVal) && hashVal == 1680946276) {
                        res.LocalScriptHash = res.ModuleScriptHash;
                        LOG_OK("Reused ModuleScript hash offset for LocalScript: 0x" + ToHex(res.LocalScriptHash));
                    }
                }
            }
            // If reuse failed, scan for LocalScript hash
            if (res.LocalScriptHash == 0) {
                uint32_t hashOff = 0;
                if (DiscoverHashOffsetForType(hProc, localScript, "LocalScript", hashOff, bytecodePtrOff)) {
                    res.LocalScriptHash = hashOff;
                }
            }
        }
    }

    res.ByteCodePointer = 0x10;
    res.Valid = (res.ModuleScriptBytecode != 0 || res.LocalScriptBytecode != 0) && res.ByteCodeSize != 0;
    if (res.Valid) {
        LOG_OK("Script offsets discovered successfully");
    }
    else {
        LOG_ERR("Failed to discover sufficient script offsets");
    }

    return res;
}