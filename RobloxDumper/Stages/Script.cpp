#include "Script.hpp"
#include "Instance.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <iomanip>
#include <sstream>

//used in replicatedstorgae for localscript and modulescript
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

//what da sigma, aaaaaaaaaaaaaaa
static uintptr_t FindFirstChildByClassRecursive(
    HANDLE hProc,
    uintptr_t currentPtr,
    const InstanceOffsets& offsets,
    const PEInfo& pe,
    const std::string& className,
    int depth,
    int& totalNodesVisited) // Removed defaults
{
    const int MAX_DEPTH = 200;
    const int MAX_TOTAL_NODES = 5000;

    if (depth > MAX_DEPTH || !currentPtr || totalNodesVisited > MAX_TOTAL_NODES) {
        return 0;
    }

    if (!HasValidVTable(hProc, currentPtr, pe)) {
        return 0;
    }

    SIZE_T got;

    // dumper is check current object's class name
    uintptr_t classDescPtr = 0;
    if (SafeRead(hProc, currentPtr + offsets.ClassDescriptor, &classDescPtr, sizeof(classDescPtr), got) && got == sizeof(classDescPtr) && classDescPtr) {
        uintptr_t namePtr = 0;
        if (SafeRead(hProc, classDescPtr + offsets.ClassName, &namePtr, sizeof(namePtr), got) && got == sizeof(namePtr) && namePtr) {
            auto str = ReadStringSafe(hProc, namePtr);
            if (str && *str == className) {
                return currentPtr;
            }
        }
    }

    // recurse into children
    if (!offsets.ChildrenStart || !offsets.ChildrenEnd) return 0;
    uintptr_t startPtr = 0;
    if (!SafeRead(hProc, currentPtr + offsets.ChildrenStart, &startPtr, sizeof(startPtr), got) || got != sizeof(startPtr) || !startPtr) return 0;
    uintptr_t firstChild = 0;
    if (!SafeRead(hProc, startPtr, &firstChild, sizeof(firstChild), got) || got != sizeof(firstChild) || !firstChild) return 0;

    if (!IsPointerValid(hProc, firstChild)) return 0;

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
        if (SafeRead(hProc, firstChild + i * 0x10, &child, sizeof(child), got) && got == sizeof(child) && child) {
            if (!IsPointerValid(hProc, child)) continue;
            totalNodesVisited++;
            if (totalNodesVisited > MAX_TOTAL_NODES) {
                return 0;
            }
            uintptr_t found = FindFirstChildByClassRecursive(hProc, child, offsets, pe, className, depth + 1, totalNodesVisited);
            if (found) return found;
        }
    }
    return 0;
}

// we got method reall!L!L!L!L!L!L! 100% legit
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

static bool DiscoverBytecodeOffsetsForType(
    HANDLE hProc,
    uintptr_t scriptPtr,
    const std::string& typeName,
    uint32_t targetSize,
    uint32_t& outPointerOffset,
    uint32_t& outSizeOffset,
    uint32_t maxOffset = 0x600)
{
    LOG_INFO("dumper is scanning " + typeName + " for bytecode offsets (target size: " + std::to_string(targetSize) + ")... for any script object (in game if u pubilshed)");
    auto result = find_offset_in_pointer(hProc, scriptPtr, targetSize, maxOffset, 0x100);
    if (!result) {
        LOG_ERR("could not find " + typeName + " bytecode offsets (target size " + std::to_string(targetSize) + "), did you mean do not remove script object or it is?");
        return false;
    }
    outPointerOffset = result->first;
    outSizeOffset = result->second;
    LOG_OK("founded " + typeName + " bytecode: pointer offset 0x" + ToHex(outPointerOffset) +
        ", size offset 0x" + ToHex(outSizeOffset) + " (size=" + std::to_string(targetSize) + ")");
    return true;
}

static bool DiscoverHashOffsetForType(
    HANDLE hProc,
    uintptr_t scriptPtr,
    const std::string& typeName,
    uint32_t& outHashOffset,
    uint32_t bytecodeOffset = 0)
{
    const uint32_t TARGET_HASH = 1680946276; //found in github
    const uint32_t MAX_OFF = 0x300;
    SIZE_T got;

    LOG_INFO("dumper is scanning " + typeName + " for hash offset...");

    for (uint32_t ptrOff = 0x20; ptrOff < MAX_OFF; ptrOff += 8) {
        if (bytecodeOffset != 0 && ptrOff == bytecodeOffset) continue;
        uintptr_t ptr = 0;
        if (!SafeRead(hProc, scriptPtr + ptrOff, &ptr, sizeof(ptr), got) || got != sizeof(ptr)) continue;
        if (!IsPointerValid(hProc, ptr)) continue;
        uint32_t val = 0;
        if (!SafeRead(hProc, ptr, &val, sizeof(val), got) || got != sizeof(val)) continue;
        if (val == TARGET_HASH) {
            outHashOffset = ptrOff;
            LOG_OK("founded " + typeName + " hash offset = 0x" + ToHex(ptrOff) + " (hash=0x" + ToHex(val) + ")");
            return true;
        }
    }
    LOG_WARN("could'nt find " + typeName + " hash offset, better luck next time, ahahhaa");
    return false;
}

ScriptOffsets FindScriptOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const InstanceOffsets& instanceOffsets)
{
    ScriptOffsets res;
    res.Valid = false;

    if (!dataModelPtr || !instanceOffsets.Valid) {
        LOG_ERR("datamodel or just instance is not available or trying while game loading");
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

    LOG_INFO("dumper is searching for ModuleScript and LocalScript in ReplicatedStorage... (totally)");

    uintptr_t workspacePtr = instanceOffsets.WorkspacePtr;
    if (!workspacePtr) LOG_WARN("workspace pointer not available");

    uintptr_t replicatedStorage = FindFirstChildByName(hProc, dataModelPtr, instanceOffsets, *pe, "ReplicatedStorage");
    if (!replicatedStorage) LOG_WARN("replicatedStorage not found");

    uintptr_t moduleScript = 0, localScript = 0;
    int nodesVisited = 0;

    // scanning replicatedstorage
    if (replicatedStorage) {
        nodesVisited = 0;
        moduleScript = FindFirstChildByClassRecursive(hProc, replicatedStorage, instanceOffsets, *pe, "ModuleScript", 0, nodesVisited);

        nodesVisited = 0; // ithor from item asylum seset budget for the next instance type
        localScript = FindFirstChildByClassRecursive(hProc, replicatedStorage, instanceOffsets, *pe, "LocalScript", 0, nodesVisited);
    }

    // fallback to if its not found (workspace doesnt have module and local script)
    if (!moduleScript && workspacePtr) {
        nodesVisited = 0;
        moduleScript = FindFirstChildByClassRecursive(hProc, workspacePtr, instanceOffsets, *pe, "ModuleScript", 0, nodesVisited);
    }
    if (!localScript && workspacePtr) {
        nodesVisited = 0;
        localScript = FindFirstChildByClassRecursive(hProc, workspacePtr, instanceOffsets, *pe, "LocalScript", 0, nodesVisited);
    }

    // final fallback, scanning datamodel
    if (!moduleScript) {
        LOG_INFO("Scanning entire DataModel for ModuleScript...");
        nodesVisited = 0;
        moduleScript = FindFirstChildByClassRecursive(hProc, dataModelPtr, instanceOffsets, *pe, "ModuleScript", 0, nodesVisited);
    }
    if (!localScript) {
        LOG_INFO("Scanning entire DataModel for LocalScript...");
        nodesVisited = 0;
        localScript = FindFirstChildByClassRecursive(hProc, dataModelPtr, instanceOffsets, *pe, "LocalScript", 0, nodesVisited);
    }

    if (moduleScript) LOG_INFO("ModuleScript found at 0x" + ToHex(moduleScript));
    else LOG_WARN("ModuleScript not found");
    if (localScript) LOG_INFO("LocalScript found at 0x" + ToHex(localScript));
    else LOG_WARN("LocalScript not found");

    if (!moduleScript && !localScript) {
        LOG_ERR("Could not find any ModuleScript or LocalScript");
        return res;
    }

    // 61 61 61 61 size ! (PLEASE NOT MEME)
    if (moduleScript) {
        uint32_t bytecodePtrOff = 0, sizeOff = 0;
        if (DiscoverBytecodeOffsetsForType(hProc, moduleScript, "ModuleScript", 61, bytecodePtrOff, sizeOff, 0x600)) {
            res.ModuleScriptBytecode = bytecodePtrOff;
            res.ByteCodeSize = sizeOff;
            uint32_t hashOff = 0;
            if (DiscoverHashOffsetForType(hProc, moduleScript, "ModuleScript", hashOff, bytecodePtrOff)) {
                res.ModuleScriptHash = hashOff;
                res.ModuleScriptGuid = hashOff;
            }
        }
    }

    // 86 size
    if (localScript) {
        uint32_t bytecodePtrOff = 0, sizeOff = 0;
        if (DiscoverBytecodeOffsetsForType(hProc, localScript, "LocalScript", 86, bytecodePtrOff, sizeOff, 0x600)) {
            res.LocalScriptBytecode = bytecodePtrOff;
            if (res.ByteCodeSize == 0) res.ByteCodeSize = sizeOff;
            // reuse ModuleScript hash if available or not
            if (res.ModuleScriptHash != 0) {
                uintptr_t hashPtr = 0; uint32_t hashVal = 0; SIZE_T got;
                if (SafeRead(hProc, localScript + res.ModuleScriptHash, &hashPtr, sizeof(hashPtr), got) && got == sizeof(hashPtr) && IsPointerValid(hProc, hashPtr)) {
                    if (SafeRead(hProc, hashPtr, &hashVal, sizeof(hashVal), got) && got == sizeof(hashVal) && hashVal == 1680946276) {
                        res.LocalScriptHash = res.ModuleScriptHash;
                        res.LocalScriptGuid = res.ModuleScriptHash;
                        LOG_OK("reused ModuleScript hash offset for LocalScript: 0x" + ToHex(res.LocalScriptHash));
                    }
                }
            }
            if (res.LocalScriptHash == 0) {
                uint32_t hashOff = 0;
                if (DiscoverHashOffsetForType(hProc, localScript, "LocalScript", hashOff, bytecodePtrOff)) {
                    res.LocalScriptHash = hashOff;
                    res.LocalScriptGuid = hashOff;
                }
            }
        }
    }

    res.ByteCodePointer = 0x10;
    res.Valid = (res.ModuleScriptBytecode != 0 || res.LocalScriptBytecode != 0) && res.ByteCodeSize != 0;

    return res;
}