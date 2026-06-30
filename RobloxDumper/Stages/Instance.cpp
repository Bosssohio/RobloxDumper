// =============================================================================
//  Instance.cpp  –  Fully dynamic with ClassDescriptor and safe tree dump
// =============================================================================
#include "Instance.hpp"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <iomanip>
#include <sstream>


// ------------------------------------------------------------------
//  Find Workspace & Name offset (unchanged)
// ------------------------------------------------------------------
static std::pair<uintptr_t, uint32_t> FindWorkspaceAndNameOffset(
    HANDLE hProc, uintptr_t dataModelPtr, const PEInfo& pe)
{
    const uint32_t MAX_VEC_OFF = 0x800;
    const uint32_t MAX_NAME_OFF = 0x200;
    SIZE_T got;

    LOG_INFO("Scanning DataModel for Workspace and Name offset...");

    for (uint32_t vecOff = 0; vecOff + 24 <= MAX_VEC_OFF; vecOff += 8) {
        uintptr_t vec[3] = { 0 };
        if (!SafeRead(hProc, dataModelPtr + vecOff, vec, sizeof(vec), got) || got != sizeof(vec))
            continue;

        uintptr_t begin = vec[0];
        uintptr_t end = vec[1];
        if (begin == 0 || end < begin) continue;
        if (!IsPointerValid(hProc, begin)) continue;

        size_t count = (end - begin) / sizeof(uintptr_t);
        if (count == 0 || count > 5000) continue;

        for (size_t i = 0; i < count; i++) {
            uintptr_t child = 0;
            if (!SafeRead(hProc, begin + i * sizeof(uintptr_t), &child, sizeof(child), got) ||
                got != sizeof(child) || child == 0)
                continue;

            if (!HasValidVTable(hProc, child, pe)) continue;

            for (uint32_t nameOff = 0; nameOff <= MAX_NAME_OFF; nameOff += 8) {
                uintptr_t namePtr = 0;
                if (!SafeRead(hProc, child + nameOff, &namePtr, sizeof(namePtr), got) ||
                    got != sizeof(namePtr) || namePtr == 0)
                    continue;
                if (!IsPointerValid(hProc, namePtr)) continue;

                auto str = ReadStringSafe(hProc, namePtr);
                if (str.has_value() && *str == "Workspace") {
                    LOG_OK("Found Workspace at 0x" + ToHex(child) +
                        " with Name offset = 0x" + ToHex(nameOff));
                    return { child, nameOff };
                }
            }
        }
    }
    LOG_ERR("Could not find Workspace or its Name offset");
    return { 0, 0 };
}

// ------------------------------------------------------------------
//  Validate candidate (unchanged)
// ------------------------------------------------------------------
static bool ValidateCandidate(
    HANDLE hProc,
    uintptr_t parentPtr,
    uintptr_t workspacePtr,
    uint32_t nameOffset,
    const PEInfo& pe,
    uint32_t startOff,
    uint32_t endOff,
    size_t& outChildCount,
    std::string& method)
{
    SIZE_T got;

    uintptr_t startPtr = 0;
    if (!SafeRead(hProc, parentPtr + startOff, &startPtr, sizeof(startPtr), got) || got != sizeof(startPtr))
        return false;
    if (!IsPointerValid(hProc, startPtr)) return false;

    uintptr_t firstChild = 0;
    if (!SafeRead(hProc, startPtr, &firstChild, sizeof(firstChild), got) || got != sizeof(firstChild))
        return false;
    if (!IsPointerValid(hProc, firstChild)) return false;

    uintptr_t endPtr = 0;
    bool endOk = false;

    if (SafeRead(hProc, firstChild + endOff, &endPtr, sizeof(endPtr), got) && got == sizeof(endPtr) &&
        IsPointerValid(hProc, endPtr) && endPtr > firstChild) {
        method = "firstChild+endOff";
        endOk = true;
    }

    if (!endOk) {
        if (SafeRead(hProc, startPtr + endOff, &endPtr, sizeof(endPtr), got) && got == sizeof(endPtr) &&
            IsPointerValid(hProc, endPtr) && endPtr > firstChild) {
            method = "startPtr+endOff";
            endOk = true;
        }
    }

    if (!endOk) return false;

    size_t count = 0;
    bool foundWS = false;
    const size_t MAX_SCAN = 10000;
    for (size_t i = 0; i < MAX_SCAN; i++) {
        if (endPtr > firstChild && (firstChild + i * 0x10) >= endPtr) break;
        uintptr_t child = 0;
        if (!SafeRead(hProc, firstChild + i * 0x10, &child, sizeof(child), got) || got != sizeof(child))
            break;
        if (!IsPointerValid(hProc, child)) break;
        if (!HasValidVTable(hProc, child, pe)) break;
        uintptr_t namePtr = 0;
        if (!SafeRead(hProc, child + nameOffset, &namePtr, sizeof(namePtr), got) || got != sizeof(namePtr))
            break;
        if (!IsPointerValid(hProc, namePtr)) break;
        auto nameStr = ReadStringSafe(hProc, namePtr);
        if (!nameStr.has_value() || nameStr->empty()) break;
        if (child == workspacePtr) foundWS = true;
        count++;
    }

    if (count == 0 || !foundWS) return false;
    outChildCount = count;
    return true;
}

// ------------------------------------------------------------------
//  Dynamic search for ChildrenStart/End (skip endOff = 0)
// ------------------------------------------------------------------
static bool FindChildrenOffsetsDynamic(
    HANDLE hProc,
    uintptr_t parentPtr,
    uintptr_t workspacePtr,
    uint32_t nameOffset,
    const PEInfo& pe,
    uint32_t& outStartOff,
    uint32_t& outEndOff,
    size_t& outChildCount)
{
    const uint32_t MAX_OFF = 0x800;
    const uint32_t MAX_END_OFF = 0x100;

    LOG_INFO("Dynamic search for ChildrenStart/End offsets...");

    for (uint32_t startOff = 0; startOff < MAX_OFF; startOff += 8) {
        uintptr_t startPtr = 0;
        SIZE_T got;
        if (!SafeRead(hProc, parentPtr + startOff, &startPtr, sizeof(startPtr), got) || got != sizeof(startPtr))
            continue;
        if (!IsPointerValid(hProc, startPtr)) continue;

        for (uint32_t endOff = 0x8; endOff < MAX_END_OFF; endOff += 8) { // start from 0x8
            size_t childCount = 0;
            std::string method;
            if (ValidateCandidate(hProc, parentPtr, workspacePtr, nameOffset, pe,
                startOff, endOff, childCount, method)) {
                LOG_OK("Found valid children: start=0x" + ToHex(startOff) +
                    ", end=0x" + ToHex(endOff) + " (method: " + method +
                    "), count=" + std::to_string(childCount));
                outStartOff = startOff;
                outEndOff = endOff;
                outChildCount = childCount;
                return true;
            }
        }
    }

    LOG_ERR("No valid children offsets found");
    return false;
}

// ------------------------------------------------------------------
//  Parent offset (dynamic)
// ------------------------------------------------------------------
static uint32_t FindParentOffset(HANDLE hProc, uintptr_t workspacePtr, uintptr_t dataModelPtr) {
    const uint32_t MAX_OFF = 0x200;
    SIZE_T got;
    LOG_INFO("Scanning Workspace for Parent");
    for (uint32_t off = 0; off <= MAX_OFF; off += 8) {
        uintptr_t val = 0;
        if (!SafeRead(hProc, workspacePtr + off, &val, sizeof(val), got) || got != sizeof(val))
            continue;
        if (val == dataModelPtr) {
            LOG_OK("Parent offset = 0x" + ToHex(off));
            return off;
        }
    }
    LOG_ERR("Parent offset not found");
    return 0;
}

// ------------------------------------------------------------------
//  ClassDescriptor and ClassName via RTTI (no hardcoded offsets)
// ------------------------------------------------------------------
static bool FindClassOffsetsViaRTTI(
    HANDLE hProc,
    uintptr_t workspacePtr,
    const PEInfo& pe,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf,
    uint32_t& outClassDescriptorOffset,
    uint32_t& outClassNameOffset)
{
    LOG_INFO("Finding ClassDescriptor and ClassName via RTTI...");

    auto rtti = FindRTTI(hProc, pe, rdataBuf, dataBuf, ".?AVClassDescriptor@Reflection@RBX@@");
    if (!rtti) {
        LOG_ERR("ClassDescriptor RTTI not found");
        return false;
    }

    uintptr_t classDescVtable = pe.moduleBase + rtti->vtableRVA;
    const uint32_t MAX_OFF = 0x200;
    SIZE_T got;

    // Scan Workspace for the ClassDescriptor pointer
    for (uint32_t off = 0; off <= MAX_OFF; off += 8) {
        uintptr_t val = 0;
        if (!SafeRead(hProc, workspacePtr + off, &val, sizeof(val), got) || got != sizeof(val))
            continue;
        if (!IsPointerValid(hProc, val)) continue;

        uintptr_t vtable = 0;
        if (!SafeRead(hProc, val, &vtable, sizeof(vtable), got) || got != sizeof(vtable))
            continue;
        if (vtable != classDescVtable) continue;

        // Found the ClassDescriptor pointer – store its offset
        outClassDescriptorOffset = off;

        // Now find the class name string inside the ClassDescriptor
        // Scan for a string "Workspace" inside the ClassDescriptor object
        bool nameFound = false;
        for (uint32_t nameOff = 0; nameOff < 0x100; nameOff += 8) {
            uintptr_t namePtr = 0;
            if (!SafeRead(hProc, val + nameOff, &namePtr, sizeof(namePtr), got) || got != sizeof(namePtr))
                continue;
            if (!IsPointerValid(hProc, namePtr)) continue;
            auto str = ReadStringSafe(hProc, namePtr);
            if (str.has_value() && *str == "Workspace") {
                outClassNameOffset = nameOff;
                nameFound = true;
                LOG_OK("ClassDescriptor offset = 0x" + ToHex(off) +
                    ", ClassName offset = 0x" + ToHex(nameOff) + " (\"" + *str + "\")");
                break;
            }
        }
        if (nameFound) return true;
    }

    LOG_ERR("Could not find ClassDescriptor or ClassName via RTTI");
    return false;
}

// ------------------------------------------------------------------
//  Main entry point
// ------------------------------------------------------------------
InstanceOffsets FindInstanceOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf)
{
    InstanceOffsets res;
    res.Valid = false;

    if (!dataModelPtr) { LOG_ERR("DataModel pointer is null"); return res; }

    uintptr_t moduleBase = GetModuleBase(hProc);
    if (!moduleBase) { LOG_ERR("Could not get module base"); return res; }
    auto pe = GetPEInfo(hProc, moduleBase);
    if (!pe) { LOG_ERR("Could not parse PE"); return res; }

    // 1. Workspace & Name
    auto [workspacePtr, nameOffset] = FindWorkspaceAndNameOffset(hProc, dataModelPtr, *pe);
    if (!workspacePtr || !nameOffset) {
        LOG_ERR("Failed to find Workspace or Name offset");
        return res;
    }
    res.Name = nameOffset;
    res.WorkspacePtr = workspacePtr;
    res.DataModelPtr = dataModelPtr;

    // 2. Children offsets
    uint32_t startOff = 0, endOff = 0;
    size_t childCount = 0;
    if (!FindChildrenOffsetsDynamic(hProc, dataModelPtr, workspacePtr, nameOffset, *pe,
        startOff, endOff, childCount)) {
        LOG_ERR("Failed to find children offsets");
        return res;
    }
    res.ChildrenStart = startOff;
    res.ChildrenEnd = endOff;
    res.Attributes = (uint32_t)childCount;

    // 3. Parent
    res.Parent = FindParentOffset(hProc, workspacePtr, dataModelPtr);
    if (res.Parent == 0) {
        LOG_ERR("Failed to find Parent offset");
        return res;
    }

    // 4. ClassDescriptor & ClassName via RTTI
    uint32_t classDescOff = 0, classNameOff = 0;
    if (!FindClassOffsetsViaRTTI(hProc, workspacePtr, *pe, rdataBuf, dataBuf, classDescOff, classNameOff)) {
        LOG_ERR("Failed to find ClassDescriptor or ClassName");
        return res;
    }
    res.ClassDescriptor = classDescOff;
    res.ClassName = classNameOff;

    res.Valid = true;
    LOG_OK("Instance offsets discovered successfully");
    return res;
}

// ------------------------------------------------------------------
//  Tree dump with safe child validation and BOTH endPtr methods
// ------------------------------------------------------------------
void DumpInstanceTree(
    HANDLE hProc,
    uintptr_t rootInstancePtr,
    const InstanceOffsets& offsets,
    std::ostream& out,
    int depth)
{
    const int MAX_DEPTH = 200;
    const size_t MAX_CHILDREN = 5000;

    if (depth > MAX_DEPTH || rootInstancePtr == 0) {
        out << "{}";
        return;
    }

    auto indent = [depth]() -> std::string { return std::string(depth * 2, ' '); };

    std::string name = "<unknown>";
    if (offsets.Name) {
        uintptr_t namePtr = 0; SIZE_T got;
        if (SafeRead(hProc, rootInstancePtr + offsets.Name, &namePtr, sizeof(namePtr), got) && got == sizeof(namePtr) && namePtr)
            if (auto s = ReadStringSafe(hProc, namePtr)) name = *s;
    }

    std::string className = "Instance";
    if (offsets.ClassDescriptor && offsets.ClassName) {
        uintptr_t classDescPtr = 0;
        SIZE_T got;
        if (SafeRead(hProc, rootInstancePtr + offsets.ClassDescriptor, &classDescPtr, sizeof(classDescPtr), got) && got == sizeof(classDescPtr) && classDescPtr) {
            uintptr_t namePtr = 0;
            if (SafeRead(hProc, classDescPtr + offsets.ClassName, &namePtr, sizeof(namePtr), got) && got == sizeof(namePtr) && namePtr) {
                if (auto s = ReadStringSafe(hProc, namePtr)) className = *s;
            }
        }
    }

    out << indent() << "{\n";
    out << indent() << "  \"Name\": \"" << EscapeCString(name) << "\",\n";
    out << indent() << "  \"ClassName\": \"" << EscapeCString(className) << "\",\n";
    out << indent() << "  \"Address\": \"0x" << ToHex(rootInstancePtr) << "\",\n";

    uintptr_t dataModelPtr = 0;
    if (offsets.Parent) {
        SIZE_T got;
        SafeRead(hProc, rootInstancePtr + offsets.Parent, &dataModelPtr, sizeof(dataModelPtr), got);
    }

    // ---- Children ----
    if (offsets.ChildrenStart && dataModelPtr) {
        uintptr_t startPtr = 0;
        SIZE_T got;
        if (SafeRead(hProc, dataModelPtr + offsets.ChildrenStart, &startPtr, sizeof(startPtr), got) && got == sizeof(startPtr) && startPtr) {
            uintptr_t firstChild = 0;
            if (SafeRead(hProc, startPtr, &firstChild, sizeof(firstChild), got) && got == sizeof(firstChild) && firstChild) {
                uintptr_t endPtr = 0;
                bool endOk = false;

                // ★ FIX: Try both methods
                // Method A: endPtr = firstChild + ChildrenEnd
                if (SafeRead(hProc, firstChild + offsets.ChildrenEnd, &endPtr, sizeof(endPtr), got) && got == sizeof(endPtr) && endPtr > firstChild) {
                    endOk = true;
                }
                // Method B: endPtr = startPtr + ChildrenEnd
                if (!endOk) {
                    if (SafeRead(hProc, startPtr + offsets.ChildrenEnd, &endPtr, sizeof(endPtr), got) && got == sizeof(endPtr) && endPtr > firstChild) {
                        endOk = true;
                    }
                }

                if (endOk) {
                    size_t count = (endPtr - firstChild) / 0x10;
                    if (count == 0 && offsets.Attributes) count = offsets.Attributes;
                    if (count > MAX_CHILDREN) count = MAX_CHILDREN;

                    out << indent() << "  \"Children\": [\n";
                    for (size_t i = 0; i < count; i++) {
                        uintptr_t childPtr = 0;
                        if (SafeRead(hProc, firstChild + i * 0x10, &childPtr, sizeof(childPtr), got) && got == sizeof(childPtr) && childPtr != 0) {
                            // Strict validation before recursing
                            if (IsPointerValid(hProc, childPtr) && HasValidVTable(hProc, childPtr, GetPEInfo(hProc, GetModuleBase(hProc)).value())) {
                                uintptr_t namePtr = 0;
                                if (offsets.Name && SafeRead(hProc, childPtr + offsets.Name, &namePtr, sizeof(namePtr), got) && got == sizeof(namePtr) && IsPointerValid(hProc, namePtr)) {
                                    auto str = ReadStringSafe(hProc, namePtr);
                                    if (str.has_value() && !str->empty()) {
                                        DumpInstanceTree(hProc, childPtr, offsets, out, depth + 2);
                                        if (i < count - 1) out << ",";
                                        out << "\n";
                                        continue;
                                    }
                                }
                            }
                            // If validation fails, skip this child
                        }
                    }
                    out << indent() << "  ]\n";
                }
                else {
                    out << indent() << "  \"Children\": []\n";
                }
            }
            else {
                out << indent() << "  \"Children\": []\n";
            }
        }
        else {
            out << indent() << "  \"Children\": []\n";
        }
    }
    else {
        out << indent() << "  \"Children\": []\n";
    }

    out << indent() << "}";
}