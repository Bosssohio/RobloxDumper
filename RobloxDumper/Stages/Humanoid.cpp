#include "Humanoid.hpp"
#include "../OffsetScanner.hpp"
#include <set>
#include <cmath>
#include <cctype>

static uintptr_t FindFirstChildByClassRecursive(
    HANDLE hProc,
    uintptr_t currentPtr,
    const InstanceOffsets& offsets,
    const PEInfo& pe,
    const std::string& className,
    int depth = 0,
    int& totalNodesVisited = *(new int(0)))
{
    const int MAX_DEPTH = 200;
    const int MAX_TOTAL_NODES = 5000;

    if (depth > MAX_DEPTH || !currentPtr || totalNodesVisited > MAX_TOTAL_NODES) {
        return 0;
    }

    uintptr_t classDescPtr = 0;
    SIZE_T got;
    if (SafeRead(hProc, currentPtr + offsets.ClassDescriptor, &classDescPtr, sizeof(classDescPtr), got) && got == sizeof(classDescPtr) && classDescPtr) {
        uintptr_t namePtr = 0;
        if (SafeRead(hProc, classDescPtr + offsets.ClassName, &namePtr, sizeof(namePtr), got) && got == sizeof(namePtr) && namePtr) {
            auto str = ReadStringSafe(hProc, namePtr);
            if (str && *str == className) {
                return currentPtr;
            }
        }
    }

    if (!offsets.ChildrenStart || !offsets.ChildrenEnd) return 0;
    uintptr_t startPtr = 0;
    if (!SafeRead(hProc, currentPtr + offsets.ChildrenStart, &startPtr, sizeof(startPtr), got) || got != sizeof(startPtr) || !startPtr) return 0;
    uintptr_t firstChild = 0;
    if (!SafeRead(hProc, startPtr, &firstChild, sizeof(firstChild), got) || got != sizeof(firstChild) || !firstChild) return 0;

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
            uintptr_t found = FindFirstChildByClassRecursive(hProc, child, offsets, pe, className, depth + 1, totalNodesVisited);
            if (found) return found;
        }
    }
    return 0;
}

static bool IsFloatEqual(float a, float b, float eps = 0.001f) {
    return fabs(a - b) < eps;
}

static uint32_t FindFloatInRange(HANDLE hProc, uintptr_t obj, float target, uint32_t startOff, uint32_t endOff, uint32_t align = 4) {
    SIZE_T got;
    for (uint32_t off = startOff; off <= endOff; off += align) {
        float val = 0;
        if (!SafeRead(hProc, obj + off, &val, sizeof(val), got) || got != sizeof(val)) continue;
        if (IsFloatEqual(val, target)) return off;
    }
    return 0;
}

static uint32_t FindFloatInRangeHeuristic(HANDLE hProc, uintptr_t obj, float minVal, float maxVal, uint32_t startOff, uint32_t endOff, uint32_t align = 4) {
    SIZE_T got;
    for (uint32_t off = startOff; off <= endOff; off += align) {
        float val = 0;
        if (!SafeRead(hProc, obj + off, &val, sizeof(val), got) || got != sizeof(val)) continue;
        if (val >= minVal && val <= maxVal) return off;
    }
    return 0;
}

static uint32_t FindIntInRange(HANDLE hProc, uintptr_t obj, int target, uint32_t startOff, uint32_t endOff, uint32_t align = 4) {
    SIZE_T got;
    for (uint32_t off = startOff; off <= endOff; off += align) {
        int val = 0;
        if (!SafeRead(hProc, obj + off, &val, sizeof(val), got) || got != sizeof(val)) continue;
        if (val == target) return off;
    }
    return 0;
}

// Robust MSVC std::string Inline/SSO Reader
//make sure if its ass bruh
static std::optional<std::string> ReadStringSSO(HANDLE hProc, uintptr_t addr) {
    size_t length = 0;
    size_t capacity = 0;
    SIZE_T got;

    if (!SafeRead(hProc, addr + 0x10, &length, sizeof(length), got) || got != sizeof(length)) return std::nullopt;
    if (!SafeRead(hProc, addr + 0x18, &capacity, sizeof(capacity), got) || got != sizeof(capacity)) return std::nullopt;

    if (length == 0 || length > 100) return std::nullopt;
    if (capacity != 15 && capacity < 16) return std::nullopt;

    if (capacity >= 16) {
        uintptr_t heapPtr = 0;
        if (SafeRead(hProc, addr, &heapPtr, sizeof(heapPtr), got) && got == sizeof(heapPtr) && IsPointerValid(hProc, heapPtr)) {
            std::string result(length, '\0');
            if (SafeRead(hProc, heapPtr, &result[0], length, got) && got == length) return result;
        }
    }
    else {
        std::string result(length, '\0');
        if (SafeRead(hProc, addr, &result[0], length, got) && got == length) return result;
    }
    return std::nullopt;
}

static uintptr_t FindHumanoidInstance(HANDLE hProc, uintptr_t dataModelPtr, const InstanceOffsets& instanceOffsets, const PEInfo& pe) {
    LOG_INFO("dumper is searching DataModel for NPC->Humanoid...");
    int totalNodes = 0;
    uintptr_t humanoid = FindFirstChildByClassRecursive(hProc, dataModelPtr, instanceOffsets, pe, "Humanoid", 0, totalNodes);
    if (humanoid) {
        LOG_OK("Humanoid found at 0x" + ToHex(humanoid));
    }
    else {
        LOG_WARN("humanoid not found in DataModel, please do not remove");
    }
    return humanoid;
}

HumanoidOffsets FindHumanoidOffsets(HANDLE hProc, uintptr_t dataModelPtr, const InstanceOffsets& instanceOffsets) {
    HumanoidOffsets res;
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

    uintptr_t humanoid = FindHumanoidInstance(hProc, dataModelPtr, instanceOffsets, *pe);
    if (!humanoid) {
        LOG_ERR("dumper cannot Humanoid founded, cannot discover offsets");
        return res;
    }

    LOG_INFO("Discovering Humanoid offsets dynamically...");
    std::set<uint32_t> usedOffsets;

    // floats
    res.Health = FindFloatInRange(hProc, humanoid, 100.0f, 0x190, 0x1A0, 4);
    if (res.Health) { usedOffsets.insert(res.Health); LOG_OK("Health offset: 0x" + ToHex(res.Health)); }

    // maxhealth (floats)
    for (uint32_t off = 0x1B0; off <= 0x1C0; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        float val = 0;
        SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 100.0f)) {
            res.MaxHealth = off;
            usedOffsets.insert(off);
            LOG_OK("MaxHealth offset: 0x" + ToHex(off));
            break;
        }
    }

    // walkspeed
    uint32_t wsOff = FindFloatInRange(hProc, humanoid, 16.0f, 0x1D0, 0x1F0, 4);
    if (wsOff && usedOffsets.find(wsOff) == usedOffsets.end()) {
        res.WalkSpeed = wsOff; usedOffsets.insert(wsOff);
        LOG_OK("WalkSpeed offset: 0x" + ToHex(wsOff));
    }
    else {
        wsOff = FindFloatInRangeHeuristic(hProc, humanoid, 10.0f, 30.0f, 0x1D0, 0x1F0, 4);
        if (wsOff && usedOffsets.find(wsOff) == usedOffsets.end()) {
            res.WalkSpeed = wsOff; usedOffsets.insert(wsOff);
            LOG_OK("WalkSpeed offset (heuristic): 0x" + ToHex(wsOff));
        }
    }

    // jumppower
    uint32_t jpOff = FindFloatInRange(hProc, humanoid, 50.0f, 0x1A8, 0x1C0, 4);
    if (jpOff && usedOffsets.find(jpOff) == usedOffsets.end()) {
        res.JumpPower = jpOff; usedOffsets.insert(jpOff);
        LOG_OK("JumpPower offset: 0x" + ToHex(jpOff));
    }
    else {
        jpOff = FindFloatInRangeHeuristic(hProc, humanoid, 30.0f, 70.0f, 0x1A8, 0x1C0, 4);
        if (jpOff && usedOffsets.find(jpOff) == usedOffsets.end()) {
            res.JumpPower = jpOff; usedOffsets.insert(jpOff);
            LOG_OK("JumpPower offset (heuristic): 0x" + ToHex(jpOff));
        }
    }

    // jumpheight
    uint32_t jhOff = FindFloatInRange(hProc, humanoid, 7.2f, 0x1A0, 0x1B0, 4);
    if (jhOff && usedOffsets.find(jhOff) == usedOffsets.end()) {
        res.JumpHeight = jhOff; usedOffsets.insert(jhOff);
        LOG_OK("JumpHeight offset: 0x" + ToHex(jhOff));
    }
    else {
        jhOff = FindFloatInRangeHeuristic(hProc, humanoid, 5.0f, 15.0f, 0x1A0, 0x1B0, 4);
        if (jhOff && usedOffsets.find(jhOff) == usedOffsets.end()) {
            res.JumpHeight = jhOff; usedOffsets.insert(jhOff);
            LOG_OK("JumpHeight offset (heuristic): 0x" + ToHex(jhOff));
        }
    }

    // hipheight
    for (uint32_t off = 0x198; off <= 0x1A8; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        float val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 0.0f)) {
            res.HipHeight = off; usedOffsets.insert(off);
            LOG_OK("HipHeight offset: 0x" + ToHex(off));
            break;
        }
    }

    // maxslopeangle (SLOP RETROSLOP?!?!?! AHAHAHHAH)
    for (uint32_t off = 0x1B0; off <= 0x1C0; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        float val = 0;
        SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 89.0f)) {
            res.MaxSlopeAngle = off;
            usedOffsets.insert(off);
            LOG_OK("MaxSlopeAngle offset: 0x" + ToHex(off));
            break;
        }
    }
    // fallback to shit if 89 doesnt exist (impossible to rid fallback)
    if (res.MaxSlopeAngle == 0) {
        for (uint32_t off = 0x1B0; off <= 0x1C0; off += 4) {
            if (usedOffsets.find(off) != usedOffsets.end()) continue;
            float val = 0;
            SIZE_T got;
            if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 70.0f)) {
                res.MaxSlopeAngle = off;
                usedOffsets.insert(off);
                LOG_OK("MaxSlopeAngle offset (fallback 70.0): 0x" + ToHex(off));
                break;
            }
        }
    }

    // walktimer
    for (uint32_t off = 0x1D0; off <= 0x1E0; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        float val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 0.0f)) {
            res.WalkTimer = off; usedOffsets.insert(off);
            LOG_OK("WalkTimer offset: 0x" + ToHex(off));
            break;
        }
    }

    // healthdisplaydistance (easy)
    for (uint32_t off = 0x190; off <= 0x1A0; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        float val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 0.0f)) {
            res.HealthDisplayDistance = off; usedOffsets.insert(off);
            LOG_OK("HealthDisplayDistance offset: 0x" + ToHex(off));
            break;
        }
    }

    // booleans offsets
    // autojumpenabled
    for (uint32_t off = 0x1E0; off <= 0x200; off += 1) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uint8_t val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 1) {
            if (off != res.AutoRotate && off != res.RequiresNeck) {
                res.AutoJumpEnabled = off; usedOffsets.insert(off);
                LOG_OK("AutoJumpEnabled offset: 0x" + ToHex(off));
                break;
            }
        }
    }

    // autorotate
    for (uint32_t off = 0x1E0; off <= 0x1E2; off += 1) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uint8_t val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 1) {
            res.AutoRotate = off; usedOffsets.insert(off);
            LOG_OK("AutoRotate offset: 0x" + ToHex(off));
            break;
        }
    }

    // Sit (cute)
    for (uint32_t off = 0x1E8; off <= 0x1EA; off += 1) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uint8_t val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 0) {
            res.Sit = off; usedOffsets.insert(off);
            LOG_OK("Sit offset: 0x" + ToHex(off));
            break;
        }
    }

    // BreakJointsOnDeath (ahh fresh meat)
    for (uint32_t off = 0x1E4; off <= 0x1E6; off += 1) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uint8_t val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 0) {
            res.BreakJointsOnDeath = off; usedOffsets.insert(off);
            LOG_OK("BreakJointsOnDeath offset: 0x" + ToHex(off));
            break;
        }
    }

    // PlatformStand 
    for (uint32_t off = 0x1E6; off <= 0x1E8; off += 1) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uint8_t val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 0) {
            res.PlatformStand = off; usedOffsets.insert(off);
            LOG_OK("PlatformStand offset: 0x" + ToHex(off));
            break;
        }
    }

    // RequiresNeck 
    for (uint32_t off = 0x1E0; off <= 0x1EC; off += 1) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uint8_t val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 1) {
            if (off != res.AutoRotate) {
                res.RequiresNeck = off; usedOffsets.insert(off);
                LOG_OK("RequiresNeck offset: 0x" + ToHex(off));
                break;
            }
        }
    }

    // UseJumpPower 
    for (uint32_t off = 0x1E0; off <= 0x1EC; off += 1) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uint8_t val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 0) {
            if (off != res.AutoJumpEnabled && off != res.Sit && off != res.BreakJointsOnDeath && off != res.PlatformStand) {
                res.UseJumpPower = off; usedOffsets.insert(off);
                LOG_OK("UseJumpPower offset: 0x" + ToHex(off));
                break;
            }
        }
    }

    // emuns/int
    // nameocculans (issue)
    for (uint32_t off = 0x1B0; off <= 0x1D0; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        int val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 2) {
            res.NameOcclusion = off; usedOffsets.insert(off);
            LOG_OK("NameOcclusion offset (value 2): 0x" + ToHex(off));
            break;
        }
    }
    // fallback if not founded 
    if (res.NameOcclusion == 0) {
        for (uint32_t off = 0x1B0; off <= 0x1D0; off += 4) {
            if (usedOffsets.find(off) != usedOffsets.end()) continue;
            int val = 0; SIZE_T got;
            if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val != 0) {
                res.NameOcclusion = off; usedOffsets.insert(off);
                LOG_OK("NameOcclusion offset (fallback non-zero): 0x" + ToHex(off));
                break;
            }
        }
    }

    // RigType
    for (uint32_t off = 0x1EC; off <= 0x220; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        int val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 0) {
            // im not so ensure it doesn't overlap with NameOcclusion
            if (off != res.NameOcclusion) {
                res.RigType = off; usedOffsets.insert(off);
                LOG_OK("RigType offset: 0x" + ToHex(off));
                break;
            }
        }
    }

    // HumanoidState 
    for (uint32_t off = 0x1F0; off <= 0x240; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        int val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 8) {
            res.HumanoidState = off; usedOffsets.insert(off);
            LOG_OK("HumanoidState offset (active 8): 0x" + ToHex(off));
            break;
        }
    }
    if (res.HumanoidState == 0) {
        for (uint32_t off = 0x1F0; off <= 0x240; off += 4) {
            if (usedOffsets.find(off) != usedOffsets.end()) continue;
            int val = 0; SIZE_T got;
            if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && val == 0) {
                if (off != res.RigType && off != res.NameOcclusion) {
                    res.HumanoidState = off; usedOffsets.insert(off);
                    LOG_OK("HumanoidState offset (fallback 0): 0x" + ToHex(off));
                    break;
                }
            }
        }
    }

    // vector3 (first float)
    // CameraOffset 
    for (uint32_t off = 0x1B0; off <= 0x1D0; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        float val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 0.0f)) {
            res.CameraOffset = off; usedOffsets.insert(off);
            LOG_OK("CameraOffset offset (start): 0x" + ToHex(off));
            break;
        }
    }

    // MoveDirection
    for (uint32_t off = 0x1D0; off <= 0x1E0; off += 4) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        float val = 0; SIZE_T got;
        if (SafeRead(hProc, humanoid + off, &val, sizeof(val), got) && got == sizeof(val) && IsFloatEqual(val, 0.0f)) {
            res.MoveDirection = off; usedOffsets.insert(off);
            LOG_OK("MoveDirection offset (start): 0x" + ToHex(off));
            break;
        }
    }

    // object pointer
    const uint32_t MAX_OBJ_SCAN = 0x500;
    for (uint32_t off = 0x400; off < MAX_OBJ_SCAN; off += 8) {
        if (usedOffsets.find(off) != usedOffsets.end()) continue;
        uintptr_t ptr = 0; SIZE_T got;
        if (!SafeRead(hProc, humanoid + off, &ptr, sizeof(ptr), got) || got != sizeof(ptr)) continue;
        if (!IsPointerValid(hProc, ptr)) continue;

        uintptr_t classDescPtr = 0;
        if (!SafeRead(hProc, ptr + instanceOffsets.ClassDescriptor, &classDescPtr, sizeof(classDescPtr), got) || got != sizeof(classDescPtr)) continue;
        if (!IsPointerValid(hProc, classDescPtr)) continue;

        uintptr_t namePtr = 0;
        if (!SafeRead(hProc, classDescPtr + instanceOffsets.ClassName, &namePtr, sizeof(namePtr), got) || got != sizeof(namePtr)) continue;
        if (!IsPointerValid(hProc, namePtr)) continue;

        auto name = ReadStringSafe(hProc, namePtr);
        if (name && (*name == "Part" || *name == "BasePart" || *name == "Model")) {
            if (res.HumanoidRootPart == 0) {
                res.HumanoidRootPart = off; usedOffsets.insert(off);
                LOG_OK("HumanoidRootPart offset: 0x" + ToHex(off));
            }
            else if (res.SeatPart == 0 && off != res.HumanoidRootPart) {
                res.SeatPart = off; usedOffsets.insert(off);
                LOG_OK("SeatPart offset: 0x" + ToHex(off));
            }
        }
    }

    // display name
    const uint32_t MAX_STRING_SCAN = 0x400;
    for (uint32_t off = 0x20; off < MAX_STRING_SCAN; off += 4) {
        if (off == instanceOffsets.Name) continue;
        if (usedOffsets.find(off) != usedOffsets.end()) continue;

        auto str = ReadStringSSO(hProc, humanoid + off);
        if (str && !str->empty()) {
            if (*str != "Humanoid" && *str != "humanoid") {
                res.DisplayName = off;
                usedOffsets.insert(off);
                LOG_OK("DisplayName offset found via SSO: 0x" + ToHex(off) + " (\"" + *str + "\")");
                break;
            }
        }
    }

    // vaild if its founded
    res.Valid = (res.Health != 0 && res.MaxHealth != 0);
    if (res.Valid) {
        LOG_OK("Humanoid offsets discovered successfully");
    }
    else {
        LOG_ERR("Failed to discover essential Humanoid offsets (Health & MaxHealth)");
    }
    return res;
}