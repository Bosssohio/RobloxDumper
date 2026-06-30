// =============================================================================
//  DataModel.cpp  –  Discover DataModel properties (Fixed Dynamic Scanner)
// =============================================================================
#include "DataModel.hpp"
#include "../OffsetScanner.hpp"
#include <regex>

// ------------------------------------------------------------------
//  Helper: Robustly read an MSVC x64 string layout safely
// ------------------------------------------------------------------
static std::optional<std::string> ReadStringSSO(HANDLE hProc, uintptr_t addr) {
    if (!IsPointerValid(hProc, addr)) return std::nullopt;

    // MSVC x64 std::string layout (32 bytes total):
    // [0x00] - Data pointer (Long) / Inline char buffer (Short/SSO)
    // [0x10] - Length (size_t)
    // [0x18] - Capacity (size_t)
    size_t length = 0;
    size_t capacity = 0;
    SIZE_T got;

    if (!SafeRead(hProc, addr + 0x10, &length, sizeof(length), got) || got != sizeof(length)) return std::nullopt;
    if (!SafeRead(hProc, addr + 0x18, &capacity, sizeof(capacity), got) || got != sizeof(capacity)) return std::nullopt;

    // Sanity check bounds to reject invalid memory regions
    if (length == 0 || length > 1000) return std::nullopt;

    // MSVC string verification: capacity is either exactly 15 (short) or >= 16 (long)
    if (capacity != 15 && capacity < 16) return std::nullopt;

    if (capacity >= 16) {
        // Long string: read string data from heap pointer
        uintptr_t heapPtr = 0;
        if (SafeRead(hProc, addr, &heapPtr, sizeof(heapPtr), got) && got == sizeof(heapPtr) && IsPointerValid(hProc, heapPtr)) {
            std::string result(length, '\0');
            if (SafeRead(hProc, heapPtr, &result[0], length, got) && got == length) {
                return result;
            }
        }
    }
    else {
        // Short string: read string data directly inline
        std::string result(length, '\0');
        if (SafeRead(hProc, addr, &result[0], length, got) && got == length) {
            return result;
        }
    }

    return std::nullopt;
}

// ------------------------------------------------------------------
//  Helper: validate an IP string (strict)
// ------------------------------------------------------------------
static bool IsValidIP(const std::string& str) {
    std::regex ipRegex(R"((\d{1,3}\.){3}\d{1,3}([:|]\d+)?)");
    return std::regex_match(str, ipRegex);
}

// ------------------------------------------------------------------
//  Helper: validate a UUID string
// ------------------------------------------------------------------
static bool IsValidUUID(const std::string& str) {
    std::regex uuidRegex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    return std::regex_match(str, uuidRegex);
}

DataModelOffsets FindDataModelOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const InstanceOffsets& instanceOffsets,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf,
    const PEInfo& pe)
{
    DataModelOffsets res;
    res.Valid = false;

    if (!dataModelPtr || !instanceOffsets.Valid) {
        LOG_ERR("DataModel or Instance offsets not available");
        return res;
    }

    LOG_INFO("Discovering DataModel properties...");

    // 1. GameLoaded – scan for uint32_t value 31
    uint32_t gameLoadedOff = FindIntOffset(hProc, dataModelPtr, 31, 0x1000, 4);
    if (gameLoadedOff) {
        res.GameLoaded = gameLoadedOff;
        LOG_OK("GameLoaded offset: 0x" + ToHex(gameLoadedOff));
    }
    else {
        LOG_WARN("GameLoaded offset not found");
    }

    // 2. Find NetworkClient (RTTI → container scan → flat pointer)
    uintptr_t networkClientPtr = 0;
    uint32_t networkClientOffset = 0;

    std::vector<std::string> rttiNames = {
        ".?AVNetworkClientProp@Network@RBX@@",
        ".?AVNetworkClient@RBX@@"
    };

    for (const auto& name : rttiNames) {
        auto rtti = FindRTTI(hProc, pe, rdataBuf, dataBuf, name);
        if (rtti) {
            uintptr_t networkVtable = pe.moduleBase + rtti->vtableRVA;
            LOG_OK("NetworkClient vtable found (RTTI: " + name + ") at 0x" + ToHex(networkVtable));
            const uint32_t MAX_SCAN = 0x1000;
            for (uint32_t off = 0x20; off < MAX_SCAN; off += 8) {
                uintptr_t ptr = 0;
                SIZE_T got;
                if (!SafeRead(hProc, dataModelPtr + off, &ptr, sizeof(ptr), got) || got != sizeof(ptr)) continue;
                if (!IsPointerValid(hProc, ptr)) continue;
                uintptr_t vtable = 0;
                if (!SafeRead(hProc, ptr, &vtable, sizeof(vtable), got) || got != sizeof(vtable)) continue;
                if (vtable == networkVtable) {
                    networkClientPtr = ptr;
                    networkClientOffset = off;
                    LOG_OK("NetworkClient found at 0x" + ToHex(networkClientPtr) +
                        " (offset 0x" + ToHex(off) + " in DataModel)");
                    break;
                }
            }
            if (networkClientPtr) break;
        }
    }

    if (!networkClientPtr) {
        LOG_INFO("RTTI lookup failed. Scanning DataModel for service containers...");
        const uint32_t MAX_SCAN = 0x500;
        for (uint32_t off = 0x10; off < MAX_SCAN; off += 8) {
            uintptr_t vecStart = 0, vecEnd = 0;
            SIZE_T got;
            if (!SafeRead(hProc, dataModelPtr + off, &vecStart, sizeof(vecStart), got) || got != sizeof(vecStart)) continue;
            if (!SafeRead(hProc, dataModelPtr + off + 8, &vecEnd, sizeof(vecEnd), got) || got != sizeof(vecEnd)) continue;
            if (!IsPointerValid(hProc, vecStart) || !IsPointerValid(hProc, vecEnd)) continue;
            if (vecEnd < vecStart || (vecEnd - vecStart) > 2000 * sizeof(uintptr_t)) continue;

            for (uintptr_t elemPtr = vecStart; elemPtr < vecEnd; elemPtr += sizeof(uintptr_t)) {
                uintptr_t candidate = 0;
                if (!SafeRead(hProc, elemPtr, &candidate, sizeof(candidate), got) || got != sizeof(candidate)) continue;
                if (!IsPointerValid(hProc, candidate)) continue;
                uintptr_t classDescPtr = 0;
                if (!SafeRead(hProc, candidate + instanceOffsets.ClassDescriptor, &classDescPtr, sizeof(classDescPtr), got) || got != sizeof(classDescPtr)) continue;
                if (!IsPointerValid(hProc, classDescPtr)) continue;
                uintptr_t namePtr = 0;
                if (!SafeRead(hProc, classDescPtr + instanceOffsets.ClassName, &namePtr, sizeof(namePtr), got) || got != sizeof(namePtr)) continue;
                if (!IsPointerValid(hProc, namePtr)) continue;
                auto name = ReadStringSafe(hProc, namePtr);
                if (name && *name == "NetworkClient") {
                    networkClientPtr = candidate;
                    networkClientOffset = off;
                    LOG_OK("NetworkClient found via container scan at 0x" + ToHex(networkClientPtr) +
                        " (vector offset 0x" + ToHex(off) + " in DataModel)");
                    break;
                }
            }
            if (networkClientPtr) break;
        }
    }

    if (!networkClientPtr) {
        LOG_INFO("Container scan missed, performing flat pointer scan...");
        const uint32_t MAX_SCAN = 0x1000;
        for (uint32_t off = 0x20; off < MAX_SCAN; off += 8) {
            uintptr_t ptr = 0;
            SIZE_T got;
            if (!SafeRead(hProc, dataModelPtr + off, &ptr, sizeof(ptr), got) || got != sizeof(ptr)) continue;
            if (!IsPointerValid(hProc, ptr)) continue;
            uintptr_t classDescPtr = 0;
            if (!SafeRead(hProc, ptr + instanceOffsets.ClassDescriptor, &classDescPtr, sizeof(classDescPtr), got) || got != sizeof(classDescPtr)) continue;
            if (!IsPointerValid(hProc, classDescPtr)) continue;
            uintptr_t namePtr = 0;
            if (!SafeRead(hProc, classDescPtr + instanceOffsets.ClassName, &namePtr, sizeof(namePtr), got) || got != sizeof(namePtr)) continue;
            if (!IsPointerValid(hProc, namePtr)) continue;
            auto str = ReadStringSafe(hProc, namePtr);
            if (str && *str == "NetworkClient") {
                networkClientPtr = ptr;
                networkClientOffset = off;
                LOG_OK("NetworkClient found via flat ClassName scan at 0x" + ToHex(networkClientPtr) +
                    " (offset 0x" + ToHex(off) + " in DataModel)");
                break;
            }
        }
    }

    if (!networkClientPtr) {
        LOG_WARN("NetworkClient not found (all methods exhausted)");
    }

    // 3. Scan for JobId and ServerIP independently (No Cross-Contamination)
    const uint32_t MAX_SCAN = 0x4000;

    // Prioritize scanning DataModel first as standard practice, then use NetworkClient as fallback object
    std::vector<std::pair<uintptr_t, std::string>> targets;
    targets.push_back({ dataModelPtr, "DataModel" });
    if (networkClientPtr) targets.push_back({ networkClientPtr, "NetworkClient" });

    // Find JobId Loop
    for (const auto& [obj, objName] : targets) {
        LOG_INFO("Scanning " + objName + " for JobId (8-byte alignment)...");
        for (uint32_t off = 0x20; off < MAX_SCAN; off += 8) {
            auto str = ReadStringSSO(hProc, obj + off);
            if (str && IsValidUUID(*str)) {
                res.JobId = off;
                LOG_OK("JobId offset found in " + objName + ": 0x" + ToHex(off));
                break;
            }
        }
        if (res.JobId) break;
    }

    // Find ServerIP Loop
    for (const auto& [obj, objName] : targets) {
        LOG_INFO("Scanning " + objName + " for ServerIP (8-byte alignment)...");
        for (uint32_t off = 0x20; off < MAX_SCAN; off += 8) {
            auto str = ReadStringSSO(hProc, obj + off);
            if (str && IsValidIP(*str)) {
                res.ServerIP = off;
                LOG_OK("ServerIP offset found in " + objName + ": 0x" + ToHex(off));
                break;
            }
        }
        if (res.ServerIP) break;
    }

    if (!res.JobId)    LOG_WARN("JobId offset could not be dynamically resolved.");
    if (!res.ServerIP) LOG_WARN("ServerIP offset could not be dynamically resolved.");

    res.Valid = true;
    LOG_OK("DataModel properties discovery completed.");
    return res;
}