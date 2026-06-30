// =============================================================================
//  DataModel.cpp
// =============================================================================
#include "DataModel.hpp"
#include <cstring>
#include <algorithm>

std::optional<uint32_t> FindOffsetInObjectByRTTI(
    HANDLE hProc,
    const PEInfo& pe,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf,
    uintptr_t objectAddr,
    const std::string& targetRTTI,
    size_t maxSize)
{
    const SectionInfo* rdataSec = nullptr;
    for (const auto& s : pe.sections) if (strcmp(s.name, ".rdata") == 0) rdataSec = &s;
    if (!rdataSec) { LOG_ERR("Missing .rdata section"); return std::nullopt; }
    uintptr_t rdataStart = pe.moduleBase + rdataSec->rva;
    uintptr_t rdataEnd = rdataStart + rdataSec->virtualSize;

    std::string targetName = targetRTTI;
    if (targetName.rfind(".?AV", 0) == 0) targetName = targetName.substr(4);
    if (targetName.rfind(".?AU", 0) == 0) targetName = targetName.substr(4);
    if (targetName.rfind(".?AW", 0) == 0) targetName = targetName.substr(4);
    if (targetName.rfind(".?AT", 0) == 0) targetName = targetName.substr(4);
    if (targetName.rfind("@@") == targetName.length() - 2) targetName = targetName.substr(0, targetName.length() - 2);

    LOG_INFO("Scanning object at " + ToHex(objectAddr) + " for RTTI containing \"" + targetName + "\"");

    for (uintptr_t off = 0; off < maxSize; off += 8) {
        uintptr_t ptr = 0;
        SIZE_T got = 0;
        if (!SafeRead(hProc, objectAddr + off, &ptr, 8, got) || got != 8 || ptr == 0) continue;
        if ((ptr & 0x7) != 0) continue;
        uintptr_t objVtable = 0;
        if (!SafeRead(hProc, ptr, &objVtable, 8, got) || got != 8) continue;
        if (objVtable < rdataStart || objVtable >= rdataEnd) continue;
        uintptr_t colPtr = 0;
        if (!SafeRead(hProc, objVtable - 8, &colPtr, 8, got) || got != 8 || colPtr == 0) continue;
        if (colPtr < rdataStart || colPtr >= rdataEnd) continue;
        uint32_t sig = 0;
        if (!SafeRead(hProc, colPtr, &sig, 4, got) || got != 4 || sig != 1) continue;
        uint32_t tdRVA = 0;
        if (!SafeRead(hProc, colPtr + 0x0C, &tdRVA, 4, got) || got != 4 || tdRVA == 0) continue;
        uintptr_t tdVA = pe.moduleBase + tdRVA;
        uintptr_t tdVtable = 0;
        if (!SafeRead(hProc, tdVA, &tdVtable, 8, got) || got != 8) continue;
        if (tdVtable < rdataStart || tdVtable >= rdataEnd) continue;
        char name[128] = { 0 };
        if (!SafeRead(hProc, tdVA + 0x10, name, sizeof(name) - 1, got) || got == 0) continue;
        std::string rttiName(name);

        std::string lowerRtti = rttiName;
        std::string lowerTarget = targetName;
        std::transform(lowerRtti.begin(), lowerRtti.end(), lowerRtti.begin(), ::tolower);
        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
        if (lowerRtti.find(lowerTarget) != std::string::npos) {
            LOG_OK("Found FakeDataModel pointer at offset 0x" + ToHex(off, 4));
            return (uint32_t)off;
        }
    }
    LOG_WARN("No pointer to \"" + targetName + "\" found");
    return std::nullopt;
}