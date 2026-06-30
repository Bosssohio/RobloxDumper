// =============================================================================
//  Workspace.cpp  –  Fully dynamic Workspace offsets (triple‑sample time gate)
// =============================================================================
#include "Workspace.hpp"
#include "../OffsetScanner.hpp"
#include <cmath>
#include <chrono>
#include <thread>
#include <vector>
#include <algorithm>

// ------------------------------------------------------------------
//  Helper: find pointer to a structure containing a specific float (gravity)
// ------------------------------------------------------------------
static std::optional<std::pair<uint32_t, uint32_t>> find_offset_to_float_pointer(
    HANDLE hProc,
    uintptr_t objectPtr,
    float targetFloat,
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
            float val = 0.0f;
            if (SafeRead(hProc, ptr + valOff, &val, sizeof(val), got) && got == sizeof(val)) {
                if (fabs(val - targetFloat) < 0.01f) {
                    return std::make_pair(ptrOff, valOff);
                }
            }
        }
    }
    return std::nullopt;
}

// ------------------------------------------------------------------
//  Helper: find object by class name (for CurrentCamera)
// ------------------------------------------------------------------
static uint32_t FindObjectByClassName(
    HANDLE hProc,
    uintptr_t parentPtr,
    const InstanceOffsets& offsets,
    const std::string& className,
    uint32_t minOffset = 0x20,
    uint32_t maxOffset = 0x600,
    uint32_t stride = 8)
{
    SIZE_T got;
    for (uint32_t off = minOffset; off < maxOffset; off += stride) {
        uintptr_t childPtr = 0;
        if (!SafeRead(hProc, parentPtr + off, &childPtr, sizeof(childPtr), got) || got != sizeof(childPtr) || !childPtr)
            continue;
        if (!IsPointerValid(hProc, childPtr))
            continue;

        uintptr_t classDescPtr = 0;
        if (SafeRead(hProc, childPtr + offsets.ClassDescriptor, &classDescPtr, sizeof(classDescPtr), got) && got == sizeof(classDescPtr) && classDescPtr) {
            uintptr_t namePtr = 0;
            if (SafeRead(hProc, classDescPtr + offsets.ClassName, &namePtr, sizeof(namePtr), got) && got == sizeof(namePtr) && namePtr) {
                auto str = ReadStringSafe(hProc, namePtr);
                if (str && *str == className) {
                    return off;
                }
            }
        }
    }
    return 0;
}

// ------------------------------------------------------------------
//  Triple‑sample time‑gated scanner for DistributedGameTime
//  No hardcoded offsets – purely dynamic.
//  Adjusted EPSILON and MAX_VALUE to handle real‑world environments.
// ------------------------------------------------------------------
static uint32_t FindDistributedGameTime(
    HANDLE hProc,
    uintptr_t obj,
    uint32_t startOff = 0x100,
    uint32_t endOff = 0x2000,
    uint32_t align = 8)
{
    SIZE_T got;
    const double EPSILON = 0.05;           // tolerant of Windows kernel clock granularity (±20‑30ms)
    const double RATIO_TOLERANCE = 0.25;   // absorb frame‑rate quantization
    const double MAX_GAME_TIME = 500000.0; // covers servers running for several days

    // ---- Sample 1: read all doubles, store in a flat vector ----
    std::vector<std::pair<uint32_t, double>> sample1;
    sample1.reserve((endOff - startOff) / align + 1);
    for (uint32_t off = startOff; off <= endOff; off += align) {
        double val = 0.0;
        if (SafeRead(hProc, obj + off, &val, sizeof(val), got) && got == sizeof(val) && val >= 0.0) {
            sample1.emplace_back(off, val);
        }
    }
    if (sample1.empty()) return 0;

    // ---- Sleep 1 (longer duration to absorb frame jitter) ----
    auto t1_start = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    auto t1_end = std::chrono::high_resolution_clock::now();
    double elapsed1 = std::chrono::duration<double>(t1_end - t1_start).count();

    // ---- Sample 2: compute delta1, filter candidates ----
    std::vector<std::tuple<uint32_t, double, double>> candidates; // off, val1, delta1
    for (const auto& [off, val1] : sample1) {
        double val2 = 0.0;
        if (SafeRead(hProc, obj + off, &val2, sizeof(val2), got) && got == sizeof(val2)) {
            double delta1 = val2 - val1;
            if (delta1 > 0.0 && fabs(delta1 - elapsed1) < EPSILON) {
                candidates.emplace_back(off, val1, delta1);
            }
        }
    }
    if (candidates.empty()) return 0;

    // ---- Sleep 2 (significantly different duration) ----
    auto t2_start = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(350));
    auto t2_end = std::chrono::high_resolution_clock::now();
    double elapsed2 = std::chrono::duration<double>(t2_end - t2_start).count();

    // ---- Sample 3: validate scaling ratio ----
    double bestScore = -1.0;
    uint32_t bestOff = 0;

    for (const auto& [off, val1, delta1] : candidates) {
        double val3 = 0.0;
        if (SafeRead(hProc, obj + off, &val3, sizeof(val3), got) && got == sizeof(val3)) {
            double totalDelta = val3 - val1;
            double delta2_actual = totalDelta - delta1;
            if (delta2_actual > 0.0) {
                double ratioMemory = delta2_actual / delta1;
                double ratioTime = elapsed2 / elapsed1;
                if (fabs(ratioMemory - ratioTime) < RATIO_TOLERANCE) {
                    // Verify the game time is in a reasonable range (handles long‑running servers)
                    if (val3 > 0.0 && val3 < MAX_GAME_TIME) {
                        double score = 1.0 / (fabs(delta1 - elapsed1) + fabs(delta2_actual - elapsed2) + 1e-6);
                        if (score > bestScore) {
                            bestScore = score;
                            bestOff = off;
                        }
                    }
                }
            }
        }
    }

    return bestOff;
}

// ------------------------------------------------------------------
//  Main discovery function
// ------------------------------------------------------------------
WorkspaceOffsets FindWorkspaceOffsets(
    HANDLE hProc,
    uintptr_t workspacePtr,
    const InstanceOffsets& instanceOffsets)
{
    WorkspaceOffsets res;
    res.Valid = false;

    if (!workspacePtr || !instanceOffsets.Valid) {
        LOG_ERR("Workspace or Instance offsets not available");
        return res;
    }

    LOG_INFO("Discovering Workspace offsets...");

    // 1. CurrentCamera – find by class name
    uint32_t camOff = FindObjectByClassName(hProc, workspacePtr, instanceOffsets, "Camera", 0x20, 0x600, 8);
    if (camOff) {
        res.CurrentCamera = camOff;
        LOG_OK("CurrentCamera offset: 0x" + ToHex(camOff));
    }
    else {
        LOG_WARN("CurrentCamera not found");
    }

    // 2. World – find pointer to gravity structure (196.2f)
    LOG_INFO("Searching for World via gravity pointer...");
    auto result = find_offset_to_float_pointer(hProc, workspacePtr, 196.2f, 0x1000, 0x800, 0x8, 0x4);
    if (result) {
        res.World = result->first;
        LOG_OK("World offset: 0x" + ToHex(res.World));
    }
    else {
        LOG_WARN("World not found");
    }

    // 3. DistributedGameTime – triple‑sample time gating (pure dynamic)
    LOG_INFO("Scanning for DistributedGameTime using triple‑sample scaling...");
    uint32_t timeOff = FindDistributedGameTime(hProc, workspacePtr, 0x100, 0x2000, 8);
    if (timeOff) {
        res.DistributedGameTime = timeOff;
        LOG_OK("DistributedGameTime offset: 0x" + ToHex(timeOff));
    }
    else {
        LOG_WARN("DistributedGameTime not found");
    }

    res.Valid = (res.CurrentCamera != 0 || res.World != 0 || res.DistributedGameTime != 0);
    if (res.Valid) {
        LOG_OK("Workspace offsets discovered successfully");
    }
    else {
        LOG_ERR("Failed to discover any Workspace offsets");
    }
    return res;
}