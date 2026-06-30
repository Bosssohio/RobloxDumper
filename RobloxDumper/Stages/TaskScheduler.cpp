
#include "TaskScheduler.hpp"
#include <algorithm>
#include <map>
#include <cmath>


//scan important for this
static const std::unordered_set<std::string> kKnownJobNames = {
    "WorkspaceTaskQueue", "PerformanceControlCoordinatorV2Job", "NotifyAliveJob",
    "LuaGc", "WaitingHybridScriptsJob", "ClearUnusedLuaRefsJob", "LuauTelemetry",
    "DataModelCharacterTaskQueue", "TimerTickerJob", "MemoryPrioritizationJob",
    "PerformanceControlOrchestrator", "Write Marshalled", "Read Marshalled",
    "None Marshalled", "ThumbnailFetchJob", "Sound", "LogServiceJob",
    "HttpRbxApiJob", "Simulation", "Heartbeat", "AnalyticsServiceJob",
    "HumanoidParallelManagerTaskQueue", "AnimatorParallelManagerTaskQueue",
    "ScriptContextTaskQueue", "EventBroadcastrelayFireEventJob", "Video",
    "RenderJob", "Replicator ProcessPackets", "Network Quality Responder",
    "PreRenderJob", "SceneUpdaterTaskQueue", "SmoothClusterTaskQueue",
    "DummyClient Event Processor", "Network Disconnect Clean Up",
    "Allocate Bandwidth and Run Senders", "ScopeCheckCleanupJob",
    "AvatarCreationServiceJob", "Net PacketReceive", "Net Peer Send",
    "Net Peer Stats", "MegaReplicatorPPRTaskQueue", "MegaReplicatorTaskQueue",
    "DynamicTranslationSender_LocalizationService", "LocalizationTableAnalyticsSender_LocalizationService"
};

static std::string GetSectionName(const PEInfo& pe, uintptr_t va) {
    for (const auto& s : pe.sections) {
        uintptr_t start = pe.moduleBase + s.rva;
        uintptr_t end = start + s.virtualSize;
        if (va >= start && va < end) return std::string(s.name);
    }
    return "unknown";
}

std::vector<SingletonCandidate> ResolveSingleton(
    const std::vector<uint8_t>& text,
    uintptr_t textBase,
    uintptr_t moduleBase,
    const PEInfo& pe,
    const std::vector<StringHit>& stringHits)
{
    std::vector<SingletonCandidate> res;
    if (stringHits.empty()) return res;
    uintptr_t stringVA = stringHits[0].va;

    std::vector<uintptr_t> stringRefInstrs;
    for (size_t i = 0; i + 7 <= text.size(); i++) {
        const uint8_t* b = text.data() + i;
        if ((b[0] == 0x48 || b[0] == 0x4C) && (b[1] == 0x8B || b[1] == 0x8D) && (b[2] & 0xC7) == 0x05) {
            int32_t disp = *(int32_t*)(b + 3);
            uintptr_t instrVA = textBase + i;
            uintptr_t resolved = instrVA + 7 + disp;
            if (resolved == stringVA) {
                stringRefInstrs.push_back(instrVA);
            }
        }
    }

    for (uintptr_t refVA : stringRefInstrs) {
        size_t offset = refVA - textBase;
        size_t start = (offset > 256) ? offset - 256 : 0;
        for (size_t i = start; i < offset; i++) {
            const uint8_t* b = text.data() + i;
            if ((b[0] == 0x48 || b[0] == 0x4C) && (b[1] == 0x8B || b[1] == 0x8D) && (b[2] & 0xC7) == 0x05) {
                int32_t disp = *(int32_t*)(b + 3);
                uintptr_t instrVA = textBase + i;
                uintptr_t target = instrVA + 7 + disp;
                std::string sec = GetSectionName(pe, target);
                if (sec == ".data" || sec == ".rdata") {
                    int score = 10;
                    if (i + 7 + 3 < text.size() && text[i + 7] == 0x48 && text[i + 8] == 0x85) score += 5;
                    SingletonCandidate c{ instrVA, target - moduleBase, score,
                                          (b[1] == 0x8B) ? "MOV [RIP+d32]" : "LEA [RIP+d32]" };
                    res.push_back(c);
                }
            }
        }
    }

    std::sort(res.begin(), res.end(), [](const auto& a, const auto& b) { return a.score > b.score; });
    return res;
}

std::vector<StructField> AnalyzeStructFields(
    const std::vector<uint8_t>& text,
    uintptr_t textBase,
    uintptr_t moduleBase,
    const SingletonCandidate& best)
{
    std::vector<StructField> res;
    if (best.instrVA == 0) return res;

    size_t startOff = (best.instrVA - textBase) + 7;
    size_t endOff = std::min(startOff + 2048, text.size());

    uint32_t detectedStride = 0;
    for (size_t i = startOff; i + 3 <= endOff; i++) {
        const uint8_t* b = text.data() + i;
        if (b[0] == 0x83 && (b[1] & 0xC0) == 0xC0 && (b[1] & 0x38) == 0x00) {
            uint8_t imm8 = b[2];
            if (imm8 == 0x10 || imm8 == 0x08 || imm8 == 0x18 || imm8 == 0x20 || imm8 == 0x24) {
                detectedStride = imm8;
                break;
            }
        }
        if (b[0] == 0x48 && b[1] == 0x81 && (b[2] & 0xC7) == 0xC0 && i + 7 <= endOff) {
            uint32_t imm32 = *(uint32_t*)(b + 3);
            if (imm32 == 0x10 || imm32 == 0x08 || imm32 == 0x18 || imm32 == 0x20 || imm32 == 0x24) {
                detectedStride = (uint32_t)imm32;
                break;
            }
        }
    }

    std::unordered_map<uint32_t, bool> seen;
    for (size_t i = startOff; i < endOff; i++) {
        const uint8_t* b = text.data() + i;
        if ((b[0] == 0x48 || b[0] == 0x4C) && (b[1] == 0x8B || b[1] == 0x8D)) {
            uint8_t modrm = b[2];
            uint32_t off = 0;
            if ((modrm & 0xC0) == 0x80) off = *(uint32_t*)(b + 3);
            else if ((modrm & 0xC0) == 0x40) off = (uint32_t)(uint8_t)b[3];
            else continue;
            if (off == 0 || off >= 0x1000 || seen.count(off)) continue;
            seen[off] = true;
            StructField f;
            f.instrRVA = (textBase + i) - moduleBase;
            f.offset = off;
            f.stride = detectedStride;
            f.isContainer = false;
            f.containerBegin = 0;
            f.containerEnd = 0;
            std::string note = "field";
            if (off >= 0x100 && off <= 0x300) note = "mid struct field";
            else if (off < 0x100) note = "small field";
            if (detectedStride) note += " stride=0x" + std::to_string(detectedStride);
            f.note = note;
            res.push_back(f);
        }
    }

    std::unordered_map<uint32_t, size_t> offsetToIdx;
    for (size_t i = 0; i < res.size(); i++) offsetToIdx[res[i].offset] = i;

    std::map<uint32_t, uint32_t> containerPairs;
    for (auto& f : res) {
        if (offsetToIdx.count(f.offset + 8)) {
            size_t idx2 = offsetToIdx[f.offset + 8];
            f.isContainer = true;
            f.containerBegin = f.offset;
            f.containerEnd = f.offset + 8;
            res[idx2].isContainer = true;
            res[idx2].containerBegin = f.offset;
            res[idx2].containerEnd = f.offset + 8;
            f.note += " [BEGIN/END PAIR → std::vector<> or array]";
            res[idx2].note += " [BEGIN/END PAIR → std::vector<> or array]";
            containerPairs[f.offset] = f.offset + 8;
        }
    }

    LOG_INFO("Found " + std::to_string(containerPairs.size()) + " container pairs");
    for (auto& [begin, end] : containerPairs) {
        LOG_STEP("Begin=0x" + ToHex(begin, 4) + " End=0x" + ToHex(end, 4));
    }

    std::sort(res.begin(), res.end(), [](const StructField& a, const StructField& b) { return a.offset < b.offset; });
    return res;
}

static std::optional<std::string> ReadSSOString(HANDLE hProc, uintptr_t addr) {
    uint8_t buf[32] = { 0 };
    SIZE_T got = 0;
    if (!SafeRead(hProc, addr, buf, sizeof(buf), got) || got < 0x18) return std::nullopt;

    size_t len = 0;
    memcpy(&len, buf + 0x10, sizeof(size_t));
    if (len == 0 || len > 256) return std::nullopt;

    if (len < 16) {
        return std::string((char*)buf, len);
    }
    else {
        uintptr_t ptr = 0;
        memcpy(&ptr, buf, sizeof(uintptr_t));
        if (ptr == 0) return std::nullopt;
        std::vector<char> str(len + 1, 0);
        if (!SafeRead(hProc, ptr, str.data(), len, got) || got < len) return std::nullopt;
        return std::string(str.data(), len);
    }
}

std::optional<uint32_t> FindJobNameOffset(HANDLE hProc, uintptr_t taskSchedulerObj, uint32_t jobStartOffset) {
    uintptr_t jobStartPtr = 0;
    SIZE_T got = 0;
    if (!SafeRead(hProc, taskSchedulerObj + jobStartOffset, &jobStartPtr, 8, got) || got != 8 || jobStartPtr == 0) {
        LOG_WARN("Failed to read jobStart pointer");
        return std::nullopt;
    }
    uintptr_t jobEndPtr = 0;
    if (!SafeRead(hProc, taskSchedulerObj + jobStartOffset + 0x8, &jobEndPtr, 8, got) || got != 8) {
        LOG_WARN("Failed to read jobEnd pointer");
        return std::nullopt;
    }
    if (jobStartPtr >= jobEndPtr) {
        LOG_WARN("jobStart >= jobEnd, no jobs");
        return std::nullopt;
    }

    for (uintptr_t ptr = jobStartPtr; ptr < jobEndPtr; ptr += 8) {
        uintptr_t jobAddr = 0;
        if (!SafeRead(hProc, ptr, &jobAddr, 8, got) || got != 8 || jobAddr < 0x10000) continue;

        for (size_t off = 0; off < 0x200; off += 8) {
            auto str = ReadSSOString(hProc, jobAddr + off);
            if (!str || str->empty()) continue;
            if (kKnownJobNames.find(*str) != kKnownJobNames.end()) {
                LOG_OK("Found known job name \"" + *str + "\" at offset 0x" + ToHex(off, 4));
                return (uint32_t)off;
            }
        }
    }
    LOG_WARN("No known job name found");
    return std::nullopt;
}

std::optional<uint32_t> FindMaxFpsOffset(HANDLE hProc, uintptr_t taskSchedulerObj, size_t maxSize) {
    const double target = 1.0 / 60.0;
    const double eps = 1e-9;
    uint8_t buf[0x1000] = { 0 };
    SIZE_T got = 0;
    if (!SafeRead(hProc, taskSchedulerObj, buf, std::min(maxSize, sizeof(buf)), got) || got < sizeof(double)) {
        LOG_WARN("Failed to read TaskScheduler memory");
        return std::nullopt;
    }

    for (size_t off = 0; off + sizeof(double) <= got; off += 4) {
        double val = 0;
        memcpy(&val, buf + off, sizeof(double));
        if (fabs(val - target) < eps) {
            LOG_OK("Found MaxFps double at offset 0x" + ToHex(off, 4));
            return (uint32_t)off;
        }
    }
    LOG_WARN("MaxFps double not found");
    return std::nullopt;
}
