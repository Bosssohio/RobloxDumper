#pragma once
#include "../Core.hpp"
#include <vector>
#include <optional>
#include <cstdint>
#include <string>
#include <unordered_set>

struct SingletonCandidate {
    uintptr_t instrVA, targetRVA;
    int score;
    std::string mnemonic;
};

struct StructField {
    uintptr_t instrRVA;
    uint32_t offset;
    std::string note;
    uint32_t stride = 0;
    bool isContainer = false;
    uint32_t containerBegin = 0;
    uint32_t containerEnd = 0;
};

std::vector<SingletonCandidate> ResolveSingleton(
    const std::vector<uint8_t>& text,
    uintptr_t textBase,
    uintptr_t moduleBase,
    const PEInfo& pe,
    const std::vector<StringHit>& stringHits);

std::vector<StructField> AnalyzeStructFields(
    const std::vector<uint8_t>& text,
    uintptr_t textBase,
    uintptr_t moduleBase,
    const SingletonCandidate& best);

std::optional<uint32_t> FindJobNameOffset(HANDLE hProc, uintptr_t taskSchedulerObj, uint32_t jobStartOffset);

std::optional<uint32_t> FindMaxFpsOffset(HANDLE hProc, uintptr_t taskSchedulerObj, size_t maxSize = 0x1000);