#pragma once
#include "../Core.hpp"
#include <optional>
#include <cstdint>

std::optional<uint32_t> FindOffsetInObjectByRTTI(
    HANDLE hProc,
    const PEInfo& pe,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf,
    uintptr_t objectAddr,
    const std::string& targetRTTI,
    size_t maxSize = 0x4000);