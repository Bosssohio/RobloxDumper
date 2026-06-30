
#pragma once
#include "../Core.hpp"
#include "Instance.hpp"
#include <cstdint>
#include <vector>
#include <optional>

struct DataModelOffsets {
    uint32_t GameLoaded = 0;          // bool (uint32_t, value 31 when loaded)
    uint32_t JobId = 0;              // pointer to std::string (UUID)
    uint32_t ServerIP = 0;           // pointer to std::string (IP:PORT)
    uint32_t GameId = 0;             // uint64_t (optional, requires control server if existed)
    uint32_t PlaceId = 0;            // uint64_t (optional)
    uint32_t CreatorId = 0;          // uint64_t (optional)
    bool     Valid = false;
};

DataModelOffsets FindDataModelOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const InstanceOffsets& instanceOffsets,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf,
    const PEInfo& pe
);