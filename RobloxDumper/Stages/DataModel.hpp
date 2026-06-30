// =============================================================================
//  DataModel.hpp  –  Dynamic discovery of DataModel properties
// =============================================================================
#pragma once
#include "../Core.hpp"
#include "Instance.hpp"
#include <cstdint>
#include <vector>
#include <optional>

// ---------------------------------------------------------------------------
//  DataModelOffsets
//    Holds the discovered offsets for the DataModel object.
//    All offsets are relative to the DataModel instance address.
// ---------------------------------------------------------------------------
struct DataModelOffsets {
    uint32_t GameLoaded = 0;          // bool (uint32_t, value 31 when loaded)
    uint32_t JobId = 0;              // pointer to std::string (UUID)
    uint32_t ServerIP = 0;           // pointer to std::string (IP:PORT)
    uint32_t GameId = 0;             // uint64_t (optional, requires control server)
    uint32_t PlaceId = 0;            // uint64_t (optional)
    uint32_t CreatorId = 0;          // uint64_t (optional)
    bool     Valid = false;
};

// ---------------------------------------------------------------------------
//  FindDataModelOffsets
//    - hProc: process handle
//    - dataModelPtr: address of the real DataModel object
//    - instanceOffsets: Instance offsets (needed for ClassName validation)
//    - rdataBuf, dataBuf: section buffers for RTTI lookups
//    - pe: PEInfo for module base
//    Returns a DataModelOffsets structure with discovered offsets.
//    The function uses independent scans for JobId and ServerIP with 8‑byte
//    alignment and proper MSVC string validation (SSO/long strings).
// ---------------------------------------------------------------------------
DataModelOffsets FindDataModelOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const InstanceOffsets& instanceOffsets,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf,
    const PEInfo& pe
);