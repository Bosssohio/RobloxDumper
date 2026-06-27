// =============================================================================
//  Instance.hpp  –  Fully dynamic offset discovery (no hardcoded offsets)
// =============================================================================
#pragma once
#include "../Core.hpp"
#include <string>
#include <vector>
#include <optional>
#include <ostream>

struct InstanceOffsets {
    uint32_t ChildrenStart = 0;    // offset in DataModel to the begin pointer
    uint32_t ChildrenEnd = 0;      // offset from firstChild to the end pointer (e.g., 0x8)
    uint32_t Parent = 0;           // offset in Workspace to the DataModel pointer
    uint32_t Name = 0;             // offset in Instance to the Name string
    uint32_t ClassDescriptor = 0;  // offset in Instance to the ClassDescriptor pointer (e.g., 0x18)
    uint32_t ClassName = 0;        // offset in ClassDescriptor to the class name string (e.g., 0x8)
    uint32_t Attributes = 0;       // child count (used for tree dump)
    bool     Valid = false;
    uintptr_t WorkspacePtr = 0;
    uintptr_t DataModelPtr = 0;
};

InstanceOffsets FindInstanceOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const std::vector<uint8_t>& rdataBuf,
    const std::vector<uint8_t>& dataBuf
);

void DumpInstanceTree(
    HANDLE hProc,
    uintptr_t rootInstancePtr,
    const InstanceOffsets& offsets,
    std::ostream& out,
    int depth = 0
);