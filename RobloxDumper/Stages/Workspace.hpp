#pragma once
#include "../Core.hpp"
#include "Instance.hpp"
#include <cstdint>
#include <vector>
#include <optional>

struct WorkspaceOffsets {
    uint32_t CurrentCamera = 0;        // pointer to Camera object
    uint32_t World = 0;                // pointer to World object
    uint32_t DistributedGameTime = 0;  // float (increases over time)
    bool     Valid = false;
};

WorkspaceOffsets FindWorkspaceOffsets(
    HANDLE hProc,
    uintptr_t workspacePtr,
    const InstanceOffsets& instanceOffsets
);