// =============================================================================
//  Script.hpp  –  Dynamic discovery for ModuleScript, LocalScript, and ByteCode
// =============================================================================
#pragma once
#include "../Core.hpp"
#include "Instance.hpp"
#include <cstdint>
#include <vector>
#include <optional>
#include <regex>

struct ScriptOffsets {
    uint32_t ModuleScriptBytecode = 0;
    uint32_t LocalScriptBytecode = 0;
    uint32_t ModuleScriptHash = 0;
    uint32_t LocalScriptHash = 0;
    uint32_t ByteCodePointer = 0;
    uint32_t ByteCodeSize = 0;
    bool     Valid = false;
};

ScriptOffsets FindScriptOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const InstanceOffsets& instanceOffsets
);