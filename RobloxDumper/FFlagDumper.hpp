// =============================================================================
//  FFlagDumper.hpp  – FFlag offset discovery, dump, file writing
// =============================================================================
#pragma once
#include "Core.hpp"
#include <vector>
#include <string>

struct FFlagOffsets {
    uintptr_t FFlagList = 0;
    uintptr_t ValueGetSet = 0;
    uintptr_t FlagToValue = 0;
};

struct FFlagEntry {
    std::string name;
    std::string value;
    std::string type;
    uintptr_t address;
    bool isEncrypted;
};

std::optional<FFlagOffsets> FindFFlagOffsets(HANDLE hProc, uintptr_t moduleBase);
std::vector<FFlagEntry> DumpFFlagsWithOffsets(HANDLE hProc, uintptr_t moduleBase, const FFlagOffsets& offsets);
void WriteFFlags(const std::vector<FFlagEntry>& flags, const std::string& txtPath, const std::string& jsonPath);