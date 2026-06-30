// =============================================================================
//  OffsetScanner.hpp  –  Generic scanners for floats, ints, bools, strings, objects
// =============================================================================
#pragma once
#include "Core.hpp"
#include <string>
#include <optional>
#include <regex>


// ------------------------------------------------------------------
//  Scan an object's memory for a specific float value
// ------------------------------------------------------------------
uint32_t FindFloatOffset(HANDLE hProc, uintptr_t obj, float target, uint32_t maxOffset = 0x300, uint32_t align = 4);

// ------------------------------------------------------------------
//  Scan an object's memory for a specific integer value (4 bytes)
// ------------------------------------------------------------------
uint32_t FindIntOffset(HANDLE hProc, uintptr_t obj, int target, uint32_t maxOffset = 0x300, uint32_t align = 4);

// ------------------------------------------------------------------
//  Scan an object's memory for a specific boolean (0 or 1)
// ------------------------------------------------------------------
uint32_t FindBoolOffset(HANDLE hProc, uintptr_t obj, bool target, uint32_t maxOffset = 0x300, uint32_t align = 1);

// ------------------------------------------------------------------
//  Scan an object's memory for a pointer to a string matching a pattern
// ------------------------------------------------------------------
uint32_t FindStringOffset(HANDLE hProc, uintptr_t obj, const std::string& target, uint32_t maxOffset = 0x300);

// ------------------------------------------------------------------
//  Scan an object's memory for a pointer to an object with a specific VTable
// ------------------------------------------------------------------
uint32_t FindObjectOffset(HANDLE hProc, uintptr_t obj, const PEInfo& pe, uintptr_t targetVtable, uint32_t maxOffset = 0x200);

// ------------------------------------------------------------------
//  Scan an object's memory for a pointer to a string matching a regex
// ------------------------------------------------------------------
uint32_t FindStringRegexOffset(HANDLE hProc, uintptr_t obj, const std::regex& pattern, uint32_t maxOffset = 0x300);

uint64_t FindInt64Offset(HANDLE hProc, uintptr_t obj, uint64_t target, uint32_t maxOffset = 0x1000, uint32_t align = 8);