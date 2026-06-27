// =============================================================================
//  FFlagDumper.cpp  –  With full pointer validation and strict checks
// =============================================================================
#include "FFlagDumper.hpp"
#include <fstream>
#include <unordered_set>

// ------------------------------------------------------------------
//  Helper: validate a user‑mode pointer (committed + readable)
// ------------------------------------------------------------------
static bool IsUserModePointer(HANDLE hProc, uintptr_t ptr) {
    if (ptr < 0x10000 || ptr > 0x00007FFFFFFFFFFF)
        return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProc, (LPCVOID)ptr, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    return true;
}

// ------------------------------------------------------------------
//  Read an SSO string (local copy)
// ------------------------------------------------------------------
static std::optional<std::string> ReadSSOString_local(HANDLE hProc, uintptr_t addr) {
    if (!IsUserModePointer(hProc, addr))
        return std::nullopt;
    uint8_t buf[32] = { 0 };
    SIZE_T got = 0;
    if (!SafeRead(hProc, addr, buf, sizeof(buf), got) || got < 0x18)
        return std::nullopt;
    size_t len = 0;
    memcpy(&len, buf + 0x10, sizeof(size_t));
    if (len == 0 || len > 256)
        return std::nullopt;
    if (len < 16)
        return std::string((char*)buf, len);
    uintptr_t ptr = 0;
    memcpy(&ptr, buf, sizeof(uintptr_t));
    if (!IsUserModePointer(hProc, ptr))
        return std::nullopt;
    std::vector<char> str(len + 1, 0);
    if (!SafeRead(hProc, ptr, str.data(), len, got) || got < len)
        return std::nullopt;
    return std::string(str.data(), len);
}

// ------------------------------------------------------------------
//  Find FFlag offsets
// ------------------------------------------------------------------
std::optional<FFlagOffsets> FindFFlagOffsets(HANDLE hProc, uintptr_t moduleBase) {
    FFlagOffsets offsets;
    LOG_INFO("Scanning for FFlag map...");

    uintptr_t ScanStart = 0x7000000;
    uintptr_t ScanEnd = 0x12000000;
    size_t ChunkSize = 0x1000;

    for (uintptr_t currentOffset = ScanStart; currentOffset < ScanEnd; currentOffset += ChunkSize) {
        size_t BytesToRead = std::min(ChunkSize, ScanEnd - currentOffset);
        std::vector<uint8_t> buffer(BytesToRead);
        SIZE_T got = 0;
        if (!SafeRead(hProc, moduleBase + currentOffset, buffer.data(), BytesToRead, got) || got != BytesToRead) {
            continue;
        }

        uintptr_t* Data = reinterpret_cast<uintptr_t*>(buffer.data());
        size_t AmountOfPointers = BytesToRead / sizeof(uintptr_t);

        for (size_t i = 0; i < AmountOfPointers; i++) {
            uintptr_t MaybeMap = Data[i];
            if (!IsUserModePointer(hProc, MaybeMap))
                continue;

            // Verify it's a map: read first 4 bytes as float; should be 1.0f
            uint32_t floatCheck = 0;
            if (!SafeRead(hProc, MaybeMap, &floatCheck, sizeof(uint32_t), got) || got != sizeof(uint32_t))
                continue;
            if (floatCheck != 0x3F800000)
                continue;

            // Read map start/end pointers
            uintptr_t MapStart = 0;
            if (!SafeRead(hProc, MaybeMap + 0x8, &MapStart, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                continue;
            if (!IsUserModePointer(hProc, MapStart))
                continue;

            uintptr_t MapEnd = 0;
            if (!SafeRead(hProc, MapStart + 0x8, &MapEnd, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                continue;
            if (!IsUserModePointer(hProc, MapEnd))
                continue;

            uintptr_t Current = 0;
            if (!SafeRead(hProc, MapStart, &Current, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                continue;
            if (!IsUserModePointer(hProc, Current))
                continue;

            uintptr_t Wow = currentOffset + (i * sizeof(uintptr_t));
            LOG_OK("Potential FFlag map found at offset: 0x" + ToHex(Wow));

            while (Current != 0 && Current != MapEnd) {
                // Read FFlag name
                std::string Name = ReadSSOString_local(hProc, Current + 0x10).value_or("");
                if (Name.empty()) {
                    uintptr_t Next = 0;
                    if (!SafeRead(hProc, Current, &Next, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                        break;
                    if (!IsUserModePointer(hProc, Next))
                        break;
                    Current = Next;
                    continue;
                }

                if (Name == "BatchThumbnailMinWaitMs") {
                    LOG_OK("Found known FFlag: " + Name);
                    for (uintptr_t TestValueGetSet = 0x20; TestValueGetSet <= 0x100; TestValueGetSet += 0x8) {
                        uintptr_t ValueGetSet = 0;
                        if (!SafeRead(hProc, Current + TestValueGetSet, &ValueGetSet, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                            continue;
                        if (!IsUserModePointer(hProc, ValueGetSet))
                            continue;

                        for (uintptr_t PointerToValueOffset = 0x0; PointerToValueOffset < 0x300; PointerToValueOffset += 0x8) {
                            uintptr_t PointerToValue = 0;
                            if (!SafeRead(hProc, ValueGetSet + PointerToValueOffset, &PointerToValue, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                                continue;
                            if (!IsUserModePointer(hProc, PointerToValue))
                                continue;

                            int Value = 0;
                            if (!SafeRead(hProc, PointerToValue, &Value, sizeof(int), got) || got != sizeof(int))
                                continue;
                            if (Value == 15) {
                                offsets.FFlagList = Wow;
                                offsets.ValueGetSet = TestValueGetSet;
                                offsets.FlagToValue = PointerToValueOffset;
                                LOG_OK("FFlag offsets found: FFlagList=0x" + ToHex(offsets.FFlagList) +
                                    " ValueGetSet=0x" + ToHex(offsets.ValueGetSet) +
                                    " FlagToValue=0x" + ToHex(offsets.FlagToValue));
                                return offsets;
                            }
                        }
                    }
                }

                uintptr_t NewCurrent = 0;
                if (!SafeRead(hProc, Current, &NewCurrent, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                    break;
                if (!IsUserModePointer(hProc, NewCurrent))
                    break;
                if (Current == NewCurrent)
                    break;
                Current = NewCurrent;
            }
        }
    }

    LOG_ERR("FFlag map not found");
    return std::nullopt;
}

// ------------------------------------------------------------------
//  Dump FFlags
// ------------------------------------------------------------------
std::vector<FFlagEntry> DumpFFlagsWithOffsets(HANDLE hProc, uintptr_t moduleBase, const FFlagOffsets& offsets) {
    std::vector<FFlagEntry> flags;
    LOG_INFO("Dumping FFlags using offsets...");

    uintptr_t FFlagPointer1 = 0;
    SIZE_T got = 0;
    if (!SafeRead(hProc, moduleBase + offsets.FFlagList, &FFlagPointer1, sizeof(uintptr_t), got) || got != sizeof(uintptr_t)) {
        LOG_ERR("Failed to read FFlagPointer1");
        return flags;
    }
    if (!IsUserModePointer(hProc, FFlagPointer1)) {
        LOG_ERR("FFlagPointer1 is invalid");
        return flags;
    }

    uintptr_t FFlagList = 0;
    if (!SafeRead(hProc, FFlagPointer1 + 0x8, &FFlagList, sizeof(uintptr_t), got) || got != sizeof(uintptr_t)) {
        LOG_ERR("Failed to read FFlagList");
        return flags;
    }
    if (!IsUserModePointer(hProc, FFlagList)) {
        LOG_ERR("FFlagList is invalid");
        return flags;
    }

    uintptr_t Last = 0;
    if (!SafeRead(hProc, FFlagList + 0x8, &Last, sizeof(uintptr_t), got) || got != sizeof(uintptr_t)) {
        LOG_ERR("Failed to read Last");
        return flags;
    }
    if (!IsUserModePointer(hProc, Last)) {
        LOG_ERR("Last is invalid");
        return flags;
    }

    uintptr_t Current = FFlagList;
    std::unordered_set<std::string> seenNames;

    while (Current != 0 && Current != Last) {
        std::string Name = ReadSSOString_local(hProc, Current + 0x10).value_or("");
        if (Name.empty() || seenNames.count(Name)) {
            uintptr_t Next = 0;
            if (!SafeRead(hProc, Current, &Next, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                break;
            if (!IsUserModePointer(hProc, Next))
                break;
            Current = Next;
            continue;
        }
        seenNames.insert(Name);

        uintptr_t ValueGetSet = 0;
        if (!SafeRead(hProc, Current + offsets.ValueGetSet, &ValueGetSet, sizeof(uintptr_t), got) || got != sizeof(uintptr_t)) {
            uintptr_t Next = 0;
            if (!SafeRead(hProc, Current, &Next, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                break;
            if (!IsUserModePointer(hProc, Next))
                break;
            Current = Next;
            continue;
        }
        if (!IsUserModePointer(hProc, ValueGetSet)) {
            uintptr_t Next = 0;
            if (!SafeRead(hProc, Current, &Next, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                break;
            if (!IsUserModePointer(hProc, Next))
                break;
            Current = Next;
            continue;
        }

        uintptr_t valueAddr = 0;
        if (!SafeRead(hProc, ValueGetSet + offsets.FlagToValue, &valueAddr, sizeof(uintptr_t), got) || got != sizeof(uintptr_t)) {
            uintptr_t Next = 0;
            if (!SafeRead(hProc, Current, &Next, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                break;
            if (!IsUserModePointer(hProc, Next))
                break;
            Current = Next;
            continue;
        }
        // ★ Strict validation: reject kernel addresses and invalid user-mode addresses
        if (!IsUserModePointer(hProc, valueAddr) || valueAddr == 0 || valueAddr == 0xFFFFFFFFFFFFFFFF) {
            uintptr_t Next = 0;
            if (!SafeRead(hProc, Current, &Next, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
                break;
            if (!IsUserModePointer(hProc, Next))
                break;
            Current = Next;
            continue;
        }

        std::string type = "unknown";
        std::string value;

        uint8_t boolVal = 0;
        if (SafeRead(hProc, valueAddr, &boolVal, 1, got) && got == 1) {
            if (boolVal == 0 || boolVal == 1) {
                type = "bool";
                value = boolVal ? "true" : "false";
            }
        }
        if (value.empty()) {
            int32_t intVal = 0;
            if (SafeRead(hProc, valueAddr, &intVal, 4, got) && got == 4) {
                type = "int";
                value = std::to_string(intVal);
            }
        }
        if (value.empty()) {
            float floatVal = 0;
            if (SafeRead(hProc, valueAddr, &floatVal, 4, got) && got == 4) {
                type = "float";
                value = std::to_string(floatVal);
            }
        }
        if (value.empty()) {
            uintptr_t strPtr = 0;
            if (SafeRead(hProc, valueAddr, &strPtr, 8, got) && got == 8 && IsUserModePointer(hProc, strPtr)) {
                std::string str = ReadSSOString_local(hProc, strPtr).value_or("");
                if (!str.empty()) {
                    type = "string";
                    value = str;
                }
            }
        }
        if (value.empty()) {
            value = "<unknown>";
            type = "unknown";
        }

        FFlagEntry entry;
        entry.name = Name;
        entry.value = value;
        entry.type = type;
        entry.address = valueAddr;   // Safe: we validated valueAddr
        entry.isEncrypted = false;
        flags.push_back(entry);

        uintptr_t Next = 0;
        if (!SafeRead(hProc, Current, &Next, sizeof(uintptr_t), got) || got != sizeof(uintptr_t))
            break;
        if (!IsUserModePointer(hProc, Next))
            break;
        Current = Next;
    }

    LOG_OK("Dumped " + std::to_string(flags.size()) + " FFlags");
    return flags;
}

// ------------------------------------------------------------------
//  Write FFlags to files
// ------------------------------------------------------------------
void WriteFFlags(const std::vector<FFlagEntry>& flags, const std::string& txtPath, const std::string& jsonPath) {
    std::ofstream txt(txtPath);
    if (txt.is_open()) {
        txt << "// Roblox FastFlags dumped from live process\n";
        txt << "// Total: " << flags.size() << "\n\n";
        for (const auto& f : flags) {
            txt << f.name << " = " << f.value;
            if (f.type != "unknown") txt << "  // type: " << f.type;
            if (f.isEncrypted) txt << " [ENCRYPTED]";
            txt << "\n";
        }
        txt.close();
        LOG_OK("FFlags written to " + txtPath);
    }
    std::ofstream json(jsonPath);
    if (json.is_open()) {
        json << "{\n  \"tool\": \"RobloxDumper\",\n  \"totalFlags\": " << flags.size() << ",\n  \"flags\": [\n";
        for (size_t i = 0; i < flags.size(); i++) {
            const auto& f = flags[i];
            json << "    { \"name\": \"" << f.name << "\", \"value\": \"" << f.value << "\", \"type\": \"" << f.type << "\", \"address\": \"" << ToHex(f.address) << "\", \"encrypted\": " << (f.isEncrypted ? "true" : "false") << " }";
            if (i + 1 < flags.size()) json << ",";
            json << "\n";
        }
        json << "  ]\n}\n";
        json.close();
        LOG_OK("FFlags JSON written to " + jsonPath);
    }
}