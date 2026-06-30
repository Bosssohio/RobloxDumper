
#include "Core.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstdio>

// global 
NtRVM_t g_NtRVM = nullptr;
NtSuspendProcess_t g_NtSuspendProcess = nullptr;
NtResumeProcess_t g_NtResumeProcess = nullptr;
bool g_ForceDecrypt = true;
bool g_SuspendProcess = true;
bool g_verbose = false;

// util
std::string ToHex(uintptr_t v, int w) {
    std::ostringstream s;
    s << std::uppercase << std::hex << std::setw(w) << std::setfill('0') << v;
    return s.str();
}

std::string EscapeCString(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c > 0x7E) {
            char hex[5]; snprintf(hex, sizeof(hex), "\\x%02X", (unsigned char)c);
            out += hex;
        }
        else out += c;
    }
    return out;
}

std::string ToValidIdentifier(const std::string& s) {
    std::string result;
    bool first = true;
    for (char c : s) {
        if (isalnum((unsigned char)c) || c == '_') {
            if (first && isdigit((unsigned char)c)) result += '_';
            result += c;
        }
        else if (c == ' ') result += '_';
        else if (c == '-' || c == '.' || c == ':' || c == '/' || c == '\\') result += '_';
        else if (c == '(' || c == ')' || c == '[' || c == ']') result += '_';
        else result += '_';
        first = false;
    }
    std::string final;
    bool lastUnderscore = false;
    for (char c : result) {
        if (c == '_' && lastUnderscore) continue;
        final += c;
        lastUnderscore = (c == '_');
    }
    if (final.empty()) final = "UnnamedFlag";
    if (final.back() == '_') final.pop_back();
    return final;
}

// memory reading
void InitNtFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        g_NtRVM = (NtRVM_t)GetProcAddress(ntdll, "NtReadVirtualMemory");
        g_NtSuspendProcess = (NtSuspendProcess_t)GetProcAddress(ntdll, "NtSuspendProcess");
        g_NtResumeProcess = (NtResumeProcess_t)GetProcAddress(ntdll, "NtResumeProcess");
    }
}

//can skip invaild memory

bool SEH_RawRead(HANDLE hProc, LPVOID ptr, BYTE* buf, SIZE_T size, SIZE_T& got) {
    got = 0; bool ok = false;
    __try { BOOL r = ReadProcessMemory(hProc, ptr, buf, size, &got); ok = (r && got > 0); if (!ok) got = 0; }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        got = 0; ok = false;
    }
    return ok;
}

bool SEH_NtRead(HANDLE hProc, uintptr_t addr, BYTE* buf, SIZE_T size, SIZE_T& got) {
    got = 0; if (!g_NtRVM) return false; bool ok = false;
    __try { NTSTATUS s = g_NtRVM(hProc, (PVOID)addr, buf, size, (PSIZE_T)&got); ok = (s == 0 && got > 0); if (!ok) got = 0; }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        got = 0; ok = false;
    }
    return ok;
}

bool SafeRead(HANDLE hProc, uintptr_t addr, void* buf, SIZE_T size, SIZE_T& got) {
    got = 0;
    if (g_NtRVM && SEH_NtRead(hProc, addr, (BYTE*)buf, size, got)) return true;
    return SEH_RawRead(hProc, (LPVOID)addr, (BYTE*)buf, size, got);
}

SIZE_T ForceDecryptAndReadPage(HANDLE hProc, uintptr_t va, uint8_t* dst, SIZE_T size) {
    DWORD old = 0; LPVOID ptr = (LPVOID)va;
    if (!VirtualProtectEx(hProc, ptr, size, PAGE_EXECUTE_READWRITE, &old) &&
        !VirtualProtectEx(hProc, ptr, size, PAGE_READWRITE | PAGE_GUARD, &old))
        return 0;
    SIZE_T got = 0; bool ok = SEH_NtRead(hProc, va, dst, size, got) || SEH_RawRead(hProc, ptr, dst, size, got);
    DWORD tmp; VirtualProtectEx(hProc, ptr, size, old, &tmp);
    return ok ? got : 0;
}

// parsing pe!
std::optional<PEInfo> ParsePE(HANDLE hProc, uintptr_t base) {
    IMAGE_DOS_HEADER dos; SIZE_T bytesRead = 0;
    if (!SafeRead(hProc, base, &dos, sizeof(dos), bytesRead) || bytesRead != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return std::nullopt;
    uintptr_t ntAddr = base + dos.e_lfanew;
    IMAGE_NT_HEADERS64 nt;
    if (!SafeRead(hProc, ntAddr, &nt, sizeof(nt), bytesRead) || bytesRead != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE)
        return std::nullopt;
    PEInfo pe;
    pe.moduleBase = base;
    pe.imageSize = nt.OptionalHeader.SizeOfImage;
    pe.entryRVA = nt.OptionalHeader.AddressOfEntryPoint;
    uintptr_t secBase = ntAddr + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER s;
        if (!SafeRead(hProc, secBase + i * sizeof(s), &s, sizeof(s), bytesRead) || bytesRead != sizeof(s)) continue;
        SectionInfo si{};
        memcpy(si.name, s.Name, 8);
        si.rva = s.VirtualAddress;
        si.virtualSize = s.Misc.VirtualSize;
        si.rawOffset = s.PointerToRawData;
        si.rawSize = s.SizeOfRawData;
        si.characteristics = s.Characteristics;
        pe.sections.push_back(si);
    }
    return pe;
}

std::vector<uint8_t> ReadSection(HANDLE hProc, const PEInfo& pe, const SectionInfo& sec, bool decrypt) {
    std::vector<uint8_t> buf(sec.virtualSize, 0x00);
    uintptr_t va = pe.moduleBase + sec.rva;
    SIZE_T done = 0;
    while (done < sec.virtualSize) {
        SIZE_T chunk = std::min((SIZE_T)0x800000, sec.virtualSize - done);
        SIZE_T got = 0;
        if (SEH_NtRead(hProc, va + done, buf.data() + done, chunk, got) ||
            SEH_RawRead(hProc, (LPVOID)(va + done), buf.data() + done, chunk, got)) {
            done += got;
        }
        else {
            for (SIZE_T off = 0; off < chunk; off += 0x1000) {
                SIZE_T pg = std::min((SIZE_T)0x1000, chunk - off);
                SIZE_T g2 = 0;
                if (decrypt && g_ForceDecrypt) {
                    g2 = ForceDecryptAndReadPage(hProc, va + done + off, buf.data() + done + off, pg);
                }
                else {
                    if (!SEH_NtRead(hProc, va + done + off, buf.data() + done + off, pg, g2))
                        SEH_RawRead(hProc, (LPVOID)(va + done + off), buf.data() + done + off, pg, g2);
                }
                done += g2;
            }
        }
    }
    return buf;
}

std::vector<uint8_t> ReadTextGhost(HANDLE hProc, const PEInfo& pe, const SectionInfo& sec) {
    std::vector<uint8_t> buf(sec.virtualSize, 0xCC);
    if (sec.rawOffset > 0 && sec.rawSize > 0) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameExW(hProc, nullptr, path, MAX_PATH)) {
            std::ifstream f(path, std::ios::binary);
            if (f.is_open()) {
                f.seekg(sec.rawOffset);
                size_t readSz = std::min((size_t)sec.rawSize, (size_t)sec.virtualSize);
                f.read((char*)buf.data(), readSz);
            }
        }
    }
    if (g_ForceDecrypt) {
        uintptr_t va = pe.moduleBase + sec.rva;
        for (SIZE_T off = 0; off < sec.virtualSize; off += 0x1000) {
            SIZE_T pgSz = std::min((SIZE_T)0x1000, sec.virtualSize - off);
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQueryEx(hProc, (LPCVOID)(va + off), &mbi, sizeof(mbi))) continue;
            if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
                ForceDecryptAndReadPage(hProc, va + off, buf.data() + off, pgSz);
            }
            else if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                SIZE_T got = 0;
                SEH_NtRead(hProc, va + off, buf.data() + off, pgSz, got) ||
                    SEH_RawRead(hProc, (LPVOID)(va + off), buf.data() + off, pgSz, got);
            }
        }
    }
    return buf;
}

// strings
std::vector<StringHit> ScanPlain(const uint8_t* data, size_t sz, uintptr_t baseVA, const uint8_t* needle, size_t nlen) {
    std::vector<StringHit> r;
    for (size_t i = 0; i + nlen + 1 <= sz; i++) {
        if (memcmp(data + i, needle, nlen) == 0 && data[i + nlen] == 0) {
            r.push_back({ i, baseVA + i, false, 0, "Narrow" });
        }
    }
    return r;
}

std::vector<StringHit> ScanXOR(const uint8_t* data, size_t sz, uintptr_t baseVA, const uint8_t* needle, size_t nlen) {
    std::vector<StringHit> r;
    for (size_t i = 0; i + nlen + 1 <= sz; i++) {
        uint8_t key = data[i] ^ needle[0];
        if (key == 0) continue;
        bool ok = true;
        for (size_t j = 0; j < nlen && ok; j++) if ((data[i + j] ^ key) != needle[j]) ok = false;
        if (ok && (data[i + nlen] ^ key) == 0) r.push_back({ i, baseVA + i, true, key, "NarrowXOR" });
    }
    return r;
}

std::vector<StringHit> DiscoverString(const std::vector<uint8_t>& buf, uintptr_t baseVA, const std::vector<uint8_t>& needle, bool noXor) {
    auto hits = ScanPlain(buf.data(), buf.size(), baseVA, needle.data(), needle.size());
    if (!hits.empty()) return hits;
    if (!noXor) {
        auto xhits = ScanXOR(buf.data(), buf.size(), baseVA, needle.data(), needle.size());
        if (!xhits.empty()) return xhits;
    }
    return {};
}

// rtti
std::optional<RTTIResult> FindRTTI(HANDLE hProc, const PEInfo& pe,
    const std::vector<uint8_t>& rdataBuf, const std::vector<uint8_t>& dataBuf,
    const std::string& typeName) {
    const SectionInfo* rdataSec = nullptr;
    const SectionInfo* dataSec = nullptr;
    for (const auto& s : pe.sections) {
        if (strcmp(s.name, ".rdata") == 0) rdataSec = &s;
        if (strcmp(s.name, ".data") == 0) dataSec = &s;
    }
    if (!rdataSec || !dataSec) {
        LOG_ERR("Missing .rdata or .data section");
        return std::nullopt;
    }
    uintptr_t rdataStart = pe.moduleBase + rdataSec->rva;
    uintptr_t rdataEnd = rdataStart + rdataSec->virtualSize;
    uintptr_t dataStart = pe.moduleBase + dataSec->rva;
    uintptr_t dataEnd = dataStart + dataSec->virtualSize;

    std::vector<uint8_t> needle(typeName.begin(), typeName.end());
    std::vector<uintptr_t> hits;

    auto searchBuf = [&](const std::vector<uint8_t>& buf, uintptr_t baseVA, const std::string& secName) {
        for (size_t i = 0; i + needle.size() + 1 <= buf.size(); i++) {
            if (memcmp(buf.data() + i, needle.data(), needle.size()) == 0 && buf[i + needle.size()] == 0) {
                uintptr_t va = baseVA + i;
                uintptr_t typeDescVA = va - 0x10;
                uintptr_t typeInfoVtable = 0;
                SIZE_T got = 0;
                if (!SafeRead(hProc, typeDescVA, &typeInfoVtable, 8, got) || got != 8) continue;
                bool inRdata = (typeInfoVtable >= rdataStart && typeInfoVtable < rdataEnd);
                bool inData = (typeInfoVtable >= dataStart && typeInfoVtable < dataEnd);
                if (inRdata || inData) {
                    hits.push_back(va);
                }
            }
        }
        };

    searchBuf(rdataBuf, rdataStart, ".rdata");
    searchBuf(dataBuf, dataStart, ".data");

    if (hits.empty()) {
        std::string altName = typeName;
        size_t pos = altName.find("@@");
        if (pos != std::string::npos) {
            altName = altName.substr(0, pos);
            return FindRTTI(hProc, pe, rdataBuf, dataBuf, altName);
        }
        LOG_ERR("RTTI name not found");
        return std::nullopt;
    }

    for (uintptr_t va : hits) {
        uintptr_t typeDescVA = va - 0x10;
        uint32_t typeDescRVA = (uint32_t)(typeDescVA - pe.moduleBase);
        bool foundCOL = false;
        uintptr_t colVA = 0;
        for (size_t off = 0; off + 0x18 <= rdataBuf.size(); off += 4) {
            uint32_t sig = 0; memcpy(&sig, rdataBuf.data() + off, 4);
            if (sig != 1) continue;
            uint32_t tdRVA = 0; memcpy(&tdRVA, rdataBuf.data() + off + 0x0C, 4);
            if (tdRVA != typeDescRVA) continue;
            uint32_t selfRVA = 0; memcpy(&selfRVA, rdataBuf.data() + off + 0x14, 4);
            uintptr_t colVA_candidate = rdataStart + off;
            if (selfRVA == (uint32_t)(colVA_candidate - pe.moduleBase)) {
                colVA = colVA_candidate;
                foundCOL = true;
                break;
            }
        }
        if (!foundCOL) continue;

        uintptr_t vtableRVA = 0;
        for (size_t off = 0; off + 8 <= rdataBuf.size(); off += 8) {
            uintptr_t val = 0; memcpy(&val, rdataBuf.data() + off, 8);
            if (val == colVA) {
                vtableRVA = (uint32_t)(rdataStart + off + 8 - pe.moduleBase);
                break;
            }
        }
        if (!vtableRVA) continue;

        uintptr_t vtableVA = pe.moduleBase + vtableRVA;
        uintptr_t singletonRVA = 0;
        for (size_t off = 0; off + 8 <= dataBuf.size(); off += 8) {
            uintptr_t ptr = 0; memcpy(&ptr, dataBuf.data() + off, 8);
            if (ptr == 0) continue;
            uintptr_t objVtable = 0;
            SIZE_T got = 0;
            if (SafeRead(hProc, ptr, &objVtable, 8, got) && got == 8 && objVtable == vtableVA) {
                singletonRVA = (uint32_t)(dataStart + off - pe.moduleBase);
                break;
            }
        }
        if (!singletonRVA) continue;

        RTTIResult res;
        res.stringVA = va;
        res.typeDescRVA = typeDescRVA;
        res.colRVA = (uint32_t)(colVA - pe.moduleBase);
        res.vtableRVA = vtableRVA;
        res.singletonRVA = singletonRVA;
        res.score = 10;
        return res;
    }
    LOG_ERR("No valid RTTI structure");
    return std::nullopt;
}

std::optional<std::string> ReadRobloxString(HANDLE hProc, uintptr_t addr) {
    uint8_t buf[32] = { 0 };
    SIZE_T got = 0;
    if (!SafeRead(hProc, addr, buf, sizeof(buf), got) || got < 0x18)
        return std::nullopt;

    size_t len = 0;
    memcpy(&len, buf + 0x10, sizeof(size_t));
    if (len == 0 || len > 256) return std::nullopt;

    if (len < 16)
        return std::string((char*)buf, len);
    else {
        uintptr_t ptr = 0;
        memcpy(&ptr, buf, sizeof(uintptr_t));
        if (ptr == 0) return std::nullopt;
        std::vector<char> str(len + 1, 0);
        if (!SafeRead(hProc, ptr, str.data(), len, got) || got < len)
            return std::nullopt;
        return std::string(str.data(), len);
    }
}