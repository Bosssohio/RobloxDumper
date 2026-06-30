
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <iostream>     
#include <iomanip>      
#include <sstream>     

#pragma comment(lib, "Psapi.lib")

// --- Nt* typedefs ---
typedef NTSTATUS(NTAPI* NtRVM_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* NtSuspendProcess_t)(HANDLE);
typedef NTSTATUS(NTAPI* NtResumeProcess_t)(HANDLE);

extern NtRVM_t g_NtRVM;
extern NtSuspendProcess_t g_NtSuspendProcess;
extern NtResumeProcess_t g_NtResumeProcess;
extern bool g_ForceDecrypt;
extern bool g_SuspendProcess;

// ---- Colors & Logging ----
namespace Color {
    inline void Set(WORD a) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), a); }
    inline void Info() { Set(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    inline void Good() { Set(FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    inline void Warn() { Set(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    inline void Err() { Set(FOREGROUND_RED | FOREGROUND_INTENSITY); }
    inline void Reset() { Set(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
    inline void Dim() { Set(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
    inline void Banner() { Set(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY); }
}

#define LOG_INFO(m)  do{Color::Info(); std::cout<<"[*] "<<m<<"\n"; Color::Reset();}while(0)
#define LOG_OK(m)    do{Color::Good(); std::cout<<"[+] "<<m<<"\n"; Color::Reset();}while(0)
#define LOG_WARN(m)  do{Color::Warn(); std::cout<<"[!] "<<m<<"\n"; Color::Reset();}while(0)
#define LOG_ERR(m)   do{Color::Err();  std::cout<<"[-] "<<m<<"\n"; Color::Reset();}while(0)
#define LOG_STEP(m)  do{Color::Dim();  std::cout<<"    >> "<<m<<"\n"; Color::Reset();}while(0)

#define LOG_DEBUG(msg) \
    do { \
        std::cout << "[DEBUG] " << msg << std::endl; \
    } while (0)

// utili
inline DWORD AlignUp(DWORD v, DWORD a) { return (v + a - 1) & ~(a - 1); };
std::string ToHex(uintptr_t v, int w = 16);
std::string EscapeCString(const std::string& s);
std::string ToValidIdentifier(const std::string& s);

// reading memory!!
void InitNtFunctions();
bool SEH_RawRead(HANDLE hProc, LPVOID ptr, BYTE* buf, SIZE_T size, SIZE_T& got);
bool SEH_NtRead(HANDLE hProc, uintptr_t addr, BYTE* buf, SIZE_T size, SIZE_T& got);
bool SafeRead(HANDLE hProc, uintptr_t addr, void* buf, SIZE_T size, SIZE_T& got);
SIZE_T ForceDecryptAndReadPage(HANDLE hProc, uintptr_t va, uint8_t* dst, SIZE_T size);

// parsing boblox
struct SectionInfo {
    char name[9];
    uintptr_t rva;
    uint32_t virtualSize;
    uint32_t rawOffset;
    uint32_t rawSize;
    uint32_t characteristics;
};
struct PEInfo {
    uintptr_t moduleBase;
    uintptr_t imageSize;
    uintptr_t entryRVA;
    std::vector<SectionInfo> sections;
};

std::optional<PEInfo> ParsePE(HANDLE hProc, uintptr_t base);
std::vector<uint8_t> ReadSection(HANDLE hProc, const PEInfo& pe, const SectionInfo& sec, bool decrypt = true);
std::vector<uint8_t> ReadTextGhost(HANDLE hProc, const PEInfo& pe, const SectionInfo& sec);

// find string
struct StringHit {
    size_t offset;
    uintptr_t va;
    bool xorEncoded;
    uint8_t xorKey;
    std::string encoding;
};
std::vector<StringHit> ScanPlain(const uint8_t* data, size_t sz, uintptr_t baseVA, const uint8_t* needle, size_t nlen);
std::vector<StringHit> ScanXOR(const uint8_t* data, size_t sz, uintptr_t baseVA, const uint8_t* needle, size_t nlen);
std::vector<StringHit> DiscoverString(const std::vector<uint8_t>& buf, uintptr_t baseVA, const std::vector<uint8_t>& needle, bool noXor = false);

// find rtti (scary)
struct RTTIResult {
    uintptr_t stringVA;
    uintptr_t typeDescRVA;
    uintptr_t colRVA;
    uintptr_t vtableRVA;
    uintptr_t singletonRVA;
    int score;
};

std::optional<RTTIResult> FindRTTI(HANDLE hProc, const PEInfo& pe,
    const std::vector<uint8_t>& rdataBuf, const std::vector<uint8_t>& dataBuf,
    const std::string& typeName);

// Read an MSVC std::string (SSO or heap) from the target process
std::optional<std::string> ReadRobloxString(HANDLE hProc, uintptr_t addr);

static bool IsPointerValid(HANDLE hProc, uintptr_t ptr) {
    if (ptr < 0x10000 || ptr > 0x00007FFFFFFFFFFF) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProc, (LPCVOID)ptr, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    return true;
}

static std::optional<std::string> ReadStringSafe(HANDLE hProc, uintptr_t ptr) {
    if (!IsPointerValid(hProc, ptr)) return std::nullopt;
    return ReadRobloxString(hProc, ptr);
}


static bool HasValidVTable(HANDLE hProc, uintptr_t objectPtr, const PEInfo& pe) {
    if (!IsPointerValid(hProc, objectPtr)) return false;
    uintptr_t vtable = 0;
    SIZE_T got;
    if (!SafeRead(hProc, objectPtr, &vtable, sizeof(vtable), got) || got != sizeof(vtable))
        return false;
    for (const auto& sec : pe.sections) {
        uintptr_t secStart = pe.moduleBase + sec.rva;
        uintptr_t secEnd = secStart + sec.virtualSize;
        if (vtable >= secStart && vtable < secEnd)
            return true;
    }
    return false;
}

static std::optional<PEInfo> GetPEInfo(HANDLE hProc, uintptr_t moduleBase) {
    static std::optional<PEInfo> cached;
    static uintptr_t cachedModuleBase = 0;
    if (cached.has_value() && cachedModuleBase == moduleBase)
        return cached;
    auto pe = ParsePE(hProc, moduleBase);
    if (pe) {
        cached = pe;
        cachedModuleBase = moduleBase;
    }
    return cached;
}

static uintptr_t GetModuleBase(HANDLE hProc) {
    HMODULE hMod;
    DWORD cb;
    if (!EnumProcessModules(hProc, &hMod, sizeof(hMod), &cb)) return 0;
    MODULEINFO mi;
    if (!GetModuleInformation(hProc, hMod, &mi, sizeof(mi))) return 0;
    return (uintptr_t)mi.lpBaseOfDll;
}

