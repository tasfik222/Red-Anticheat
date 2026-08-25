#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <psapi.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <Sddl.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <algorithm>
#include <tchar.h>
#include <tlhelp32.h>
#include <set>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <cmath>
#include <winsvc.h>
#include <shellapi.h>
#include <fstream>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wbemuuid.lib")

#pragma warning(disable: 6031)
#pragma warning(disable: 6387)
#pragma warning(disable: 6308)
#pragma warning(disable: 28251)
#pragma warning(disable: 4244)

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define BREAKPOINT_OPCODE 0xCC

// ============================================================
//  DISCORD WEBHOOK CONFIGURATION
// ============================================================
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wbemuuid.lib")
#include <wininet.h>

static const std::string DISCORD_WEBHOOK_URL =
    "";

static const int HEARTBEAT_INTERVAL_SECONDS = 30; // 30 second heartbeat

static std::string g_ThreadId = ""; // Global thread ID

// ── JSON Escape ──
std::string JsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

// ── wstring to string ──
std::string WstrToStr(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(sz - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], sz, nullptr, nullptr);
    return result;
}

// ── Machine Info (HWID, PC Name, Username) ──
std::string GetMotherboardSerial() {
    std::string serial = "UNKNOWN";
    IWbemLocator* pLoc = nullptr; IWbemServices* pSvc = nullptr;
    CoInitializeEx(0, COINIT_MULTITHREADED);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc))) return serial;
    if (FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, 0, 0, 0, &pSvc))) { pLoc->Release(); return serial; }
    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    IEnumWbemClassObject* pEnum = nullptr;
    pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT SerialNumber FROM Win32_BaseBoard"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnum);
    if (pEnum) {
        IWbemClassObject* pObj = nullptr; ULONG uReturn = 0;
        if (pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == S_OK) {
            VARIANT vt; VariantInit(&vt);
            if (SUCCEEDED(pObj->Get(L"SerialNumber", 0, &vt, 0, 0)) && vt.vt == VT_BSTR && vt.bstrVal) {
                int sz = WideCharToMultiByte(CP_UTF8, 0, vt.bstrVal, -1, nullptr, 0, nullptr, nullptr);
                serial.resize(sz - 1);
                WideCharToMultiByte(CP_UTF8, 0, vt.bstrVal, -1, &serial[0], sz, nullptr, nullptr);
            }
            VariantClear(&vt); pObj->Release();
        }
        pEnum->Release();
    }
    pSvc->Release(); pLoc->Release();
    return serial;
}

std::string GetVolumeSerial() {
    DWORD vol = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &vol, nullptr, nullptr, nullptr, 0);
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << vol;
    return oss.str();
}

std::string GetHWID()     { return "MB:" + GetMotherboardSerial() + "-VOL:" + GetVolumeSerial(); }
std::string GetPCName()   { char b[MAX_COMPUTERNAME_LENGTH+1]={}; DWORD s=sizeof(b); GetComputerNameA(b,&s); return b; }
std::string GetUsername() { char b[256]={}; DWORD s=sizeof(b); GetUserNameA(b,&s); return b; }

std::string GetMachineInfo() {
    return "\n> **HWID:** `" + GetHWID() + "`"
           "\n> **PC:** `"   + GetPCName() + "`"
           "\n> **User:** `" + GetUsername() + "`";
}

// ── HTTP POST helper ──
std::string HttpPost(const std::string& fullUrl, const std::string& payload) {
    std::string response;
    URL_COMPONENTSA uc = {}; uc.dwStructSize = sizeof(uc);
    char host[256]={}, path[1024]={};
    uc.lpszHostName=host; uc.dwHostNameLength=sizeof(host);
    uc.lpszUrlPath=path;  uc.dwUrlPathLength=sizeof(path);
    InternetCrackUrlA(fullUrl.c_str(), 0, 0, &uc);
    HINTERNET hI = InternetOpenA("RedEyeAC", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hI) return response;
    HINTERNET hC = InternetConnectA(hI, host, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hC) { InternetCloseHandle(hI); return response; }
    const char* acc[]={"application/json",NULL};
    HINTERNET hR = HttpOpenRequestA(hC, "POST", path, NULL, NULL, acc, INTERNET_FLAG_SECURE|INTERNET_FLAG_RELOAD, 0);
    if (!hR) { InternetCloseHandle(hC); InternetCloseHandle(hI); return response; }
    std::string hdr = "Content-Type: application/json\r\n";
    HttpSendRequestA(hR, hdr.c_str(), (DWORD)hdr.size(), (LPVOID)payload.c_str(), (DWORD)payload.size());
    char buf[4096]={}; DWORD rd=0;
    while (InternetReadFile(hR, buf, sizeof(buf)-1, &rd) && rd>0) { response.append(buf,rd); rd=0; }
    InternetCloseHandle(hR); InternetCloseHandle(hC); InternetCloseHandle(hI);
    return response;
}

std::string ParseThreadId(const std::string& json) {
    const std::string key = "\"id\":\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return "";
    pos += key.size();
    size_t end = json.find("\"", pos);
    return (end==std::string::npos)?"":json.substr(pos, end-pos);
}

std::string GetTimestamp() {
    time_t now = time(nullptr); struct tm t; localtime_s(&t, &now);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        t.tm_year+1900, t.tm_mon+1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    return buf;
}

// ── Forum Thread তৈরি করা (PC-র নামে) ──
std::string CreateDiscordThread() {
    std::string desc =
        "RED EYE AntiCheat **started** on this machine.\n"
        "Real-time monitoring is now **active**." +
        GetMachineInfo();

    std::string payload =
        "{\"thread_name\":\"" + JsonEscape(GetPCName() + " | " + GetUsername()) + "\","
        "\"embeds\":[{\"title\":\"\xF0\x9F\x9F\xA2 ANTICHEAT ONLINE\","
        "\"description\":\"" + JsonEscape(desc) + "\","
        "\"color\":52428,"
        "\"footer\":{\"text\":\"RED EYE AntiCheat | " + GetTimestamp() + "\"}}]}";

    std::string resp = HttpPost(DISCORD_WEBHOOK_URL + "?wait=true", payload);
    return ParseThreadId(resp);
}

// ── Thread-এ message পাঠানো ──
void SendDiscordAlert(const std::string& title, const std::string& description, int color = 0xFF0000) {
    if (g_ThreadId.empty()) return;
    std::string fullDesc = description + GetMachineInfo();
    std::string payload =
        "{\"embeds\":[{\"title\":\"" + JsonEscape(title) + "\","
        "\"description\":\"" + JsonEscape(fullDesc) + "\","
        "\"color\":" + std::to_string(color) + ","
        "\"footer\":{\"text\":\"RED EYE AntiCheat | " + GetTimestamp() + "\"}}]}";
    HttpPost(DISCORD_WEBHOOK_URL + "?thread_id=" + g_ThreadId, payload);
}

// ── Heartbeat Loop ──
// ============================================================
//  FREEZE DETECTION SYSTEM
//  AntiCheat প্রতি সেকেন্ডে shared memory-তে ping counter বাড়াবে
//  Guardian সেটা check করবে — না বাড়লে freeze detect করবে
// ============================================================
static HANDLE g_hSharedMem  = nullptr;
static LONG*  g_pPingCounter = nullptr;

// Shared memory তৈরি করা
void InitFreezeDetection()
{
    g_hSharedMem = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, sizeof(LONG) * 4,
        L"Global\\RedEyeACHeartbeat");

    if (g_hSharedMem) {
        g_pPingCounter = (LONG*)MapViewOfFile(
            g_hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LONG) * 4);
        if (g_pPingCounter) {
            g_pPingCounter[0] = 0; // ping counter
            g_pPingCounter[1] = (LONG)GetCurrentProcessId(); // PID
            g_pPingCounter[2] = 1; // alive flag
            g_pPingCounter[3] = 0; // freeze count
        }
    }
}

// প্রতি 500ms-এ ping counter বাড়ানো
void FreezeDetectionPingLoop()
{
    while (true) {
        if (g_pPingCounter)
            InterlockedIncrement(&g_pPingCounter[0]);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}
// ============================================================

void HeartbeatLoop() {
    int beat = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL_SECONDS));
        beat++;
        std::string msg =
            "Tool is **actively running**.\n"
            "Heartbeat #`" + std::to_string(beat) + "`";
        SendDiscordAlert("\xE2\x9C\x85 ANTICHEAT ONLINE", msg, 0x00CC44);
    }
}
// ============================================================




typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

std::wstring to_wstring(DWORD value) {
    std::wstringstream wss;
    wss << value;
    return wss.str();
}

HANDLE OpenProcessSafe(DWORD processId) {
    return OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
}

DWORD FindProcessByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (processName == pe.szExeFile) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}






std::wstring GetProcessPath(DWORD processId) {
    std::wstring processPath = L"<Unknown>";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        WCHAR buffer[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, buffer, MAX_PATH)) {
            processPath = buffer;
        }
        CloseHandle(hProcess);
    }
    return processPath;
}



std::wstring GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return L"<Unknown>";

    WCHAR processName[MAX_PATH];
    if (GetModuleBaseNameW(hProcess, NULL, processName, MAX_PATH)) {
        CloseHandle(hProcess);
        return std::wstring(processName);
    }

    CloseHandle(hProcess);
    return L"<Unknown>";
}


DWORD FindHDPlayerProcessId() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create snapshot of processes." << std::endl;
        return 0;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    DWORD targetPid = 0;
    if (Process32FirstW(hSnapshot, &processEntry)) {
        do {
            if (std::wstring(processEntry.szExeFile) == L"HD-Player.exe") {
                targetPid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    return targetPid;
}




void EnumerateAndTerminateWindowByStyle(DWORD processId) {
    
    auto EnumWindowsCallback = [](HWND hwnd, LPARAM lParam) -> BOOL {
        DWORD windowProcessId;
        GetWindowThreadProcessId(hwnd, &windowProcessId);

        if (windowProcessId == (DWORD)lParam) {
            LONG style = GetWindowLong(hwnd, GWL_STYLE);

            if (style == 0x94000000) {
               
                HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
                CONSOLE_SCREEN_BUFFER_INFO csbi;
                GetConsoleScreenBufferInfo(hCon, &csbi);
                WORD def = csbi.wAttributes;

                
                SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);

               
                std::wcout << L"\n    HWND: " << hwnd << L"\n"
                    << L"    [ESP OVERLAY DETECTED]\n";

                // Discord Alert
                {
                    std::ostringstream oss;
                    oss << "**ESP Overlay window detected on HD-Player!**\n"
                        << "HWND: `" << (uintptr_t)hwnd << "`\n"
                        << "Action: Close request sent.";
                    std::string msg = oss.str();
                    std::thread([msg]() {
                        SendDiscordAlert("\xF0\x9F\x9A\xA8 ESP OVERLAY DETECTED", msg, 0xFF0000);
                    }).detach();
                }

                if (PostMessage(hwnd, WM_CLOSE, 0, 0)) {
                    std::wcout << L"\n    [CLOSE REQUEST SENT]\n";
                }
                else {
                    std::wcout << L"\n    [FAILED TO CLOSE]\n";
                }

               
                SetConsoleTextAttribute(hCon, def);

               
                std::wcout << L"\n";
            }
        }
        return TRUE;
        };

    EnumWindows(EnumWindowsCallback, (LPARAM)processId);
}

// wintrust এবং softpub include (এখানে একবার)
#include <wintrust.h>
#include <softpub.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define ThreadQuerySetWin32StartAddress 9

using pfnNtQueryInformationThread = NTSTATUS(WINAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);


struct ModuleRange {
    uintptr_t start, end;
};


bool GetProcessModuleRanges(DWORD pid, std::vector<ModuleRange>& outRanges) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me = { sizeof(me) };
    if (!Module32FirstW(hSnap, &me)) {
        CloseHandle(hSnap);
        return false;
    }
    do {
        uintptr_t base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
        outRanges.push_back({ base, base + me.modBaseSize });
    } while (Module32NextW(hSnap, &me));
    CloseHandle(hSnap);
    return true;
}


bool IsAddressWithinModule(uintptr_t addr, const std::vector<ModuleRange>& ranges) {
    for (auto& r : ranges)
        if (addr >= r.start && addr < r.end)
            return true;
    return false;
}


BOOL IsFileSigned(LPCWSTR path) {
    WINTRUST_FILE_INFO fi = { sizeof(fi), path };
    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fi;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_SAFER_FLAG;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policy, &wtd);


    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &wtd);

    return (status == ERROR_SUCCESS);
}



// ============================================================
//  ADVANCED DETECTION SYSTEMS
// ============================================================

// ── 1. MANUAL MAP DETECTION ──
void DetectManualMap(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProc) return;

    std::vector<ModuleRange> knownRanges;
    GetProcessModuleRanges(pid, knownRanges);

    // Already alerted addresses — বারবার same address alert না করতে
    static std::set<uintptr_t> alreadyAlerted;

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0;

    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        bool isExec    = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        bool isPrivate = (mbi.Type == MEM_PRIVATE);
        bool isCommit  = (mbi.State == MEM_COMMIT);

        // False positive কমাতে:
        // 1. Minimum size 64KB (0x10000) — ছোট allocation সাধারণত normal
        // 2. PAGE_EXECUTE_READWRITE (0x40) হলেই শুধু alert — সবচেয়ে suspicious
        // 3. Already alerted address skip
        bool isSuspiciousProtect = (mbi.Protect == PAGE_EXECUTE_READWRITE ||  // 0x40
                                    mbi.Protect == PAGE_EXECUTE_WRITECOPY);    // 0x80

        if (isExec && isPrivate && isCommit &&
            isSuspiciousProtect &&
            mbi.RegionSize >= 0x10000 && // 64KB minimum
            alreadyAlerted.find((uintptr_t)mbi.BaseAddress) == alreadyAlerted.end())
        {
            uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
            if (!IsAddressWithinModule(regionBase, knownRanges)) {
                // Memory-তে MZ header আছে কিনা চেক (DLL/EXE inject হলে থাকবে)
                BYTE header[2] = {};
                SIZE_T read = 0;
                ReadProcessMemory(hProc, (LPCVOID)regionBase, header, 2, &read);
                bool hasMZHeader = (read == 2 && header[0] == 'M' && header[1] == 'Z');

                if (hasMZHeader) {
                    alreadyAlerted.insert(regionBase);
                    std::ostringstream oss;
                    oss << "**Manual Map / Hidden DLL detected in HD-Player!**\n"
                        << "Address: `0x" << std::hex << regionBase << "`\n"
                        << "Size: `" << std::dec << mbi.RegionSize << " bytes`\n"
                        << "> MZ header found in executable private memory!\n"
                        << "> DLL was manually mapped (no module entry).";
                    std::string msg = oss.str();
                    std::thread([msg]() {
                        SendDiscordAlert("\xF0\x9F\x9A\xA8 MANUAL MAP DETECTED", msg, 0xFF0000);
                    }).detach();
                }
            }
        }
        if (mbi.RegionSize == 0) break;
        addr += mbi.RegionSize;
        if (addr == 0) break;
    }
    CloseHandle(hProc);
}

// ── 2. KNOWN CHEAT SIGNATURE SCAN ──
// Memory-তে known cheat byte pattern খোঁজা
struct CheatSignature {
    const char* name;
    std::vector<BYTE> pattern;
};

static const std::vector<CheatSignature> g_Signatures = {
    // Cheat Engine signatures
    { "CheatEngine7",    { 0x43, 0x68, 0x65, 0x61, 0x74, 0x45, 0x6E, 0x67 } },
    // Common aimbot string
    { "AimbotEnable",   { 0x61, 0x69, 0x6D, 0x62, 0x6F, 0x74, 0x5F, 0x65 } },
    // ESP string
    { "ESP_ENABLE",     { 0x45, 0x53, 0x50, 0x5F, 0x45, 0x4E, 0x41, 0x42 } },
    // Common injector marker
    { "InjectedDLL",    { 0x49, 0x6E, 0x6A, 0x65, 0x63, 0x74, 0x65, 0x64 } },
    // NOP sled (common patch)
    { "NOPSled",        { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } },
};

bool ScanMemoryForPattern(HANDLE hProc, uintptr_t addr, SIZE_T size,
                           const std::vector<BYTE>& pattern)


void DetectCheatSignatures(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0;

    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_READWRITE | PAGE_READONLY)) &&
            mbi.RegionSize <= 0x1000000) // 16MB max
        {
            for (auto& sig : g_Signatures) {
                if (ScanMemoryForPattern(hProc, (uintptr_t)mbi.BaseAddress,
                                          mbi.RegionSize, sig.pattern))
                {
                    std::ostringstream oss;
                    oss << "**Known cheat signature found in HD-Player memory!**\n"
                        << "Signature: `" << sig.name << "`\n"
                        << "Address: `0x" << std::hex << (uintptr_t)mbi.BaseAddress << "`\n"
                        << "> Cheat code pattern detected in game memory!";
                    std::string msg = oss.str();
                    std::thread([msg]() {
                        SendDiscordAlert("\xF0\x9F\x9A\xA8 CHEAT SIGNATURE FOUND", msg, 0xFF0000);
                    }).detach();
                }
            }
        }
        addr += mbi.RegionSize;
        if (addr == 0) break;
    }
    CloseHandle(hProc);
}

// ── 3. KERNEL DRIVER DETECTION ──
void DetectSuspiciousDrivers()
{
    // একবারই চলবে
    static bool done = false;
    if (done) return;
    done = true;

    SC_HANDLE hScm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) return;

    DWORD needed = 0, count = 0;
    EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_ACTIVE, nullptr, 0, &needed, &count, nullptr, nullptr);
    if (needed == 0) { CloseServiceHandle(hScm); return; }

    std::vector<BYTE> buf(needed);
    if (!EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_ACTIVE, buf.data(), needed, &needed, &count, nullptr, nullptr))
    { CloseServiceHandle(hScm); return; }

    auto* svcs = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());

    // Known cheat driver names ONLY — এগুলোই সত্যিকারের cheat driver
    static const std::vector<std::wstring> knownCheatDrivers = {
        L"cheatengine", L"aimbot", L"wallhack",
        L"bypass", L"injector", L"loader", L"exploit",
        L"nocheat", L"speedhack", L"triggerbot",
        L"unknowncheats", L"cheatlib"
    };

    // Windows system driver path patterns — এগুলো সব safe
    auto isSystemDriver = [](const std::wstring& path) -> bool {
        std::wstring p = path;
        // lowercase করা
        std::transform(p.begin(), p.end(), p.begin(), ::tolower);
        return p.find(L"\\systemroot\\") != std::wstring::npos ||
               p.find(L"\\windows\\")   != std::wstring::npos ||
               p.find(L"system32\\")    != std::wstring::npos ||
               p.find(L"system32/")     != std::wstring::npos ||
               p.empty();
    };

    for (DWORD i = 0; i < count; i++) {
        SC_HANDLE hSvc = OpenServiceW(hScm, svcs[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD cfgNeeded = 0;
        QueryServiceConfigW(hSvc, nullptr, 0, &cfgNeeded);
        if (cfgNeeded == 0) { CloseServiceHandle(hSvc); continue; }

        std::vector<BYTE> cfgBuf(cfgNeeded);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
        if (!QueryServiceConfigW(hSvc, cfg, cfgNeeded, &cfgNeeded))
        { CloseServiceHandle(hSvc); continue; }

        std::wstring drvPath = cfg->lpBinaryPathName;

        // System driver হলে skip
        if (isSystemDriver(drvPath)) { CloseServiceHandle(hSvc); continue; }

        // Driver store path হলে skip (Windows update drivers)
        std::wstring pathLow = drvPath;
        std::transform(pathLow.begin(), pathLow.end(), pathLow.begin(), ::tolower);
        if (pathLow.find(L"driverstore") != std::wstring::npos)
        { CloseServiceHandle(hSvc); continue; }

        // Known cheat name চেক
        std::wstring nameLow = svcs[i].lpServiceName;
        std::transform(nameLow.begin(), nameLow.end(), nameLow.begin(), ::tolower);
        bool isKnown = false;
        for (auto& kc : knownCheatDrivers)
            if (nameLow.find(kc) != std::wstring::npos) { isKnown = true; break; }

        // শুধু known cheat নামের driver alert করবো
        // অথবা non-system path-এ unsigned driver
        if (isKnown) {
            std::string drvName  = WstrToStr(svcs[i].lpServiceName);
            std::string drvPathS = WstrToStr(drvPath);
            std::string msg =
                "**Known cheat kernel driver detected!**\n"
                "Driver: `" + drvName + "`\n"
                "Path: `" + drvPathS + "`\n"
                "> **Known cheat driver name!** Immediate action required.";
            std::thread([msg]() {
                SendDiscordAlert("\xF0\x9F\x9A\xA8 CHEAT DRIVER DETECTED", msg, 0xFF0000);
            }).detach();
        }

        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
}

// ── 4. SCREEN CAPTURE DETECTION ──
// কেউ screen capture করছে কিনা (OBS, Fraps, screenshot tools)
void DetectScreenCapture()
{
    static const std::vector<std::wstring> captureProcs = {
        L"obs64.exe", L"obs32.exe", L"obs.exe",
        L"fraps.exe", L"bandicam.exe", L"action.exe",
        L"xsplit.exe", L"nvcontainer.exe",
        L"shadowplay.exe", L"gfexperience.exe",
        L"medal.exe", L"outplayed.exe", L"plays.exe",
        L"screencapture.exe", L"snagit32.exe"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            std::wstring exeName = pe.szExeFile;
            std::wstring exeLow = exeName;
            std::transform(exeLow.begin(), exeLow.end(), exeLow.begin(), ::tolower);

            for (auto& cap : captureProcs) {
                if (exeLow == cap) {
                    std::string msg =
                        "**Screen capture software detected!**\n"
                        "Process: `" + WstrToStr(exeName) + "`\n"
                        "PID: `" + std::to_string(pe.th32ProcessID) + "`\n"
                        "> Player may be recording/streaming gameplay.";
                    std::thread([msg]() {
                        SendDiscordAlert("\xF0\x9F\x93\xB9 SCREEN CAPTURE DETECTED", msg, 0xFFAA00);
                    }).detach();
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

// ── 5. DEBUGGER DETECTION ──
// কেউ HD Player-কে debug করছে কিনা
void DetectDebugger(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;

    BOOL isDebugged = FALSE;
    if (CheckRemoteDebuggerPresent(hProc, &isDebugged) && isDebugged) {
        std::string msg =
            "**HD-Player is being DEBUGGED!**\n"
            "PID: `" + std::to_string(pid) + "`\n"
            "> Someone attached a debugger to HD-Player!\n"
            "> Possible reverse engineering / cheat development!";
        std::thread([msg]() {
            SendDiscordAlert("\xF0\x9F\x9A\xA8 DEBUGGER DETECTED", msg, 0xFF0000);
        }).detach();
    }
    CloseHandle(hProc);
}

// ── 6. MEMORY WRITE DETECTION ──
// HD Player-এর memory-তে কেউ write করেছে কিনা (checksum দিয়ে)
struct MemoryChecksum {
    uintptr_t address;
    SIZE_T     size;
    DWORD      checksum;
};

DWORD CalcChecksum(const std::vector<BYTE>& data) {
    DWORD cs = 0;
    for (BYTE b : data) cs = (cs << 1) ^ b;
    return cs;
}

std::vector<MemoryChecksum> g_MemChecksums;

void InitMemoryChecksums(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;

    g_MemChecksums.clear();

    // HD Player main module-এর executable sections
    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hModSnap == INVALID_HANDLE_VALUE) { CloseHandle(hProc); return; }

    MODULEENTRY32W me = { sizeof(me) };
    if (Module32FirstW(hModSnap, &me)) {
        // শুধু main module (first entry = main exe)
        uintptr_t base = (uintptr_t)me.modBaseAddr;
        SIZE_T     size = me.modBaseSize;

        // 4KB chunk-এ ভেঙে checksum নেওয়া
        for (SIZE_T offset = 0; offset < size; offset += 0x1000) {
            SIZE_T chunkSize = std::min((SIZE_T)0x1000, size - offset);
            std::vector<BYTE> buf(chunkSize);
            SIZE_T read = 0;
            if (ReadProcessMemory(hProc, (LPCVOID)(base + offset), buf.data(), chunkSize, &read) && read > 0) {
                g_MemChecksums.push_back({ base + offset, chunkSize, CalcChecksum(buf) });
            }
        }
    }
    CloseHandle(hModSnap);
    CloseHandle(hProc);
}

void CheckMemoryIntegrity(DWORD pid)
{
    if (g_MemChecksums.empty()) { InitMemoryChecksums(pid); return; }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return;

    int modifiedCount = 0;
    for (auto& cs : g_MemChecksums) {
        std::vector<BYTE> buf(cs.size);
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)cs.address, buf.data(), cs.size, &read)) continue;
        DWORD newCs = CalcChecksum(buf);
        if (newCs != cs.checksum) {
            modifiedCount++;
            std::ostringstream oss;
            oss << "**HD-Player memory was MODIFIED!**\n"
                << "Address: `0x" << std::hex << cs.address << "`\n"
                << "Original CRC: `0x" << cs.checksum << "`\n"
                << "Current CRC: `0x" << newCs << "`\n"
                << "> Someone patched HD-Player game memory! (Wallhack/Aimbot)";
            std::string msg = oss.str();
            std::thread([msg]() {
                SendDiscordAlert("\xF0\x9F\x9A\xA8 MEMORY MODIFIED", msg, 0xFF0000);
            }).detach();
            cs.checksum = newCs; // update করো যাতে বারবার alert না আসে
        }
    }
    CloseHandle(hProc);
}

// ── 7. MOUSE/AIM BEHAVIOR DETECTION ──
// Aim pattern অস্বাভাবিক কিনা চেক (pixel-perfect rapid movement)
struct AimSample { POINT pt; DWORD time; };
static std::vector<AimSample> g_AimHistory;
static const int AIM_HISTORY_SIZE = 30;

void DetectAimbot()
{
    POINT pt;
    GetCursorPos(&pt);
    DWORD now = GetTickCount();

    g_AimHistory.push_back({ pt, now });
    if ((int)g_AimHistory.size() > AIM_HISTORY_SIZE)
        g_AimHistory.erase(g_AimHistory.begin());

    if ((int)g_AimHistory.size() < AIM_HISTORY_SIZE) return;

    // Speed এবং direction change হঠাৎ অনেক বেশি হলে suspicious
    int snapCount = 0;
    for (int i = 1; i < (int)g_AimHistory.size(); i++) {
        auto& prev = g_AimHistory[i-1];
        auto& curr = g_AimHistory[i];
        DWORD dt = curr.time - prev.time;
        if (dt == 0) continue;

        double dx = curr.pt.x - prev.pt.x;
        double dy = curr.pt.y - prev.pt.y;
        double dist = sqrt(dx*dx + dy*dy);
        double speed = dist / dt; // pixels per ms

        // 50+ pixels/ms — humanly impossible
        if (speed > 50.0) snapCount++;
    }

    if (snapCount >= 5) {
        static DWORD lastAimAlert = 0;
        DWORD now2 = GetTickCount();
        if (now2 - lastAimAlert > 10000) { // 10 সেকেন্ডে একবার
            lastAimAlert = now2;
            std::string msg =
                "**Suspicious mouse movement detected!**\n"
                "Snap Count: `" + std::to_string(snapCount) + "/" +
                std::to_string(AIM_HISTORY_SIZE) + "`\n"
                "> Inhuman aim speed detected — possible aimbot!";
            std::thread([msg]() {
                SendDiscordAlert("\xF0\x9F\x9A\xA8 AIMBOT BEHAVIOR DETECTED", msg, 0xFF6600);
            }).detach();
        }
    }
}

// ── 8. HWID BLACKLIST CHECK ──
// Discord থেকে ban list চেক করা (future use — placeholder)
// আপনি Discord channel-এ HWID যোগ করলে এখানে check হবে

// ── 9. VIRTUAL MACHINE DETECTION ──
// Cheater VM-এ খেলছে কিনা
void DetectVirtualMachine()
{
    static bool checked = false;
    if (checked) return;
    checked = true;

    bool isVM = false;
    std::string vmType;

    // Registry check
    struct { HKEY hive; const wchar_t* key; const wchar_t* val; const wchar_t* match; } checks[] = {
        { HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"VBOX" },
        { HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"VMWARE" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", nullptr, nullptr },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", nullptr, nullptr },
    };

    for (auto& c : checks) {
        HKEY hKey;
        if (RegOpenKeyExW(c.hive, c.key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (c.val && c.match) {
                wchar_t buf[256] = {};
                DWORD sz = sizeof(buf);
                if (RegQueryValueExW(hKey, c.val, nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                    std::wstring val = buf;
                    std::wstring match = c.match;
                    if (val.find(match) != std::wstring::npos) { isVM = true; vmType = WstrToStr(match); }
                }
            } else { isVM = true; vmType = "Unknown VM"; }
            RegCloseKey(hKey);
        }
    }

    // Process check
    static const std::vector<std::wstring> vmProcs = {
        L"vmtoolsd.exe", L"vmwaretray.exe", L"vboxservice.exe",
        L"vboxtray.exe", L"vmsrvc.exe", L"vmusrvc.exe"
    };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                std::wstring exeLow = pe.szExeFile;
                std::transform(exeLow.begin(), exeLow.end(), exeLow.begin(), ::tolower);
                for (auto& vp : vmProcs)
                    if (exeLow == vp) { isVM = true; vmType = WstrToStr(pe.szExeFile); break; }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    if (isVM) {
        std::string msg =
            "**Virtual Machine detected!**\n"
            "VM Type: `" + vmType + "`\n"
            "> Player is running HD-Player inside a VM!\n"
            "> Possible attempt to bypass AntiCheat detection.";
        std::thread([msg]() {
            SendDiscordAlert("\xF0\x9F\x96\xA5 VIRTUAL MACHINE DETECTED", msg, 0xFFAA00);
        }).detach();
    }
}

// ── MASTER SCAN — সব detection একসাথে ──
void RunAllDetections(DWORD hdPid)
{
    DetectDebugger(hdPid);
    DetectManualMap(hdPid);
    DetectCheatSignatures(hdPid);
    CheckMemoryIntegrity(hdPid);
    DetectSuspiciousDrivers();
    DetectScreenCapture();
    DetectVirtualMachine();
    DetectAimbot();
}
// ============================================================

void ScanProcess(DWORD pid)
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hCon, &csbi);
    WORD defaultAttr = csbi.wAttributes;


    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc)
    {
        WCHAR exePath[MAX_PATH] = L"<unknown>";
        if (GetModuleFileNameExW(hProc, nullptr, exePath, _countof(exePath)))
        {
            bool ok = IsFileSigned(exePath);
            SetConsoleTextAttribute(hCon,
                ok
                ? (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
                : (FOREGROUND_RED | FOREGROUND_INTENSITY));
            std::wcout << (ok ? L"[SIGNED]   " : L"[UNSIGNED] ")
                << L"[EXE] " << exePath << L"\n\n";
            SetConsoleTextAttribute(hCon, defaultAttr);
        }
        CloseHandle(hProc);
    }


    std::wcout << L"Loaded modules:\n";
    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hModSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W me = { sizeof(me) };
        if (Module32FirstW(hModSnap, &me))
        {
            do
            {
                bool ok = IsFileSigned(me.szExePath);
                SetConsoleTextAttribute(hCon,
                    ok
                    ? (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
                    : (FOREGROUND_RED | FOREGROUND_INTENSITY));
                std::wcout << (ok ? L"[SIGNED]   " : L"[UNSIGNED] ")
                    << me.szModule << L" -> " << me.szExePath << L"\n";
                SetConsoleTextAttribute(hCon, defaultAttr);

                // Discord Alert — শুধু unsigned হলে
                if (!ok) {
                    std::string modName = WstrToStr(me.szModule);
                    std::string modPath = WstrToStr(me.szExePath);
                    std::string msg =
                        "**Unsigned/Injected DLL found in HD-Player!**\n"
                        "Module: `" + modName + "`\n"
                        "Path: `"   + modPath + "`";
                    std::thread([msg]() {
                        SendDiscordAlert("\xF0\x9F\x9A\xA8 UNSIGNED MODULE DETECTED", msg, 0xFF0066);
                    }).detach();
                }
            } while (Module32NextW(hModSnap, &me));
        }
        CloseHandle(hModSnap);
    }
    std::wcout << L"\n";

    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    auto NtQIT = reinterpret_cast<pfnNtQueryInformationThread>(
        GetProcAddress(hNt, "NtQueryInformationThread"));
    if (!NtQIT)
    {
        std::wcerr << L"Cannot get NtQueryInformationThread\n";
        return;
    }


    std::vector<ModuleRange> ranges;
    if (!GetProcessModuleRanges(pid, ranges))
    {
        std::wcerr << L"Module-range enumeration failed\n";
        return;
    }


    std::wcout << L"Checking for suspicious threads...\n";
    bool foundSuspicious = false;
    HANDLE hThrSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThrSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(hThrSnap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE hThr = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!hThr) continue;

                uintptr_t startAddr = 0;
                NTSTATUS st = NtQIT(hThr,
                    ThreadQuerySetWin32StartAddress,
                    &startAddr,
                    sizeof(startAddr),
                    nullptr);
                if (st == STATUS_SUCCESS &&
                    !IsAddressWithinModule(startAddr, ranges))
                {
                    foundSuspicious = true;
                    SetConsoleTextAttribute(hCon,
                        FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::wcout
                        << L"[SUSPICIOUS THREAD] PID=" << pid
                        << L" TID=" << te.th32ThreadID
                        << L" Start=0x" << std::hex << startAddr << std::dec
                        << L"\n";
                    SetConsoleTextAttribute(hCon, defaultAttr);

                    // Discord Alert
                    {
                        std::ostringstream oss;
                        oss << "**Injected/Unknown thread found in HD-Player!**\n"
                            << "PID: `" << pid << "`\n"
                            << "TID: `" << te.th32ThreadID << "`\n"
                            << "Start Address: `0x" << std::hex << startAddr << "`\n"
                            << "Thread started outside any known module.";
                        std::string msg = oss.str();
                        std::thread([msg]() {
                            SendDiscordAlert("\xF0\x9F\x9A\xA8 SUSPICIOUS THREAD DETECTED", msg, 0xFF6600);
                        }).detach();
                    }
                }

                CloseHandle(hThr);
            } while (Thread32Next(hThrSnap, &te));
        }
        CloseHandle(hThrSnap);
    }


    if (!foundSuspicious)
    {
        SetConsoleTextAttribute(hCon,
            FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"No suspicious threads found.\n";
        SetConsoleTextAttribute(hCon, defaultAttr);
    }

    std::wcout << L"\nScan complete for PID " << pid << L".\n";
}





// MonitorAndRestrictAccess uses ScanProcess defined above
void MonitorAndRestrictAccess(DWORD targetPid) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {

        return;
    }

    auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {

        return;
    }

    ULONG handleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    if (!handleInfo) {
        std::cerr << "Memory allocation failed." << std::endl;
        return;
    }
    std::vector<DWORD> safeProcesses;
    while (true) {

        if (FindProcessByName(L"HD-Player.exe") != targetPid) {
            std::wcout << L"HD-Player.exe has stopped. Stopping monitoring." << std::endl;
            break;
        }

        NTSTATUS status;
        while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, nullptr)) == STATUS_INFO_LENGTH_MISMATCH) {
            handleInfoSize *= 2;
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
            if (!handleInfo) {
                std::cerr << "Memory reallocation failed." << std::endl;
                return;
            }
        }

        if (!NT_SUCCESS(status)) {

            free(handleInfo);
            return;
        }

        for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
            SYSTEM_HANDLE handle = handleInfo->Handles[i];

            if (handle.ProcessId == GetCurrentProcessId()) {
                continue;
            }

            HANDLE hOwningProcess = OpenProcessSafe(handle.ProcessId);
            if (!hOwningProcess) continue;

            HANDLE hDuplicate = nullptr;

            if (DuplicateHandle(hOwningProcess, (HANDLE)handle.Handle, GetCurrentProcess(), &hDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                if (GetProcessId(hDuplicate) == targetPid) {

                    std::wstring processPath = GetProcessPath(handle.ProcessId);
                    std::wstring processName = GetProcessName(handle.ProcessId);

                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);


                    bool isSafe = (processPath.find(L"C:\\Windows\\System32") != std::wstring::npos) &&
                        (processName == L"taskmgr.exe" || processName == L"lsass.exe" || processName == L"conhost.exe" || processName == L"svchost.exe" || processName == L"csrss.exe" || processName == L"audiodg.exe");

                    if (isSafe) {
                        safeProcesses.push_back(handle.ProcessId);
                        DuplicateHandle(hOwningProcess, (HANDLE)handle.Handle, hOwningProcess, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);

                    }
                    else
                    {


                        DuplicateHandle(hOwningProcess, (HANDLE)handle.Handle, hOwningProcess, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);



                        std::wcout << L"Suspicious Process Detected. PID: " << handle.ProcessId << L", Path: " << processPath << std::endl;

                        // Discord Alert
                        {
                            std::string pidStr  = std::to_string(handle.ProcessId);
                            std::string pathStr = WstrToStr(processPath);
                            std::string nameStr = WstrToStr(GetProcessName(handle.ProcessId));
                            std::string msg =
                                "**Suspicious process has handle on HD-Player!**\n"
                                "Name: `" + nameStr + "`\n"
                                "PID: `"  + pidStr  + "`\n"
                                "Path: `" + pathStr + "`";
                            std::thread([msg]() {
                                SendDiscordAlert("\xF0\x9F\x9A\xA8 CHEAT PROCESS DETECTED", msg, 0xFF4400);
                            }).detach();
                        }

                        ScanProcess(handle.ProcessId);

                    }




                }
                CloseHandle(hDuplicate);
            }

            CloseHandle(hOwningProcess);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    free(handleInfo);
}



PVOID GetZwWriteVirtualMemoryAddress() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {

        return nullptr;
    
    return (PVOID)((uintptr_t)zwWriteVirtualMemory);
}


std::string GetProcessName(HANDLE processHandle) {
    char processName[MAX_PATH] = "<Unknown>";
    if (GetModuleBaseNameA(processHandle, NULL, processName, sizeof(processName) / sizeof(char))) {
        return std::string(processName);
    }
    return std::string("<Unknown>");
}


bool ReadMemory(HANDLE processHandle, PVOID address, std::vector<BYTE>& buffer, SIZE_T size) {
    buffer.resize(size);
    SIZE_T bytesRead;
    if (ReadProcessMemory(processHandle, address, buffer.data(), size, &bytesRead) && bytesRead == size) {
        return true;
    }
    return false;
}


void PrintBytes(const std::vector<BYTE>& bytes) {
    for (BYTE b : bytes) {
        printf("%02X ", b);
    }
    std::cout << std::endl;
}




void monitorexternal() {

    std::wstring targetProcessName = L"HD-Player.exe";

    bool isProcessRunning = true;

    while (true) {

        DWORD targetPid = FindProcessByName(targetProcessName);

        if (targetPid != 0) {

            isProcessRunning = true;
            std::wcout << L"Monitoring process: " << targetProcessName << L" (PID: " << targetPid << L")..." << std::endl;


            MonitorAndRestrictAccess(targetPid);


        }
        else {

            if (isProcessRunning) {
                std::wcout << L"Waiting for process: " << targetProcessName << L" to start..." << std::endl;
                isProcessRunning = false;
            }

        }

        std::this_thread::sleep_for(std::chrono::milliseconds(400));


    }

}


void monitoresp() {
    static bool firstRun = true;
    while (true) {
        DWORD targetPid = FindHDPlayerProcessId();

        if (targetPid != 0) {
            // ESP overlay চেক
            EnumerateAndTerminateWindowByStyle(targetPid);

            // সব advanced detection চালানো
            RunAllDetections(targetPid);

            // First run-এ memory checksum initialize করা
            if (firstRun) {
                InitMemoryChecksums(targetPid);
                firstRun = false;
            }
        }

        // Aimbot detection (HD Player না থাকলেও চলবে)
        DetectAimbot();

        std::this_thread::sleep_for(std::chrono::milliseconds(3000)); // 3 সেকেন্ড
    }
}


std::thread external;
std::thread internal;


bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << "\n";
        return false;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}


void EnsureAdminPrivileges()
{
    BOOL isAdmin = FALSE;
    HANDLE hToken = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
        {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isAdmin)
    {
        // Admin নেই — UAC দিয়ে restart করো
        wchar_t selfPath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        ShellExecuteW(nullptr, L"runas", selfPath, nullptr, nullptr, SW_HIDE);
        ExitProcess(0);
    }
}





std::atomic<bool> g_running{ true };
std::string name = "RED EYE - Developed By GLA1B";

void PrintBanner()
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hCon, &csbi);
    WORD def = csbi.wAttributes;

    WORD borderCol = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    WORD textCol = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

    const int width = 42;
    std::string pad((width - 2 - name.size()) / 2, ' ');

    SetConsoleTextAttribute(hCon, borderCol);
    std::cout << std::string(width, '*') << "\n";
    std::cout << "*" << std::string(width - 2, ' ') << "*\n";
    std::cout << "*" << pad;
    SetConsoleTextAttribute(hCon, textCol);
    std::cout << name;
    SetConsoleTextAttribute(hCon, borderCol);
    std::cout << pad;
    if ((name.size() % 2) != 0) std::cout << " ";
    std::cout << "*\n";
    std::cout << "*" << std::string(width - 2, ' ') << "*\n";
    std::cout << std::string(width, '*') << "\n\n";
    SetConsoleTextAttribute(hCon, def);
}

void MonitorTime()
{
    auto prevSteady = std::chrono::steady_clock::now();
    const auto expectedInterval = std::chrono::seconds(1);
    const auto threshold = std::chrono::milliseconds(50);
    bool tampered = false;

    while (g_running.load())
    {
        std::this_thread::sleep_for(expectedInterval);

        time_t nowTime = time(nullptr);
        struct tm local_tm;
        localtime_s(&local_tm, &nowTime);

        char timeBuf[64];
        int hour = local_tm.tm_hour % 12;
        if (hour == 0) hour = 12;
        const char* ampm = (local_tm.tm_hour < 12) ? "AM" : "PM";
        snprintf(timeBuf, sizeof(timeBuf),
            "Developed By Galib. %02d:%02d:%02d %s",
            hour, local_tm.tm_min, local_tm.tm_sec, ampm);
        SetConsoleTitleA(timeBuf);

        auto nowSteady = std::chrono::steady_clock::now();
        auto actualInterval = nowSteady - prevSteady;
        auto diff = (actualInterval > expectedInterval)
            ? actualInterval - expectedInterval
            : expectedInterval - actualInterval;

        if (diff > threshold) {
            if (!tampered) {
                double sec = std::chrono::duration<double>(diff).count();
                HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
                CONSOLE_SCREEN_BUFFER_INFO csbi;
                GetConsoleScreenBufferInfo(hCon, &csbi);
                WORD def = csbi.wAttributes;
                SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << "\nBypass attempted. Time jump: "
                    << std::fixed << std::setprecision(3)
                    << sec << " seconds\n";

                // Discord Alert
                
        else {
            tampered = false;
        }

        prevSteady = nowSteady;
    }
}


void DisableConsoleSelection()
{

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE)
        return;

    DWORD mode = 0;
    if (!GetConsoleMode(hStdin, &mode))
        return;


    mode |= ENABLE_EXTENDED_FLAGS;

    mode &= ~(ENABLE_QUICK_EDIT_MODE | ENABLE_MOUSE_INPUT);

    SetConsoleMode(hStdin, mode);
}


// ============================================================
//  GUARDIAN AUTO-DROP SYSTEM
//  AntiCheat চালু হলে Guardian EXE Downloads folder-এ drop হবে
//  এবং automatically চালু হবে
// ============================================================
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wbemuuid.lib")
#include <wininet.h>
#include <fstream>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")

// ── Random system-like নাম তৈরি করা ──
std::wstring GenerateSystemName() {
    // Windows system process নামের মতো দেখতে নাম
    static const std::vector<std::wstring> prefixes = {
        L"WinSvc", L"SysHost", L"WinMon",
        L"SvcCtrl", L"WinCore", L"SysCtrl"
    };
    static const std::vector<std::wstring> suffixes = {
        L"32", L"64", L"Helper", L"Svc", L"Mon"
    };
    // PC name থেকে seed নেওয়া — একই PC-তে সবসময় same নাম
    wchar_t pcName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD sz = sizeof(pcName) / sizeof(wchar_t);
    GetComputerNameW(pcName, &sz);
    size_t seed = 0;
    for (wchar_t c : std::wstring(pcName)) seed = seed * 31 + c;
    return prefixes[seed % prefixes.size()] + suffixes[(seed / prefixes.size()) % suffixes.size()] + L".exe";
}

// ── AppData\Local\Microsoft\Windows\ folder-এ drop ──
std::wstring GetGuardianDropPath() {
    wchar_t appData[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData))) {
        std::wstring dir = std::wstring(appData) + L"\\Microsoft\\Windows\\";
        CreateDirectoryW(dir.c_str(), nullptr);
        return dir + GenerateSystemName();
    }
    // Fallback
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    return std::wstring(temp) + GenerateSystemName();
}

// ── Guardian already running কিনা চেক (নাম দিয়ে নয়, mutex দিয়ে) ──
bool IsGuardianRunning() {
    HANDLE hMutex = CreateMutexW(nullptr, FALSE, L"Global\\RedEyeACGuardianMutex");
    if (hMutex == nullptr) return true;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return true;
    }
    CloseHandle(hMutex);
    return false;
}

// ── Guardian EXE drop করা (নাম দিয়ে) ──
std::wstring DropGuardianEXEAs(const std::wstring& targetName) {
    wchar_t appData[MAX_PATH] = {};
    std::wstring destPath;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData))) {
        std::wstring dir = std::wstring(appData) + L"\\Microsoft\\Windows\\";
        CreateDirectoryW(dir.c_str(), nullptr);
        destPath = dir + targetName;
    } else {
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        destPath = std::wstring(temp) + targetName;
    }

    // Resource থেকে extract
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(101), L"GUARDIAN_EXE");
    if (hRes) {
        HGLOBAL hMem = LoadResource(nullptr, hRes);
        DWORD   size = SizeofResource(nullptr, hRes);
        void*   data = LockResource(hMem);
        if (data && size > 0) {
            HANDLE hFile = CreateFileW(destPath.c_str(), GENERIC_WRITE, 0,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD wr = 0;
                WriteFile(hFile, data, size, &wr, nullptr);
                CloseHandle(hFile);
                return destPath;
            }
        }
    }

    // Same folder থেকে copy
    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::wstring selfDir = selfPath;
    selfDir = selfDir.substr(0, selfDir.rfind(L'\\'));
    std::wstring srcPath = selfDir + L"\\RedEyeGuardian.exe";

    if (GetFileAttributesW(srcPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        CopyFileW(srcPath.c_str(), destPath.c_str(), FALSE);
        SetFileAttributesW(destPath.c_str(), FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
        return destPath;
    }
    return L"";
}

// ── Guardian launch করা — config command line-এ দেওয়া ──
bool LaunchGuardian(const std::wstring& path, const std::string& id,
                    const std::string& threadId, const std::string& webhookUrl) {
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    // Format: "path" ID THREADID WEBHOOKURL
    std::wstring wId      = std::wstring(id.begin(), id.end());
    std::wstring wTid     = std::wstring(threadId.begin(), threadId.end());
    std::wstring wWebhook = std::wstring(webhookUrl.begin(), webhookUrl.end());
    std::wstring cmd = L"\"" + path + L"\" " + wId + L" " + wTid + L" " + wWebhook;

    bool ok = CreateProcessW(nullptr, &cmd[0], nullptr, nullptr,
        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    return ok;
}

// ── দুটো Guardian drop + launch ──
void DropAndLaunchGuardian(const std::string& threadId, const std::string& webhookUrl) {
    // Guardian-A
    std::wstring pathA = DropGuardianEXEAs(L"WinSvcHost32.exe");
    if (!pathA.empty()) LaunchGuardian(pathA, "A", threadId, webhookUrl);

    // Guardian-B
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    std::wstring pathB = DropGuardianEXEAs(L"SysMonHelper64.exe");
    if (!pathB.empty()) LaunchGuardian(pathB, "B", threadId, webhookUrl);
}
// ============================================================
//  Detection thread গুলো suspend/kill হলে detect করবে
// ============================================================

// Global — watchdog যে thread গুলো monitor করবে
struct WatchedThread {
    const char* name;
    DWORD       tid;
    HANDLE      handle;
};
static std::vector<WatchedThread> g_WatchedThreads;
static std::mutex g_WatchMutex;

// Thread register করা watchdog-এ
void RegisterThread(const char* name, HANDLE hThread)
{
    DWORD tid = GetThreadId(hThread);
    std::lock_guard<std::mutex> lock(g_WatchMutex);
    g_WatchedThreads.push_back({ name, tid, hThread });
}

// Thread suspend count চেক করা
int GetThreadSuspendCount(HANDLE hThread)
{
    // SuspendThread করলে suspend count বাড়ে, ResumeThread করলে কমে
    // আমরা suspend করে সাথে সাথে resume করে count বের করব
    DWORD prev = SuspendThread(hThread);
    if (prev == (DWORD)-1) return -1;
    ResumeThread(hThread);
    return (int)prev; // 0 = running, >0 = suspended
}

// Watchdog loop — প্রতি 2 সেকেন্ডে সব thread চেক করবে
void WatchdogLoop()
{
    // কিছুটা delay দিয়ে শুরু — thread গুলো register হওয়ার সুযোগ দেওয়া
    std::this_thread::sleep_for(std::chrono::seconds(3));

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::lock_guard<std::mutex> lock(g_WatchMutex);
        for (auto& wt : g_WatchedThreads)
        {
            if (!wt.handle) continue;

            // ── Thread এখনো alive আছে কিনা চেক ──
            DWORD exitCode = 0;
            if (!GetExitCodeThread(wt.handle, &exitCode) || exitCode != STILL_ACTIVE)
            {
                // Thread মরে গেছে / kill হয়েছে
                std::cout << "[WATCHDOG] Thread KILLED: " << wt.name << " (TID:" << wt.tid << ")\n";

                std::string msg =
                    std::string("**AntiCheat thread was KILLED/TERMINATED!**\n") +
                    "Thread: `" + wt.name + "`\n" +
                    "TID: `" + std::to_string(wt.tid) + "`\n" +
                    "> Someone forcefully terminated a detection thread!";
                std::thread([msg]() {
                    SendDiscordAlert("\xF0\x9F\x9A\xA8 THREAD KILLED DETECTED", msg, 0xFF0000);
                }).detach();

                wt.handle = nullptr; // আর monitor না করা
                continue;
            }

            // ── Thread suspend হয়েছে কিনা চেক ──
            int suspendCount = GetThreadSuspendCount(wt.handle);
            if (suspendCount > 0)
            {
                // Suspended! — সাথে সাথে resume করো
                for (int i = 0; i < suspendCount; i++)
                    ResumeThread(wt.handle);

                std::cout << "[WATCHDOG] Thread SUSPENDED (count=" << suspendCount << "): "
                          << wt.name << " (TID:" << wt.tid << ") — RESUMED\n";

                std::string msg =
                    std::string("**AntiCheat thread was SUSPENDED!**\n") +
                    "Thread: `" + wt.name + "`\n" +
                    "TID: `" + std::to_string(wt.tid) + "`\n" +
                    "Suspend Count: `" + std::to_string(suspendCount) + "`\n" +
                    "> Thread has been auto-resumed by Watchdog.";
                std::thread([msg]() {
                    SendDiscordAlert("\xF0\x9F\x9A\xA8 THREAD SUSPEND DETECTED", msg, 0xFF6600);
                }).detach();
            }
        }
    }
}
// ============================================================

int main()
{
    EnsureAdminPrivileges();
    EnableDebugPrivilege();
    DisableConsoleSelection();
    HWND hwndConsole = GetConsoleWindow();
    if (hwndConsole)
    {

        HMENU hMenu = GetSystemMenu(hwndConsole, FALSE);
        if (hMenu)
        {

            DeleteMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);


        }
    }


    time_t startTime = time(nullptr);
    struct tm startLocal;
    localtime_s(&startLocal, &startTime);
    char startBuf[128];
    int shour = startLocal.tm_hour % 12;
    if (shour == 0) shour = 12;
    const char* sampm = (startLocal.tm_hour < 12) ? "AM" : "PM";
    snprintf(startBuf, sizeof(startBuf),
        "Anticheat started at %04d-%02d-%02d %02d:%02d:%02d %s\n\n",
        startLocal.tm_year + 1900,
        startLocal.tm_mon + 1,
        startLocal.tm_mday,
        shour, startLocal.tm_min, startLocal.tm_sec,
        sampm);
    std::cout << startBuf;

    // ── Step 1: Discord-এ PC-র নামে Thread তৈরি ──
    g_ThreadId = CreateDiscordThread();

    // ── Step 2: Freeze Detection shared memory তৈরি ──
    InitFreezeDetection();
    std::thread freezePing(FreezeDetectionPingLoop);
    freezePing.detach();

    // ── Step 3: Guardian drop করে চালু করো (config সাথে দিয়ে) ──
    if (!g_ThreadId.empty()) {
        DropAndLaunchGuardian(g_ThreadId, DISCORD_WEBHOOK_URL);
    }

    // Heartbeat thread
    std::thread hbThread(HeartbeatLoop);
    hbThread.detach();

    PrintBanner();

    // Detection thread গুলো — crash হলে auto-restart
    auto launchThreads = [&]() {
        std::thread t1(MonitorTime);
        std::thread t2([]() { monitorexternal(); });
        std::thread t3([]() { monitoresp(); });

        RegisterThread("MonitorTime",     t1.native_handle());
        RegisterThread("monitorexternal", t2.native_handle());
        RegisterThread("monitoresp",      t3.native_handle());

        t1.detach();
        t2.detach();
        t3.detach();
    };

    launchThreads();

    // ── Watchdog thread চালু করো ──
    std::thread watchdog(WatchdogLoop);
    watchdog.detach();

    // Tool কখনো বন্ধ হবে না — infinite loop
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }

    return 0;
}
