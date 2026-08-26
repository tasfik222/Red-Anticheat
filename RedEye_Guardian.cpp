// ============================================================
//  RED EYE GUARDIAN — Dual Guardian System
//  Guardian-A এবং Guardian-B একে অপরকে monitor করে
//  যেকোনো একটা মারলে অন্যটা detect করে + restart করে
//  AntiCheat thread গুলোও দুজনেই monitor করে
// ============================================================

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <ctime>
#include <wininet.h>
#include <shlobj.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

// ── Global config ──
static std::string  g_WebhookUrl = "";
static std::string  g_ThreadId   = "";
static std::string  g_SessionKey = "";  // Web dashboard session key (main AntiCheat থেকে পাওয়া)
static const std::string API_BASE_URL = "";
static std::wstring g_AntiCheatExeName = L"Red Eye - AntiCheat for HD-Player.exe";
static std::atomic<bool> g_Running{ true };

// ── এটা Guardian-A নাকি Guardian-B? ──
// Command line argument দিয়ে আসবে: "A" বা "B"
static std::string g_GuardianId = "A";

// Guardian-A এবং Guardian-B এর নাম
static const std::wstring GUARDIAN_A_NAME = L"WinSvcHost32.exe";
static const std::wstring GUARDIAN_B_NAME = L"SysMonHelper64.exe";

// ── Helpers ──
std::string GetTimestamp() {
    time_t now = time(nullptr); struct tm t; localtime_s(&t, &now);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        t.tm_year+1900, t.tm_mon+1, t.tm_mday,
        t.tm_hour, t.tm_min, t.tm_sec);
    return buf;
}

std::string JsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        if      (c == '"')  o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else                o += c;
    }
    return o;
}

std::string GetPCName() {
    char b[MAX_COMPUTERNAME_LENGTH+1] = {}; DWORD s = sizeof(b);
    GetComputerNameA(b, &s); return b;
}
std::string GetUsername() {
    char b[256] = {}; DWORD s = sizeof(b);
    GetUserNameA(b, &s); return b;
}
std::string GetMachineInfo() {
    return "\n> **PC:** `" + GetPCName() + "`"
           "\n> **User:** `" + GetUsername() + "`"
           "\n> **Guardian:** `" + g_GuardianId + "`";
}

// ── HTTP POST ──
void HttpPost(const std::string& url, const std::string& payload) {
    URL_COMPONENTSA uc = {}; uc.dwStructSize = sizeof(uc);
    char host[256] = {}, path[1024] = {};
    uc.lpszHostName = host; uc.dwHostNameLength = sizeof(host);
    uc.lpszUrlPath  = path; uc.dwUrlPathLength  = sizeof(path);
    InternetCrackUrlA(url.c_str(), 0, 0, &uc);
    HINTERNET hI = InternetOpenA("RedEyeGuardian", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
    if (!hI) return;
    HINTERNET hC = InternetConnectA(hI, host, INTERNET_DEFAULT_HTTPS_PORT, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hC) { InternetCloseHandle(hI); return; }
    const char* acc[] = { "application/json", NULL };
    HINTERNET hR = HttpOpenRequestA(hC, "POST", path, 0, 0, acc, INTERNET_FLAG_SECURE|INTERNET_FLAG_RELOAD, 0);
    if (!hR) { InternetCloseHandle(hC); InternetCloseHandle(hI); return; }
    std::string hdr = "Content-Type: application/json\r\n";
    HttpSendRequestA(hR, hdr.c_str(), (DWORD)hdr.size(), (LPVOID)payload.c_str(), (DWORD)payload.size());
    InternetCloseHandle(hR); InternetCloseHandle(hC); InternetCloseHandle(hI);
}

// ============================================================
//  WEB DASHBOARD API INTEGRATION (Guardian → same dashboard as AntiCheat)
// ============================================================
#ifndef INTERNET_OPTION_SECURE_PROTOCOLS
#define INTERNET_OPTION_SECURE_PROTOCOLS 84
#endif
#ifndef SECURITY_FLAG_SECURE
#define SECURITY_FLAG_SECURE 0x00000001
#endif

void ApiPostEvent(const std::string& payload) {
    if (g_SessionKey.empty()) return;

    std::string fullUrl = API_BASE_URL + "/api/event";
    URL_COMPONENTSA uc = {}; uc.dwStructSize = sizeof(uc);
    char host[256]={}, path[1024]={};
    uc.lpszHostName=host; uc.dwHostNameLength=sizeof(host);
    uc.lpszUrlPath=path;  uc.dwUrlPathLength=sizeof(path);
    if (!InternetCrackUrlA(fullUrl.c_str(),0,0,&uc)) return;

    HINTERNET hI=InternetOpenA("RedEyeGuardianAPI",INTERNET_OPEN_TYPE_DIRECT,0,0,0);
    if(!hI) return;
    HINTERNET hC=InternetConnectA(hI,host,INTERNET_DEFAULT_HTTPS_PORT,0,0,INTERNET_SERVICE_HTTP,0,0);
    if(!hC){InternetCloseHandle(hI); return;}
    const char* acc[]={"application/json",NULL};
    HINTERNET hR=HttpOpenRequestA(hC,"POST",path,0,0,acc,
        INTERNET_FLAG_SECURE|INTERNET_FLAG_RELOAD|
        INTERNET_FLAG_IGNORE_CERT_CN_INVALID|INTERNET_FLAG_NO_CACHE_WRITE,0);
    if(!hR){InternetCloseHandle(hC);InternetCloseHandle(hI); return;}

    // Cloudflare requires TLS 1.2+; WinINet defaults don't reliably enable it.
    DWORD secFlags = 0; DWORD secLen = sizeof(secFlags);
    InternetQueryOptionA(hR, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, &secLen);
    secFlags |= SECURITY_FLAG_SECURE | 0x00000800;
    InternetSetOptionA(hR, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    DWORD protoFlags = 0x00000800 /*TLS1.2*/ | 0x00002000 /*TLS1.3*/ | 0x00000200 /*TLS1.1*/;
    InternetSetOptionA(hI, INTERNET_OPTION_SECURE_PROTOCOLS, &protoFlags, sizeof(protoFlags));

    std::string hdrs = "Content-Type: application/json\r\nX-API-Key: " + g_SessionKey + "\r\n";
    HttpSendRequestA(hR,hdrs.c_str(),(DWORD)hdrs.size(),(LPVOID)payload.c_str(),(DWORD)payload.size());

    char buf[512]={}; DWORD rd=0;
    while(InternetReadFile(hR,buf,sizeof(buf)-1,&rd)&&rd>0){rd=0;} // response এর দরকার নেই, শুধু drain করা

    InternetCloseHandle(hR);InternetCloseHandle(hC);InternetCloseHandle(hI);
}

// Discord alert-এর মতোই website dashboard-এও event পাঠানো
void SendWebEvent(const std::string& type, const std::string& title,
                  const std::string& desc, const std::string& severity) {
    if (g_SessionKey.empty()) return;
    std::string payload =
        "{\"type\":\""+JsonEscape(type)+"\","
        "\"title\":\""+JsonEscape(title)+"\","
        "\"description\":\""+JsonEscape(desc)+"\","
        "\"severity\":\""+severity+"\"}";
    std::thread([payload](){ ApiPostEvent(payload); }).detach();
}
// ============================================================

void SendAlert(const std::string& title, const std::string& desc, int color = 0xFF0000) {
    if (g_ThreadId.empty() || g_WebhookUrl.empty()) return;
    std::string fullDesc = desc + GetMachineInfo();
    std::string payload =
        "{\"embeds\":[{\"title\":\"" + JsonEscape(title) + "\","
        "\"description\":\"" + JsonEscape(fullDesc) + "\","
        "\"color\":" + std::to_string(color) + ","
        "\"footer\":{\"text\":\"RED EYE Guardian-" + g_GuardianId + " | " + GetTimestamp() + "\"}}]}";
    HttpPost(g_WebhookUrl + "?thread_id=" + g_ThreadId, payload);

    // Website dashboard-এও একই notification পাঠানো
    std::string severity = "HIGH";
    if (color == 0xFFAA00 || color == 0xFF6600) severity = "MEDIUM";
    else if (color == 0x3498DB || color == 0x00CC44) severity = "LOW";
    SendWebEvent(title, title, desc, severity);
}

// ============================================================
//  HEARTBEAT TIMEOUT DETECTION
//  AntiCheat-এর ONLINE message 30 সেকেন্ডের বেশি না আসলে alert
// ============================================================

// AntiCheat-এর heartbeat timeout (সেকেন্ডে) — AntiCheat-এর interval + 5s buffer
static const int HEARTBEAT_TIMEOUT_SECONDS = 35;

// AntiCheat shared memory থেকে ping counter check করে timeout detect করা
void HeartbeatTimeoutLoop()
{
    // Shared memory open হওয়ার জন্য wait
    HANDLE hMem = nullptr;
    LONG*  pCounter = nullptr;

    for (int retry = 0; retry < 30; retry++) {
        hMem = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, L"Global\\RedEyeACHeartbeat");
        if (hMem) break;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    if (!hMem) return;

    pCounter = (LONG*)MapViewOfFile(hMem, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LONG) * 4);
    if (!pCounter) { CloseHandle(hMem); return; }

    LONG lastCount = pCounter[0];
    DWORD lastChangeTime = GetTickCount();
    bool alertSent = false;

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        LONG curCount = pCounter[0];
        DWORD now = GetTickCount();

        if (curCount != lastCount) {
            // Counter বাড়ছে — tool চলছে
            lastCount = curCount;
            lastChangeTime = now;

            if (alertSent) {
                // আগে alert গিয়েছিল, এখন resume হয়েছে
                alertSent = false;
                std::string msg =
                    "**AntiCheat is responding again!**\n"
                    "Ping Counter: `" + std::to_string(curCount) + "`\n"
                    "> Tool has resumed normal operation.";
                std::thread([msg]() {
                    SendAlert("\xE2\x9C\x85 ANTICHEAT RESUMED", msg, 0x00CC44);
                }).detach();
            }
        } else {
            // Counter বাড়েনি
            DWORD elapsed = (now - lastChangeTime) / 1000; // seconds

            if ((int)elapsed >= HEARTBEAT_TIMEOUT_SECONDS && !alertSent) {
                alertSent = true;

                // Process alive কিনা check
                LONG pid = pCounter[1];
                bool processAlive = false;
                if (pid != 0) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
                    if (hProc) { processAlive = true; CloseHandle(hProc); }
                }

                std::string reason = processAlive
                    ? "Process is running but **not responding**!\n> Tool may be **frozen/paused** by a cheat tool."
                    : "Process is **NOT running**!\n> Tool has been **killed or crashed**.";

                std::string msg =
                    "**No heartbeat received for " + std::to_string(elapsed) + " seconds!**\n"
                    "Last Ping: `" + std::to_string(curCount) + "`\n"
                    "PID: `" + std::to_string(pid) + "`\n"
                    + reason + "\n"
                    "> Expected heartbeat every `30 seconds`.";

                std::thread([msg]() {
                    SendAlert("\xF0\x9F\x9A\xA8 ANTICHEAT NOT RESPONDING", msg, 0xFF0000);
                }).detach();
            }
        }
    }
}
// ============================================================
//  AntiCheat-এর shared memory ping counter চেক করে
//  Counter না বাড়লে — tool freeze/pause হয়েছে
// ============================================================
void FreezeMonitorLoop()
{
    // Shared memory open করা
    HANDLE hMem = nullptr;
    LONG*  pCounter = nullptr;

    // AntiCheat চালু না হওয়া পর্যন্ত wait
    for (int retry = 0; retry < 30; retry++) {
        hMem = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, L"Global\\RedEyeACHeartbeat");
        if (hMem) break;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    if (!hMem) return; // AntiCheat shared memory পাওয়া যায়নি

    pCounter = (LONG*)MapViewOfFile(hMem, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LONG) * 4);
    if (!pCounter) { CloseHandle(hMem); return; }

    LONG lastCount   = pCounter[0];
    LONG lastPid     = pCounter[1];
    int  freezeCount = 0;
    bool wasFrozen   = false;
    DWORD lastAlertTime = 0;

    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        LONG curCount = pCounter[0];
        LONG curPid   = pCounter[1];

        // ── Process kill হয়েছে কিনা চেক ──
        if (curPid != 0) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)curPid);
            if (!hProc) {
                // Process মরে গেছে
                DWORD now = GetTickCount();
                if (now - lastAlertTime > 5000) {
                    lastAlertTime = now;
                    std::string msg =
                        "**RED EYE AntiCheat process was KILLED!**\n"
                        "PID: `" + std::to_string(curPid) + "`\n"
                        "> Someone forcefully terminated the AntiCheat!\n"
                        "> Cheat injection may be in progress!";
                    std::thread([msg]() {
                        SendAlert("\xF0\x9F\x94\xB4 ANTICHEAT KILLED", msg, 0xFF0000);
                    }).detach();
                }
                std::this_thread::sleep_for(std::chrono::seconds(3));
                continue;
            }
            CloseHandle(hProc);
        }

        // ── Ping counter চেক ──
        if (curCount == lastCount) {
            // Counter বাড়েনি — tool হয়তো freeze হয়েছে
            freezeCount++;

            if (freezeCount >= 3 && !wasFrozen) {
                // ৩ বার check করেও counter না বাড়লে = freeze
                wasFrozen = true;
                DWORD now = GetTickCount();
                if (now - lastAlertTime > 5000) {
                    lastAlertTime = now;

                    // CPU usage চেক করা
                    FILETIME idleTime, kernelTime, userTime;
                    GetSystemTimes(&idleTime, &kernelTime, &userTime);

                    std::string msg =
                        "**RED EYE AntiCheat has been FROZEN/PAUSED!**\n"
                        "PID: `" + std::to_string(curPid) + "`\n"
                        "Ping Counter: `Stopped at " + std::to_string(curCount) + "`\n"
                        "Freeze Duration: `~" + std::to_string(freezeCount * 1500 / 1000) + " seconds`\n"
                        "> Someone paused/froze the AntiCheat tool!\n"
                        "> Possible cheat injection during freeze window!";
                    std::thread([msg]() {
                        SendAlert("\xF0\x9F\x9A\xA8 ANTICHEAT FROZEN/PAUSED", msg, 0xFF0000);
                    }).detach();
                }
            }
        } else {
            // Counter বাড়ছে — tool চলছে
            if (wasFrozen) {
                // Freeze শেষ হয়েছে
                wasFrozen = false;
                std::string msg =
                    "**RED EYE AntiCheat has RESUMED!**\n"
                    "PID: `" + std::to_string(curPid) + "`\n"
                    "Ping Counter: `" + std::to_string(curCount) + "`\n"
                    "> AntiCheat is running again after freeze.\n"
                    "> **Scan recommended** — cheat may have been injected during freeze!";
                std::thread([msg]() {
                    SendAlert("\xE2\x9A\xA0 ANTICHEAT RESUMED AFTER FREEZE", msg, 0xFFAA00);
                }).detach();
            }
            freezeCount = 0;
            lastCount = curCount;
        }
    }
}
// ============================================================

// ============================================================
//  GUARDIAN MUTUAL FREEZE DETECTION
//  প্রতিটা Guardian নিজের ping counter shared memory-তে রাখে
//  Partner সেটা চেক করে — না বাড়লে freeze detect করে
// ============================================================

// Guardian নিজের shared memory name
// Guardian-A: "Global\RedEyeGuardianA"
// Guardian-B: "Global\RedEyeGuardianB"

static HANDLE g_hSelfMem   = nullptr;
static LONG*  g_pSelfPing  = nullptr;

// নিজের shared memory তৈরি করা
void InitGuardianSharedMem()
{
    std::wstring memName = L"Global\\RedEyeGuardian" +
        std::wstring(g_GuardianId.begin(), g_GuardianId.end());

    g_hSelfMem = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, sizeof(LONG) * 2, memName.c_str());

    if (g_hSelfMem) {
        g_pSelfPing = (LONG*)MapViewOfFile(
            g_hSelfMem, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LONG) * 2);
        if (g_pSelfPing) {
            g_pSelfPing[0] = 0;                         // ping counter
            g_pSelfPing[1] = (LONG)GetCurrentProcessId(); // PID
        }
    }
}

// নিজের ping counter বাড়ানো (প্রতি 500ms)
void GuardianSelfPingLoop()
{
    while (true) {
        if (g_pSelfPing)
            InterlockedIncrement(&g_pSelfPing[0]);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// Forward declaration
void RestartGuardian(const std::wstring& guardianName, const std::string& guardianId);

// Partner Guardian-এর freeze চেক করা
void GuardianPartnerFreezeLoop()
{
    // Partner-এর shared memory name
    std::string partnerId   = (g_GuardianId == "A") ? "B" : "A";
    std::wstring partnerMem = L"Global\\RedEyeGuardian" +
        std::wstring(partnerId.begin(), partnerId.end());
    std::wstring partnerExe = (g_GuardianId == "A") ? GUARDIAN_B_NAME : GUARDIAN_A_NAME;

    // Partner চালু হওয়ার জন্য wait
    HANDLE hPartnerMem = nullptr;
    LONG*  pPartnerPing = nullptr;

    for (int retry = 0; retry < 20; retry++) {
        hPartnerMem = OpenFileMappingW(FILE_MAP_READ, FALSE, partnerMem.c_str());
        if (hPartnerMem) break;
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    if (!hPartnerMem) return; // Partner চালু হয়নি

    pPartnerPing = (LONG*)MapViewOfFile(hPartnerMem, FILE_MAP_READ, 0, 0, sizeof(LONG) * 2);
    if (!pPartnerPing) { CloseHandle(hPartnerMem); return; }

    LONG lastCount    = pPartnerPing[0];
    DWORD lastChange  = GetTickCount();
    bool alertSent    = false;
    const int TIMEOUT = 10; // 10 সেকেন্ড

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        LONG  curCount = pPartnerPing[0];
        LONG  partPid  = pPartnerPing[1];
        DWORD now      = GetTickCount();

        if (curCount != lastCount) {
            // Partner চলছে
            lastCount   = curCount;
            lastChange  = now;

            if (alertSent) {
                alertSent = false;
                std::string msg =
                    "**Guardian-" + partnerId + " has RESUMED!**\n"
                    "PID: `" + std::to_string(partPid) + "`\n"
                    "> Guardian is operational again.";
                std::thread([msg]() {
                    SendAlert("\xE2\x9C\x85 GUARDIAN RESUMED", msg, 0x00CC44);
                }).detach();
            }
        } else {
            DWORD elapsed = (now - lastChange) / 1000;

            if ((int)elapsed >= TIMEOUT && !alertSent) {
                alertSent = true;

                // Process alive কিনা check
                bool alive = false;
                if (partPid) {
                    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)partPid);
                    if (h) { alive = true; CloseHandle(h); }
                }

                std::string reason = alive
                    ? "Process alive but **NOT responding**!\n> Guardian may be **frozen/paused** by cheater!"
                    : "Process **NOT found**!\n> Guardian has been **killed**!";

                std::string msg =
                    "**Guardian-" + partnerId + " is NOT responding!**\n"
                    "No ping for `" + std::to_string(elapsed) + " seconds`\n"
                    "PID: `" + std::to_string(partPid) + "`\n"
                    + reason + "\n"
                    "> Detected by Guardian-" + g_GuardianId;

                std::thread([msg, partnerExe, partnerId, this_id = g_GuardianId]() {
                    SendAlert("\xF0\x9F\x9A\xA8 GUARDIAN-" + partnerId + " FROZEN/KILLED",
                        msg, 0xFF0000);
                }).detach();

                // Partner restart করার চেষ্টা
                RestartGuardian(partnerExe, partnerId);
            }
        }
    }
}
// ============================================================
void ReceiveConfig() {
    // Guardian-A: pipe "RedEyeACConfig"
    // Guardian-B: pipe "RedEyeACConfigB"
    std::wstring pipeName = (g_GuardianId == "A")
        ? L"\\\\.\\pipe\\RedEyeACConfig"
        : L"\\\\.\\pipe\\RedEyeACConfigB";

    while (g_ThreadId.empty() || g_WebhookUrl.empty()) {
        HANDLE hPipe = CreateNamedPipeW(pipeName.c_str(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,
            1, 4096, 4096, 30000, nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        bool connected = ConnectNamedPipe(hPipe, nullptr) ||
                         GetLastError() == ERROR_PIPE_CONNECTED;
        if (connected) {
            char buf[4096] = {}; DWORD rd = 0;
            if (ReadFile(hPipe, buf, sizeof(buf)-1, &rd, nullptr) && rd > 0) {
                std::string data(buf, rd);
                size_t sep = data.find('|');
                if (sep != std::string::npos) {
                    g_ThreadId   = data.substr(0, sep);
                    g_WebhookUrl = data.substr(sep + 1);
                }
            }
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        if (g_ThreadId.empty() || g_WebhookUrl.empty())
            std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

// ── Process PID খোঁজা ──
DWORD FindProcessPID(const std::wstring& exeName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (std::wstring(pe.szExeFile) == exeName) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

// ── AntiCheat thread গুলো নেওয়া ──
struct TInfo { DWORD tid; HANDLE handle; };
std::vector<TInfo> GetThreads(DWORD pid) {
    std::vector<TInfo> v;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return v;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (h) v.push_back({ te.th32ThreadID, h });
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return v;
}

int GetSuspendCount(HANDLE h) {
    DWORD p = SuspendThread(h);
    if (p == (DWORD)-1) return -1;
    ResumeThread(h);
    return (int)p;
}

// ── Guardian EXE path বের করা ──
std::wstring GetGuardianPath(const std::wstring& name) {
    wchar_t appData[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData)))
        return std::wstring(appData) + L"\\Microsoft\\Windows\\" + name;
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    return std::wstring(temp) + name;
}

// ── Guardian restart করা ──
void RestartGuardian(const std::wstring& guardianName, const std::string& guardianId) {
    std::wstring path = GetGuardianPath(guardianName);
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // Same folder থেকে copy করা
        wchar_t selfPath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        CopyFileW(selfPath, path.c_str(), FALSE);
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    }

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"\"" + path + L"\" " + std::wstring(guardianId.begin(), guardianId.end());
    CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
}

// ── Main Monitor Loop ──
void MonitorLoop() {
    DWORD acPid = 0;
    std::vector<TInfo> acThreads;
    bool acWasAlive = false;
    bool partnerWasAlive = false;

    // Partner Guardian name
    std::wstring partnerName = (g_GuardianId == "A") ? GUARDIAN_B_NAME : GUARDIAN_A_NAME;
    std::string  partnerId   = (g_GuardianId == "A") ? "B" : "A";

    while (g_Running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // ── 1. AntiCheat process চেক ──
        DWORD curAcPid = FindProcessPID(g_AntiCheatExeName);

        if (acWasAlive && curAcPid == 0) {
            SendAlert("\xF0\x9F\x94\xB4 ANTICHEAT PROCESS KILLED",
                "**RED EYE AntiCheat has been terminated!**\n"
                "> Someone forcefully killed the AntiCheat!\n"
                "> Possible cheat activity on this PC.",
                0xFF0000);
            acWasAlive = false;
            for (auto& t : acThreads) if (t.handle) CloseHandle(t.handle);
            acThreads.clear(); acPid = 0;
        }

        if (curAcPid != 0) {
            if (curAcPid != acPid) {
                for (auto& t : acThreads) if (t.handle) CloseHandle(t.handle);
                acThreads = GetThreads(curAcPid);
                acPid = curAcPid; acWasAlive = true;
            }

            // AntiCheat thread গুলো চেক
            for (auto& t : acThreads) {
                if (!t.handle) continue;

                DWORD ex = 0;
                if (!GetExitCodeThread(t.handle, &ex) || ex != STILL_ACTIVE) {
                    std::string msg =
                        "**AntiCheat thread was KILLED!**\n"
                        "TID: `" + std::to_string(t.tid) + "`\n"
                        "> Someone terminated a detection thread!";
                    std::thread([msg]() { SendAlert("\xF0\x9F\x9A\xA8 THREAD KILLED", msg, 0xFF0000); }).detach();
                    CloseHandle(t.handle); t.handle = nullptr;
                    continue;
                }

                int sc = GetSuspendCount(t.handle);
                if (sc > 0) {
                    for (int i = 0; i < sc; i++) ResumeThread(t.handle);
                    std::string msg =
                        "**AntiCheat thread was SUSPENDED!**\n"
                        "TID: `" + std::to_string(t.tid) + "`\n"
                        "Suspend Count: `" + std::to_string(sc) + "`\n"
                        "> **Auto-resumed** by Guardian-" + g_GuardianId + ".\n"
                        "> Cheat tool tried to freeze detection!";
                    std::thread([msg]() { SendAlert("\xF0\x9F\x9A\xA8 THREAD SUSPENDED", msg, 0xFF6600); }).detach();
                }
            }
        }

        // ── 2. Partner Guardian চেক ──
        DWORD partnerPid = FindProcessPID(partnerName);

        if (partnerWasAlive && partnerPid == 0) {
            // Partner মরে গেছে — alert + restart
            std::string msg =
                "**Guardian-" + partnerId + " was KILLED!**\n"
                "> Guardian-" + g_GuardianId + " detected the kill.\n"
                "> Attempting to restart Guardian-" + partnerId + "...";
            SendAlert("\xF0\x9F\x9A\xA8 GUARDIAN-" + partnerId + " KILLED", msg, 0xFF0000);

            // Restart partner
            RestartGuardian(partnerName, partnerId);
            partnerWasAlive = false;
        }

        if (partnerPid != 0) {
            partnerWasAlive = true;

            // Partner-এর সব thread চেক — suspend হয়েছে কিনা
            std::vector<TInfo> partnerThreads = GetThreads(partnerPid);
            for (auto& t : partnerThreads) {
                if (!t.handle) continue;
                int sc = GetSuspendCount(t.handle);
                if (sc > 0) {
                    for (int i = 0; i < sc; i++) ResumeThread(t.handle);
                    std::string msg =
                        "**Guardian-" + partnerId + " thread was SUSPENDED!**\n"
                        "TID: `" + std::to_string(t.tid) + "`\n"
                        "> **Auto-resumed** by Guardian-" + g_GuardianId + ".\n"
                        "> Cheat tool tried to disable the Guardian!";
                    std::thread([msg]() { SendAlert("\xF0\x9F\x9A\xA8 GUARDIAN SUSPENDED", msg, 0xFF6600); }).detach();
                }
                CloseHandle(t.handle);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    // Command line থেকে config নেওয়া
    // Format: Guardian.exe <ID> <THREADID> <WEBHOOKURL> <SESSIONKEY>
    if (argc >= 2) g_GuardianId = argv[1];
    if (argc >= 3) g_ThreadId   = argv[2];
    if (argc >= 4) g_WebhookUrl = argv[3];
    if (argc >= 5) g_SessionKey = argv[4];

    // Mutex — Guardian-A এবং Guardian-B আলাদা mutex
    std::wstring mutexName = L"Global\\RedEyeGuardian" +
        std::wstring(g_GuardianId.begin(), g_GuardianId.end()) + L"Mutex";
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0;
    }

    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // Config না পেলে wait করা (fallback)
    if (g_ThreadId.empty() || g_WebhookUrl.empty()) {
        ReceiveConfig();
    }

    // Startup alert
    SendAlert("\xF0\x9F\x9B\xA1 GUARDIAN-" + g_GuardianId + " ACTIVE",
        "RED EYE Guardian-" + g_GuardianId + " has started.\n"
        "Monitoring AntiCheat threads + Partner Guardian.\n"
        "> **Freeze/Pause detection ACTIVE!**",
        0x3498DB);

    // ── Freeze Detection + Heartbeat Timeout Monitor (শুধু Guardian-A) ──
    if (g_GuardianId == "A") {
        std::thread freezeMon(FreezeMonitorLoop);
        freezeMon.detach();

        std::thread timeoutMon(HeartbeatTimeoutLoop);
        timeoutMon.detach();
    }

    // Monitor loop — crash হলে restart
    while (true) {
        try { MonitorLoop(); } catch (...) {}
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}
