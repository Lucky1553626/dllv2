#pragma once
#include "SecurityAnalyzer.h"
#include <windows.h>
#include <psapi.h>
#include <wincrypt.h>
#include <wbemidl.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <chrono>
#include <softpub.h>
#include <sstream>    // 解决 wstringstream 问题
#include <iomanip>    // 解决 put_time 问题
#include <unordered_map> 
#include <atlbase.h>  // 解决 CComPtr 问题
#include <comdef.h>   // 解决 _com_error 问题

class ProcessScanner {
public:
    ProcessScanner();
    ~ProcessScanner();

    void RunFullScan();
    void WMIEventLoop();
    void StartMonitoring();
    void StopMonitoring();
    void OnProcessCreated(DWORD pid);
    void OnProcessExited(DWORD pid);
    static const std::unordered_set<std::wstring> COMMERCIAL_CAS;

private:
    static const DWORD CURRENT_PID;
    constexpr static long MAX_FILE_SIZE = 10 * 1024 * 1024;
    constexpr static int MAX_DEPTH = 4;
    constexpr static int MAX_PROCESSES = 5;
    vector<wstring> memoryPatternsText = {
        L"游戏中弹出窗口自动确认", L"目标范围内缩地", L"取身上装备PID",
        L"目标为队友时协助他", L"死亡回挂机点", L"空打地攻击不减",
        L"自动登录游戏设置区", L"出售时背包全修", L"点击查询目标ID",
        L"目标玩家或怪物", L"角色死亡时自动", L"一键锁定为目标玩家加血"
    };

    vector<wstring> filePatterns = {
        L"移动到坐标", L"设置打怪列表", L"对话NPC",
        L"任务杀怪数量跳转", L"判断任务物品", L"延迟精确",
        L"角色死亡处理", L"移动挂机点", L"判断任务信息下",
        L"移至NPC", L"到指定高度", L"设置挂机方式"
    };

    unordered_map<DWORD, FILETIME> processCreateTimes;

    struct PatternBytes {
        std::vector<BYTE> utf16_le;
        std::vector<BYTE> gbk;
        std::vector<BYTE> utf8;
    };

    SecurityAnalyzer m_securityCheck;
    std::wstring logFilePath;
    std::unordered_set<DWORD> scannedProcesses;
    std::unordered_set<DWORD> terminatedPids;
    std::unordered_map<DWORD, FILETIME> processCreateTimes;
    std::vector<PatternBytes> memoryPatternsBytes;
    std::wstring selfProcessPath;

    HANDLE hExitEvent;
    std::thread scanThread;
    std::thread wmiThread;
    std::mutex processLock;
    std::mutex logMutex;
    bool debugMode = true;

    // Core methods
    void InitializeMemoryPatterns();
    void SafeLog(const std::wstring& msg);
    bool ScanProcessMemory(DWORD pid);
    bool TerminateMaliciousProcess(DWORD pid);
    void ProcessScanJob(DWORD pid);
    void ScanFile(const std::wstring& path, DWORD pid);
    void ScanDirectory(const std::wstring& path, int depth, DWORD pid);
    bool IsSystemProcess(const std::wstring& path);
    wstring GetProcessPath(DWORD pid);
    bool IsCommercialSigned(const std::wstring& filePath);
    void TerminateSelfProcess();

    // Helper methods
    FILETIME GetProcessCreateTime(DWORD pid);
    bool IsProcessActive(DWORD pid);
    void RemoveProcessRecord(DWORD pid);
    static bool SearchBytes(const BYTE* buffer, size_t bufferSize,
        const BYTE* pattern, size_t patternSize);
};
using CComVariant = ATL::CComVariant;
using CComPtr = ATL::CComPtr<IWbemLocator>;
using CComQIPtr = ATL::CComQIPtr<IWbemClassObject>;