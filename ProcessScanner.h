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
#include <sstream>    // ��� wstringstream ����
#include <iomanip>    // ��� put_time ����
#include <unordered_map> 
#include <atlbase.h>  // ��� CComPtr ����
#include <comdef.h>   // ��� _com_error ����

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
        L"��Ϸ�е��������Զ�ȷ��", L"Ŀ�귶Χ������", L"ȡ����װ��PID",
        L"Ŀ��Ϊ����ʱЭ����", L"�����عһ���", L"�մ�ع�������",
        L"�Զ���¼��Ϸ������", L"����ʱ����ȫ��", L"�����ѯĿ��ID",
        L"Ŀ����һ����", L"��ɫ����ʱ�Զ�", L"һ������ΪĿ����Ҽ�Ѫ"
    };

    vector<wstring> filePatterns = {
        L"�ƶ�������", L"���ô���б�", L"�Ի�NPC",
        L"����ɱ��������ת", L"�ж�������Ʒ", L"�ӳپ�ȷ",
        L"��ɫ��������", L"�ƶ��һ���", L"�ж�������Ϣ��",
        L"����NPC", L"��ָ���߶�", L"���ùһ���ʽ"
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