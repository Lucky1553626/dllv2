#include "pch.h"
#include <windows.h>
#include <psapi.h>
#include <wchar.h>
#include <wincrypt.h>
#include <comdef.h>
#include <wbemidl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <atlbase.h>
#include <atlconv.h>
#include <array>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <memory>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <fcntl.h>
#include <io.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;
using namespace std::chrono_literals;

// 新增函数：将 std::string 转换为 std::wstring
std::wstring string2wstring(const std::string& str) {
    int len;
    int slength = (int)str.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), slength, 0, 0);
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

// DLL导出接口
extern "C" {
    __declspec(dllexport) BOOL __stdcall StartMonitor();
    __declspec(dllexport) void __stdcall StopMonitor();
}

// 全局配置
constexpr long MAX_FILE_SIZE = 10 * 1024 * 1024;
constexpr int MAX_DEPTH = 4;
constexpr int MAX_PROCESSES = 5;

// 检测特征列表
vector<wstring> filePatterns = {
    L"移动到坐标", L"设置打怪列表", L"对话NPC",
    L"任务杀怪数量跳转", L"判断任务物品", L"延迟精确",
    L"角色死亡处理", L"移动挂机点", L"判断任务信息下",
    L"移至NPC", L"到指定高度", L"设置挂机方式"
};

vector<wstring> memoryPatternsText = {
    L"游戏中弹出窗口自动确认", L"目标范围内缩地", L"取身上装备PID",
    L"目标为队友时协助他", L"死亡回挂机点", L"空打地攻击不减",
    L"自动登录游戏设置区", L"出售时背包全修", L"点击查询目标ID",
    L"目标玩家或怪物", L"角色死亡时自动", L"一键锁定为目标玩家加血"
};

class ProcessScanner {
private:
    struct PatternBytes {
        vector<BYTE> utf16_le;
        vector<BYTE> gbk;
        vector<BYTE> utf8;
    };

    mutex processLock;
    mutex logMutex;
    wstring logFilePath;
    unordered_set<DWORD> scannedProcesses;
    unordered_set<DWORD> terminatedPids;
    unordered_map<DWORD, FILETIME> processCreateTimes;
    vector<PatternBytes> memoryPatternsBytes;
    bool debugMode = true;
    static const DWORD CURRENT_PID;
    wstring selfProcessPath;

    void SafeLog(const wstring& msg) {
        lock_guard<mutex> lock(logMutex);

        auto now = chrono::system_clock::now();
        time_t time = chrono::system_clock::to_time_t(now);
        tm localTime;
        localtime_s(&localTime, &time);

        wstringstream wss;
        wss << put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L" " << msg << L"\n";

        OutputDebugStringW(wss.str().c_str());

        wofstream logFile(logFilePath, ios::app);
        if (logFile.is_open()) {
            logFile.imbue(locale(""));
            logFile << wss.str();
            logFile.close();
        }
        else {
            OutputDebugStringW((L"[错误] 无法写入日志文件: " + logFilePath).c_str());
        }
    }

    void InitializeMemoryPatterns() {
        memoryPatternsBytes.clear();
        for (const auto& pattern : memoryPatternsText) {
            PatternBytes pb;

            // UTF-16 LE
            pb.utf16_le.resize(pattern.size() * sizeof(wchar_t));
            memcpy(pb.utf16_le.data(), pattern.c_str(), pattern.size() * sizeof(wchar_t));

            // GBK
            int gbkSize = WideCharToMultiByte(CP_ACP, 0, pattern.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (gbkSize > 0) {
                vector<char> buffer(gbkSize);
                WideCharToMultiByte(CP_ACP, 0, pattern.c_str(), -1, buffer.data(), gbkSize, nullptr, nullptr);
                pb.gbk.assign(buffer.begin(), buffer.end() - 1);
            }

            // UTF-8
            int utf8Size = WideCharToMultiByte(CP_UTF8, 0, pattern.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (utf8Size > 0) {
                vector<char> buffer(utf8Size);
                WideCharToMultiByte(CP_UTF8, 0, pattern.c_str(), -1, buffer.data(), utf8Size, nullptr, nullptr);
                pb.utf8.assign(buffer.begin(), buffer.end() - 1);
            }

            memoryPatternsBytes.push_back(pb);
        }
    }

    bool SearchBytes(const BYTE* buffer, size_t bufferSize, const BYTE* pattern, size_t patternSize) {
        if (patternSize == 0 || bufferSize < patternSize) return false;
        for (size_t i = 0; i <= bufferSize - patternSize; ++i) {
            if (memcmp(buffer + i, pattern, patternSize) == 0) {
                return true;
            }
        }
        return false;
    }

    wstring GetProcessPath(DWORD pid) {
        wchar_t path[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            if (debugMode) SafeLog(L"[错误] 无法打开进程: " + to_wstring(pid));
            return L"";
        }

        BOOL success = QueryFullProcessImageNameW(hProcess, 0, path, &size);
        CloseHandle(hProcess);
        return success ? wstring(path) : L"";
    }

    bool IsSystemProcess(const wstring& path) {
        wchar_t sysPaths[3][MAX_PATH] = { 0 };

        if (!GetSystemDirectoryW(sysPaths[0], MAX_PATH)) {
            SafeLog(L"[错误] 无法获取系统目录");
            return false;
        }

        if (!GetWindowsDirectoryW(sysPaths[1], MAX_PATH)) {
            SafeLog(L"[错误] 无法获取Windows目录");
            return false;
        }

        if (!GetEnvironmentVariableW(L"ProgramFiles", sysPaths[2], MAX_PATH)) {
            SafeLog(L"[错误] 无法获取ProgramFiles目录");
            return false;
        }

        for (const auto& sysPath : sysPaths) {
            if (wcslen(sysPath) > 0 && path.find(sysPath) == 0) {
                return true;
            }
        }
        return false;
    }

    bool ScanProcessMemory(DWORD pid) {
        if (pid == CURRENT_PID) return false;

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            SafeLog(L"[内存错误] 无法打开进程: " + to_wstring(pid));
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi;
        bool found = false;

        for (LPVOID address = 0;
            VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi);
            address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize) {

            if (mbi.State != MEM_COMMIT || mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                continue;

            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                buffer.resize(bytesRead); // 仅处理实际读取的数据

                for (const auto& pattern : memoryPatternsBytes) {
                    if (!found && SearchBytes(buffer.data(), buffer.size(), pattern.utf16_le.data(), pattern.utf16_le.size())) {
                        SafeLog(L"[内存检测] PID " + to_wstring(pid) + L" 发现UTF-16特征");
                        found = true;
                    }
                    if (!found && SearchBytes(buffer.data(), buffer.size(), pattern.gbk.data(), pattern.gbk.size())) {
                        SafeLog(L"[内存检测] PID " + to_wstring(pid) + L" 发现GBK特征");
                        found = true;
                    }
                    if (!found && SearchBytes(buffer.data(), buffer.size(), pattern.utf8.data(), pattern.utf8.size())) {
                        SafeLog(L"[内存检测] PID " + to_wstring(pid) + L" 发现UTF-8特征");
                        found = true;
                    }
                    if (found) break;
                }
            }
        }

        CloseHandle(hProcess);
        if (found) {
            return TerminateMaliciousProcess(pid);
        }
        return false;
    }

    void ScanFile(const wstring& path, DWORD pid) {
        {
            lock_guard<mutex> lock(processLock);
            if (terminatedPids.count(pid)) return;
        }

        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return;

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > MAX_FILE_SIZE) {
            CloseHandle(hFile);
            return;
        }

        vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart));
        DWORD read = 0;
        if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            CloseHandle(hFile);
            return;
        }
        CloseHandle(hFile);

        UINT codePage = CP_ACP;
        if (buffer.size() >= 2) {
            if (buffer[0] == 0xFF && buffer[1] == 0xFE) codePage = 1200;
            else if (buffer[0] == 0xFE && buffer[1] == 0xFF) codePage = 1201;
            else if (buffer.size() >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
                codePage = CP_UTF8;
        }

        int wideLen = MultiByteToWideChar(codePage, MB_ERR_INVALID_CHARS,
            reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), nullptr, 0);
        if (wideLen <= 0) return;

        wstring content;
        content.resize(wideLen);
        MultiByteToWideChar(codePage, 0, reinterpret_cast<char*>(buffer.data()),
            static_cast<int>(buffer.size()), &content[0], wideLen);

        for (const auto& term : filePatterns) {
            size_t pos = 0;
            while ((pos = content.find(term, pos)) != wstring::npos) {
                SafeLog(L"[文件检测] 发现特征: " + term + L" 在文件: " + path);
                if (TerminateMaliciousProcess(pid)) return;
                pos += term.length();
            }
        }
    }

    void ScanDirectory(const wstring& path, int depth, DWORD pid) {
        {
            lock_guard<mutex> lock(processLock);
            if (terminatedPids.count(pid)) return;
        }

        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((path + L"\\*").c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) continue;

            wstring fullPath = path + L"\\" + findData.cFileName;
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (depth < MAX_DEPTH) ScanDirectory(fullPath, depth + 1, pid);
            }
            else {
                if (PathMatchSpecW(fullPath.c_str(), L"*.txt;*.chm;*.spt;*.cfg")) {
                    ScanFile(fullPath, pid);
                }
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }

    bool TerminateMaliciousProcess(DWORD pid) {
        lock_guard<mutex> lock(processLock);
        if (terminatedPids.count(pid)) return true;

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) {
            DWORD lastError = GetLastError();
            SafeLog(L"[终止失败] 无法打开进程: " + to_wstring(pid) + L" 错误码: " + to_wstring(lastError));
            return false;
        }

        BOOL success = TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);

        if (success) {
            terminatedPids.insert(pid);
            SafeLog(L"[进程终止] 成功终止 PID: " + to_wstring(pid));
            return true;
        }
        else {
            DWORD lastError = GetLastError();
            SafeLog(L"[终止错误] PID: " + to_wstring(pid) + L" 错误码: " + to_wstring(lastError));
            return false;
        }
    }

    FILETIME GetProcessCreateTime(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return FILETIME();

        FILETIME createTime, exitTime, kernelTime, userTime;
        GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime);
        CloseHandle(hProcess);
        return createTime;
    }

    bool IsProcessActive(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return false;

        DWORD exitCode;
        GetExitCodeProcess(hProcess, &exitCode);
        CloseHandle(hProcess);
        return exitCode == STILL_ACTIVE;
    }

    void RemoveProcessRecord(DWORD pid) {
        lock_guard<mutex> lock(processLock);
        scannedProcesses.erase(pid);
        processCreateTimes.erase(pid);
        terminatedPids.erase(pid);
    }

    bool IsRunAsAdmin() {
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        PSID AdministratorsGroup = nullptr;

        BOOL ok = AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &AdministratorsGroup
        );

        if (ok) {
            if (!CheckTokenMembership(nullptr, AdministratorsGroup, &ok)) {
                ok = FALSE;
            }
            FreeSid(AdministratorsGroup);
        }

        return ok == TRUE;
    }

public:
    thread wmiThread;
    thread scanThread;
    HANDLE hExitEvent = nullptr;

    ProcessScanner() {
        wchar_t exePath[MAX_PATH] = { 0 };
        if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
            MessageBoxW(0, L"无法获取EXE路径", L"错误", MB_ICONERROR);
            throw runtime_error("路径错误");
        }
        selfProcessPath = wstring(exePath);
        PathRemoveFileSpecW(exePath);
        logFilePath = wstring(exePath) + L"\\ProcessMonitor.log";

        // 强制创建日志文件
        HANDLE hFile = CreateFileW(
            logFilePath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            wstring msg = L"创建日志文件失败，错误码: " + to_wstring(err);
            MessageBoxW(0, msg.c_str(), L"错误", MB_ICONERROR);
            throw runtime_error("文件创建失败");
        }
        CloseHandle(hFile);
        SafeLog(L"[系统] ====== 监控服务启动 ======");

        if (!IsRunAsAdmin()) {
            MessageBoxW(0, L"需要管理员权限运行", L"权限错误", MB_ICONERROR);
            throw runtime_error("权限不足");
        }

        hExitEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!hExitEvent) {
            SafeLog(L"[错误] 退出事件创建失败");
            throw runtime_error("事件创建失败");
        }

        InitializeMemoryPatterns();  // 初始化内存特征模式
    }

    ~ProcessScanner() {
        SafeLog(L"[系统] ====== 正在关闭服务 ======");

        if (hExitEvent) {
            SetEvent(hExitEvent);
            if (wmiThread.joinable()) wmiThread.join();
            if (scanThread.joinable()) scanThread.join();
            CloseHandle(hExitEvent);
        }

        CoUninitialize();
        SafeLog(L"[系统] ====== 服务已停止 ======");
    }

    void RunFullScan() {
        SafeLog(L"[扫描] 开始全系统进程扫描");
        vector<DWORD> pids(1024);
        DWORD needed;

        if (EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &needed)) {
            pids.resize(needed / sizeof(DWORD));
            SafeLog(L"[扫描] 发现进程数量: " + to_wstring(pids.size()));

            vector<thread> workers;
            for (auto pid : pids) {
                if (pid == 0 || pid == CURRENT_PID) continue;

                workers.emplace_back([this, pid] {
                    ProcessScanJob(pid);
                    });

                if (workers.size() >= MAX_PROCESSES) {
                    for (auto& t : workers) t.join();
                    workers.clear();
                }
            }

            for (auto& t : workers) t.join();
        }
        else {
            SafeLog(L"[错误] 进程枚举失败: " + to_wstring(GetLastError()));
        }
        SafeLog(L"[扫描] 全系统扫描完成");
    }

    void WMIEventLoop() {
        HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hr)) {
            SafeLog(L"[错误] 线程COM初始化失败: " + to_wstring(hr));
            return;
        }

        CComPtr<IWbemLocator> pLoc;
        hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (void**)&pLoc);
        if (FAILED(hr)) {
            SafeLog(L"[错误] 创建WMI定位器失败: " + to_wstring(hr));
            CoUninitialize();
            return;
        }

        CComPtr<IWbemServices> pSvc;
        hr = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            nullptr,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
            &pSvc
        );
        if (FAILED(hr)) {
            SafeLog(L"[错误] 连接WMI服务器失败: " + to_wstring(hr));
            CoUninitialize();
            return;
        }

        hr = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE
        );

        if (FAILED(hr)) {
            SafeLog(L"[错误] 设置代理安全失败: " + to_wstring(hr));
            CoUninitialize();
            return;
        }

        class EventSink : public IWbemObjectSink {
            ProcessScanner* scanner;
            bool isStartEvent;
        public:
            EventSink(ProcessScanner* s, bool start) : scanner(s), isStartEvent(start) {}

            STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
                if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
                    *ppv = this;
                    return S_OK;
                }
                return E_NOINTERFACE;
            }

            STDMETHODIMP_(ULONG) AddRef() override { return 1; }
            STDMETHODIMP_(ULONG) Release() override { return 1; }

            STDMETHODIMP Indicate(LONG count, IWbemClassObject** objs) override {
                for (LONG i = 0; i < count; ++i) {
                    VARIANT vtProp;
                    VariantInit(&vtProp);

                    if (SUCCEEDED(objs[i]->Get(L"TargetInstance", 0, &vtProp, 0, 0))) {
                        if (vtProp.vt == VT_UNKNOWN) {
                            CComPtr<IWbemClassObject> pTargetInstance;
                            vtProp.punkVal->QueryInterface(IID_IWbemClassObject, (void**)&pTargetInstance);
                            if (pTargetInstance) {
                                VARIANT pid;
                                VariantInit(&pid);
                                if (SUCCEEDED(pTargetInstance->Get(L"ProcessId", 0, &pid, 0, 0))) {
                                    if (isStartEvent) {
                                        scanner->OnProcessCreated(pid.uintVal);
                                    }
                                    else {
                                        scanner->OnProcessExited(pid.uintVal);
                                    }
                                    VariantClear(&pid);
                                }
                            }
                        }
                        VariantClear(&vtProp);
                    }
                }
                return WBEM_S_NO_ERROR;
            }

            STDMETHODIMP SetStatus(LONG, HRESULT, BSTR, IWbemClassObject*) override {
                return WBEM_S_NO_ERROR;
            }
        };

        EventSink startSink(this, true);
        EventSink stopSink(this, false);

        hr = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_DYNAMIC_CLOAKING,
            NULL);

        HRESULT hr1 = pSvc->ExecNotificationQueryAsync(
            _bstr_t("WQL"),
            _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
            WBEM_FLAG_SEND_STATUS,
            nullptr,
            &startSink
        );

        if (FAILED(hr1)) {
            SafeLog(L"[错误] 注册 __InstanceCreationEvent 失败: " + to_wstring(hr1));
        }
        else {
            SafeLog(L"[WMI] 注册 __InstanceCreationEvent 成功");
        }

        HRESULT hr2 = pSvc->ExecNotificationQueryAsync(
            _bstr_t("WQL"),
            _bstr_t("SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
            WBEM_FLAG_SEND_STATUS,
            nullptr,
            &stopSink
        );

        if (FAILED(hr2)) {
            SafeLog(L"[错误] 注册 __InstanceDeletionEvent 失败: " + to_wstring(hr2));
        }
        else {
            SafeLog(L"[WMI] 注册 __InstanceDeletionEvent 成功");
        }

        if (FAILED(hr1) || FAILED(hr2)) {
            SafeLog(L"[错误] WMI事件注册失败");
            pSvc.Release();
            pLoc.Release();
            CoUninitialize();
            return;
        }

        SafeLog(L"[WMI] 事件监听已启动");

        // 修改此处，使用 this 指针
        while (WaitForSingleObject(this->hExitEvent, 100) == WAIT_TIMEOUT) {
            MSG msg;
            while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }

        pSvc->CancelAsyncCall(&startSink);
        pSvc->CancelAsyncCall(&stopSink);
        SafeLog(L"[WMI] 事件监听已停止");

        pSvc.Release();
        pLoc.Release();
        CoUninitialize();
    }

    void ProcessScanJob(DWORD pid) {
        if (pid == CURRENT_PID) return;

        if (!IsProcessActive(pid)) {
            RemoveProcessRecord(pid);
            return;
        }

        FILETIME createTime = GetProcessCreateTime(pid);
        {
            lock_guard<mutex> lock(processLock);
            auto it = processCreateTimes.find(pid);
            if (it != processCreateTimes.end() &&
                CompareFileTime(&it->second, &createTime) == 0) {
                return;
            }
            processCreateTimes[pid] = createTime;
        }

        wstring path = GetProcessPath(pid);
        if (path.empty()) {
            SafeLog(L"[错误] 无法获取进程路径: PID " + to_wstring(pid));
            return;
        }

        // 过滤自身进程同目录同名的进程
        if (path == selfProcessPath) {
            SafeLog(L"[过滤] 跳过与自身相同的进程: PID " + to_wstring(pid));
            return;
        }

        wstring processName = PathFindFileNameW(path.c_str());
        SafeLog(L"[扫描] 正在检查进程: " + processName + L" (PID: " + to_wstring(pid) + L")");

        if (IsSystemProcess(path)) {
            SafeLog(L"[系统] 跳过系统进程: " + path);
            return;
        }

        bool terminated = ScanProcessMemory(pid);
        if (!terminated) {
            wstring dirPath = path.substr(0, path.find_last_of(L'\\'));
            SafeLog(L"[扫描] 检查目录: " + dirPath);
            ScanDirectory(dirPath, 0, pid);
        }
    }

    void OnProcessCreated(DWORD pid) {
        lock_guard<mutex> lock(processLock);
        thread([this, pid] {
            ProcessScanJob(pid);
            }).detach();
    }

    void OnProcessExited(DWORD pid) {
        RemoveProcessRecord(pid);
        SafeLog(L"[进程退出] PID: " + to_wstring(pid));
    }
};

const DWORD ProcessScanner::CURRENT_PID = GetCurrentProcessId();

mutex g_instanceMutex;
unique_ptr<ProcessScanner> g_scanner;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        try {
            thread monitorThread([] {
                StartMonitor();
                });
            monitorThread.detach();
        }
        catch (const exception& e) {
            wstring errMsg = L"[错误] 启动监控服务时发生异常: " + string2wstring(e.what());
            OutputDebugStringW(errMsg.c_str());
        }
        break;
    case DLL_PROCESS_DETACH:
        StopMonitor();
        break;
    }
    return TRUE;
}

__declspec(dllexport) BOOL __stdcall StartMonitor() {
    lock_guard<mutex> lock(g_instanceMutex);
    if (g_scanner) {
        OutputDebugStringW(L"[警告] 监控服务已运行");
        return FALSE;
    }

    try {
        g_scanner = make_unique<ProcessScanner>();

        g_scanner->scanThread = thread([] {
            OutputDebugStringW(L"[线程] 全盘扫描线程启动");
            g_scanner->RunFullScan();
            OutputDebugStringW(L"[线程] 全盘扫描线程退出");
            });

        g_scanner->wmiThread = thread([] {
            OutputDebugStringW(L"[线程] WMI监控线程启动");
            g_scanner->WMIEventLoop();
            OutputDebugStringW(L"[线程] WMI监控线程退出");
            });

        g_scanner->scanThread.detach();
        g_scanner->wmiThread.detach();

        return TRUE;
    }
    catch (const exception& e) {
        wstring errMsg = L"[错误] 启动失败: " + string2wstring(e.what());
        OutputDebugStringW(errMsg.c_str());
        return FALSE;
    }
}

__declspec(dllexport) void __stdcall StopMonitor() {
    lock_guard<mutex> lock(g_instanceMutex);
    if (!g_scanner) return;

    if (g_scanner->hExitEvent) {
        SetEvent(g_scanner->hExitEvent);
    }

    if (g_scanner->wmiThread.joinable()) {
        g_scanner->wmiThread.join();
    }
    if (g_scanner->scanThread.joinable()) {
        g_scanner->scanThread.join();
    }

    g_scanner.reset();
    OutputDebugStringW(L"[系统] 监控服务已停止");
}
