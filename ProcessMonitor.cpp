#include "ProcessScanner.h"
#include <fstream>
#include <algorithm>
#include <atlconv.h>
#include <wintrust.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <comdef.h>
#include <chrono>
#include <random>
#include <wincrypt.h>
#include <comutil.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "comsuppw.lib")

using namespace std;
using namespace chrono_literals;
const DWORD ProcessScanner::CURRENT_PID = GetCurrentProcessId();


// 静态成员初始化
const unordered_set<wstring> ProcessScanner::COMMERCIAL_CAS = {
    L"DigiCert", L"Symantec", L"VeriSign",
    L"GlobalSign", L"Comodo", L"Entrust",
    L"Thawte", L"GeoTrust",
    L"Microsoft Code Signing PCA",
    L"Baltimore CyberTrust Root"
};

ProcessScanner::ProcessScanner() {
    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        throw runtime_error("无法获取可执行文件路径");
    }
    selfProcessPath = exePath;
    PathRemoveFileSpecW(exePath);
    logFilePath = wstring(exePath) + L"\\ProcessMonitor.log";

    // 初始化退出事件
    hExitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hExitEvent) {
        throw runtime_error("无法创建退出事件");
    }

    InitializeMemoryPatterns();

    // 立即执行首次安全检测
    SecurityAnalyzer initialCheck;
    if (initialCheck.AnalyzeEnvironment()) {
        TerminateSelfProcess();
    }
}

ProcessScanner::~ProcessScanner() {
    StopMonitoring();
    if (hExitEvent) {
        CloseHandle(hExitEvent);
    }
}

void ProcessScanner::InitializeMemoryPatterns() {
    memoryPatternsBytes.clear();
    for (const auto& pattern : memoryPatternsText) {
        PatternBytes pb;

        // UTF-16 LE
        pb.utf16_le.resize(pattern.size() * sizeof(wchar_t));
        memcpy(pb.utf16_le.data(), pattern.c_str(), pattern.size() * sizeof(wchar_t));

        // GBK编码
        int gbkSize = WideCharToMultiByte(CP_ACP, 0, pattern.c_str(), -1,
            nullptr, 0, nullptr, nullptr);
        if (gbkSize > 0) {
            vector<char> buffer(gbkSize);
            WideCharToMultiByte(CP_ACP, 0, pattern.c_str(), -1,
                buffer.data(), gbkSize, nullptr, nullptr);
            pb.gbk.assign(buffer.begin(), buffer.end() - 1);
        }

        // UTF-8编码
        int utf8Size = WideCharToMultiByte(CP_UTF8, 0, pattern.c_str(), -1,
            nullptr, 0, nullptr, nullptr);
        if (utf8Size > 0) {
            vector<char> buffer(utf8Size);
            WideCharToMultiByte(CP_UTF8, 0, pattern.c_str(), -1,
                buffer.data(), utf8Size, nullptr, nullptr);
            pb.utf8.assign(buffer.begin(), buffer.end() - 1);
        }

        memoryPatternsBytes.push_back(pb);
    }
}

void ProcessScanner::SafeLog(const wstring& msg) {
    lock_guard<mutex> lock(logMutex);

    // 获取当前时间
    auto now = chrono::system_clock::now();
    time_t time = chrono::system_clock::to_time_t(now);
    tm localTime;
    localtime_s(&localTime, &time);

    // 构建日志条目
    wstringstream wss;
    wss << put_time(&localTime, L"%Y-%m-%d %H:%M:%S")
        << L" [" << GetCurrentProcessId() << L"] "
        << msg << L"\n";

    // 输出到调试器和日志文件
    OutputDebugStringW(wss.str().c_str());

    wofstream logFile(logFilePath, ios::app);
    if (logFile) {
        logFile.imbue(locale(""));
        logFile << wss.str();
    }
    else {
        OutputDebugStringW(L"[错误] 无法写入日志文件");
    }
}

bool ProcessScanner::SearchBytes(const BYTE* buffer, size_t bufferSize,
    const BYTE* pattern, size_t patternSize) {
    if (patternSize == 0 || bufferSize < patternSize) return false;

    const BYTE* end = buffer + bufferSize - patternSize;
    for (const BYTE* pos = buffer; pos <= end; ++pos) {
        if (memcmp(pos, pattern, patternSize) == 0) {
            return true;
        }
    }
    return false;
}

wstring ProcessScanner::GetProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        SafeLog(L"[错误] OpenProcess失败 PID: " + to_wstring(pid)
            + L" 错误码: " + to_wstring(GetLastError()));
        return L"";
    }

    wchar_t path[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    BOOL success = QueryFullProcessImageNameW(hProcess, 0, path, &size);
    CloseHandle(hProcess);

    return success ? wstring(path) : L"";
}

bool ProcessScanner::IsSystemProcess(const wstring& path) {
    static const vector<wstring> systemPaths = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
        L"C:\\Program Files",
        L"C:\\Program Files (x86)"
    };

    for (const auto& sysPath : systemPaths) {
        if (path.find(sysPath) == 0) {
            return true;
        }
    }
    return false;
}

bool ProcessScanner::ScanProcessMemory(DWORD pid) {
    if (pid == CURRENT_PID) return false;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        SafeLog(L"[错误] 无法打开进程内存 PID: " + to_wstring(pid)
            + L" 错误码: " + to_wstring(GetLastError()));
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* address = 0;
    bool found = false;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {

            vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                mbi.RegionSize, &bytesRead)) {
                buffer.resize(bytesRead);

                for (const auto& pattern : memoryPatternsBytes) {
                    bool match = false;
                    if (!pattern.utf16_le.empty()) {
                        match |= SearchBytes(buffer.data(), buffer.size(),
                            pattern.utf16_le.data(), pattern.utf16_le.size());
                    }
                    if (!pattern.gbk.empty()) {
                        match |= SearchBytes(buffer.data(), buffer.size(),
                            pattern.gbk.data(), pattern.gbk.size());
                    }
                    if (!pattern.utf8.empty()) {
                        match |= SearchBytes(buffer.data(), buffer.size(),
                            pattern.utf8.data(), pattern.utf8.size());
                    }

                    if (match) {
                        found = true;
                        SafeLog(L"[内存检测] 在PID " + to_wstring(pid)
                            + L" 中发现恶意特征码");
                        break;
                    }
                }
            }
        }
        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return found ? TerminateMaliciousProcess(pid) : false;
}

void ProcessScanner::ScanFile(const wstring& path, DWORD pid) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SafeLog(L"[文件错误] 无法打开文件: " + path
            + L" 错误码: " + to_wstring(GetLastError()));
        return;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > MAX_FILE_SIZE) {
        CloseHandle(hFile);
        return;
    }

    vector<BYTE> buffer(fileSize.QuadPart);
    DWORD read = 0;
    if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
        CloseHandle(hFile);
        SafeLog(L"[文件错误] 读取失败: " + path
            + L" 错误码: " + to_wstring(GetLastError()));
        return;
    }
    CloseHandle(hFile);

    // 自动检测编码
    UINT codePage = CP_ACP;
    if (buffer.size() >= 2) {
        if (buffer[0] == 0xFF && buffer[1] == 0xFE) codePage = 1200;  // UTF-16 LE
        else if (buffer[0] == 0xFE && buffer[1] == 0xFF) codePage = 1201; // UTF-16 BE
        else if (buffer.size() >= 3 &&
            buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) {
            codePage = CP_UTF8;  // UTF-8 BOM
        }
    }

    // 转换为宽字符
    int wideLen = MultiByteToWideChar(codePage, MB_ERR_INVALID_CHARS,
        reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()),
        nullptr, 0);
    if (wideLen <= 0) {
        SafeLog(L"[编码错误] 无法转换文件内容: " + path);
        return;
    }

    wstring content;
    content.resize(wideLen);
    MultiByteToWideChar(codePage, 0, reinterpret_cast<char*>(buffer.data()),
        static_cast<int>(buffer.size()), content.data(), wideLen);

    // 多模式匹配
    for (const auto& term : filePatterns) {
        size_t pos = 0;
        while ((pos = content.find(term, pos)) != wstring::npos) {
            SafeLog(L"[文件检测] 在 " + path + L" 中发现特征: " + term);
            if (TerminateMaliciousProcess(pid)) {
                return; // 终止后立即返回
            }
            pos += term.length();
        }
    }
}

void ProcessScanner::ScanDirectory(const wstring& path, int depth, DWORD pid) {
    WIN32_FIND_DATAW findData;
    wstring searchPath = path + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        SafeLog(L"[目录错误] 无法扫描: " + path
            + L" 错误码: " + to_wstring(GetLastError()));
        return;
    }

    do {
        if (wcscmp(findData.cFileName, L".") == 0 ||
            wcscmp(findData.cFileName, L"..") == 0) continue;

        wstring fullPath = path + L"\\" + findData.cFileName;
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (depth < MAX_DEPTH) {
                ScanDirectory(fullPath, depth + 1, pid);
            }
        }
        else {
            if (PathMatchSpecW(const_cast<LPWSTR>(fullPath.c_str()),
                const_cast<LPWSTR>(L"*.txt;*.chm;*.spt;*.cfg"))) {
                ScanFile(fullPath, pid);
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

bool ProcessScanner::TerminateMaliciousProcess(DWORD pid) {
    lock_guard<mutex> lock(processLock);
    if (terminatedPids.count(pid)) {
        return true; // 已经终止过
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        SafeLog(L"[终止失败] 打开进程失败 PID: " + to_wstring(pid)
            + L" 错误码: " + to_wstring(GetLastError()));
        return false;
    }

    BOOL success = TerminateProcess(hProcess, 1);
    DWORD lastError = GetLastError();
    CloseHandle(hProcess);

    if (success) {
        terminatedPids.insert(pid);
        SafeLog(L"[成功终止] PID: " + to_wstring(pid));

        // 终止自身
        TerminateSelfProcess();
        return true;
    }
    else {
        SafeLog(L"[终止失败] PID: " + to_wstring(pid)
            + L" 错误码: " + to_wstring(lastError));
        return false;
    }
}

FILETIME ProcessScanner::GetProcessCreateTime(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FILETIME();

    FILETIME createTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        createTime.dwLowDateTime = 0;
        createTime.dwHighDateTime = 0;
    }
    CloseHandle(hProcess);
    return createTime;
}
bool SecurityAnalyzer::CheckVMPerformance() {
    PDH_HQUERY query;
    PDH_STATUS status = PdhOpenQuery(nullptr, 0, &query);
    if (status != ERROR_SUCCESS) return false;

    PDH_HCOUNTER counter;
    status = PdhAddCounterW(query, L"\\Processor(_Total)\\% Processor Time", 0, &counter);
    if (status != ERROR_SUCCESS) {
        PdhCloseQuery(query);
        return false;
    }

    PdhCollectQueryData(query);
    Sleep(1000);
    PdhCollectQueryData(query);

    PDH_FMT_COUNTERVALUE value;
    status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &value);
    PdhCloseQuery(query);

    return (status == ERROR_SUCCESS && value.doubleValue < 5.0);
}
bool ProcessScanner::IsProcessActive(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    DWORD exitCode;
    GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);
    return (exitCode == STILL_ACTIVE);
}

void ProcessScanner::RemoveProcessRecord(DWORD pid) {
    lock_guard<mutex> lock(processLock);
    scannedProcesses.erase(pid);
    processCreateTimes.erase(pid);
    terminatedPids.erase(pid);
}

bool ProcessScanner::IsCommercialSigned(const wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(fileInfo) };
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData = { sizeof(winTrustData) };
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(nullptr, &WVTPolicyGUID, &winTrustData);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    // 获取证书链
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD encoding, contentType, formatType;
    BOOL result = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &encoding,
        &contentType,
        &formatType,
        &hStore,
        &hMsg,
        nullptr);

    if (!result || !hStore || !hMsg) {
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return false;
    }

    DWORD numSigners = 0;
    DWORD signerInfoSize = sizeof(numSigners);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &numSigners, &signerInfoSize);

    bool isCommercial = false;
    for (DWORD i = 0; i < numSigners; ++i) {
        DWORD cbSignerInfo = 0;
        CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, nullptr, &cbSignerInfo);
        if (cbSignerInfo == 0) continue;

        vector<BYTE> signerInfo(cbSignerInfo);
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, signerInfo.data(), &cbSignerInfo)) {
            continue;
        }

        PCMSG_SIGNER_INFO pSignerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerInfo.data());
        CERT_INFO certInfo = { 0 };
        certInfo.Issuer = pSignerInfo->Issuer;
        certInfo.SerialNumber = pSignerInfo->SerialNumber;

        PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            &certInfo,
            nullptr);
        if (!pCertContext) continue;

        // 验证证书链
        CERT_CHAIN_PARA chainPara = { sizeof(chainPara) };
        PCCERT_CHAIN_CONTEXT pChainContext = nullptr;
        if (CertGetCertificateChain(nullptr, pCertContext, nullptr, hStore,
            &chainPara, 0, nullptr, &pChainContext)) {
            if (pChainContext->cChain > 0) {
                PCERT_SIMPLE_CHAIN pSimpleChain = pChainContext->rgpChain[0];
                if (pSimpleChain->cElement > 0) {
                    PCERT_CHAIN_ELEMENT pElement = pSimpleChain->rgpElement[pSimpleChain->cElement - 1];
                    PCCERT_CONTEXT pRootCert = pElement->pCertContext;

                    // 检查根证书颁发者
                    DWORD nameSize = CertGetNameStringW(pRootCert,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0, nullptr, nullptr, 0);
                    if (nameSize > 0) {
                        vector<wchar_t> issuerName(nameSize);
                        CertGetNameStringW(pRootCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0, nullptr, issuerName.data(), nameSize);

                        for (const auto& ca : COMMERCIAL_CAS) {
                            if (wcsstr(issuerName.data(), ca.c_str())) {
                                isCommercial = true;
                                break;
                            }
                        }
                    }
                }
            }
            CertFreeCertificateChain(pChainContext);
        }
        CertFreeCertificateContext(pCertContext);
        if (isCommercial) break;
    }

    CertCloseStore(hStore, 0);
    CryptMsgClose(hMsg);
    return isCommercial;
}

void ProcessScanner::TerminateSelfProcess() {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId());
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
    ExitProcess(0);
}

void ProcessScanner::ProcessScanJob(DWORD pid) {
    if (pid == 0 || pid == CURRENT_PID) return;

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
            return; // 已扫描过相同版本进程
        }
        processCreateTimes[pid] = createTime;
    }

    wstring path = GetProcessPath(pid);
    if (path.empty()) {
        SafeLog(L"[错误] 无法获取进程路径 PID: " + to_wstring(pid));
        return;
    }

    // 跳过自身进程
    if (path == selfProcessPath) {
        SafeLog(L"[过滤] 跳过自身进程 PID: " + to_wstring(pid));
        return;
    }

    // 商业签名检查
    if (IsCommercialSigned(path)) {
        SafeLog(L"[签名验证] 可信签名进程: " + path);
        return;
    }

    // 系统进程过滤
    if (IsSystemProcess(path)) {
        SafeLog(L"[系统进程] 已跳过: " + path);
        return;
    }

    // 执行扫描
    wstring processName = PathFindFileNameW(path.c_str());
    SafeLog(L"[扫描] 正在检查进程: " + processName + L" (PID: " + to_wstring(pid) + L")");

    bool terminated = ScanProcessMemory(pid);
    if (!terminated) {
        wstring dirPath = path.substr(0, path.find_last_of(L'\\'));
        ScanDirectory(dirPath, 0, pid);
    }
}

void ProcessScanner::RunFullScan() {
    SafeLog(L"[全盘扫描] 启动");
    DWORD pids[2048], needed;

    if (!EnumProcesses(pids, sizeof(pids), &needed)) {
        SafeLog(L"[错误] 进程枚举失败: " + to_wstring(GetLastError()));
        return;
    }

    DWORD processCount = needed / sizeof(DWORD);
    vector<thread> workers;
    workers.reserve(MAX_PROCESSES);

    for (DWORD i = 0; i < processCount; ++i) {
        if (pids[i] == 0 || pids[i] == CURRENT_PID) continue;

        workers.emplace_back([this, pid = pids[i]] {
            ProcessScanJob(pid);
            });

        // 控制并发数量
        if (workers.size() >= MAX_PROCESSES) {
            for (auto& t : workers) t.join();
            workers.clear();
        }
    }

    // 等待剩余线程
    for (auto& t : workers) t.join();
    SafeLog(L"[全盘扫描] 完成");
}

void ProcessScanner::WMIEventLoop() {
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        SafeLog(L"[WMI错误] CoInitializeEx失败: " + to_wstring(hr));
        return;
    }

    CComPtr<IWbemLocator> pLoc;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) {
        SafeLog(L"[WMI错误] 创建WbemLocator失败: " + to_wstring(hr));
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
        SafeLog(L"[WMI错误] 连接WMI服务失败: " + to_wstring(hr));
        pLoc.Release();
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
        SafeLog(L"[WMI错误] 设置安全代理失败: " + to_wstring(hr));
        pSvc.Release();
        pLoc.Release();
        CoUninitialize();
        return;
    }

    class EventSink : public IWbemObjectSink {
    public:
        EventSink(ProcessScanner* scanner, bool isCreation)
            : m_scanner(scanner), m_isCreation(isCreation) {
        }

        STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
            if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
                *ppv = this;
                return S_OK;
            }
            return E_NOINTERFACE;
        }

        STDMETHODIMP_(ULONG) AddRef() override { return 1; }
        STDMETHODIMP_(ULONG) Release() override { return 1; }

        STDMETHODIMP Indicate(LONG lObjectCount, IWbemClassObject** apObjArray) override {
            for (LONG i = 0; i < lObjectCount; ++i) {
                CComVariant vtProp;
                HRESULT hr = apObjArray[i]->Get(L"TargetInstance", 0, &vtProp, 0, 0);
                if (SUCCEEDED(hr) && vtProp.vt == VT_UNKNOWN) {
                    CComQIPtr<IWbemClassObject> pTarget(vtProp.punkVal);
                    if (pTarget) {
                        CComVariant vtPid;
                        pTarget->Get(L"ProcessId", 0, &vtPid, 0, 0);
                        if (vtPid.vt == VT_I4) {
                            if (m_isCreation) {
                                m_scanner->OnProcessCreated(vtPid.lVal);
                            }
                            else {
                                m_scanner->OnProcessExited(vtPid.lVal);
                            }
                        }
                    }
                }
            }
            return WBEM_S_NO_ERROR;
        }

        STDMETHODIMP SetStatus(LONG lFlags, HRESULT hResult,
            BSTR strParam, IWbemClassObject* pObjParam) override {
            return WBEM_S_NO_ERROR;
        }

    private:
        ProcessScanner* m_scanner;
        bool m_isCreation;
    };

    EventSink* pStartSink = new EventSink(this, true);
    EventSink* pStopSink = new EventSink(this, false);

    hr = pSvc->ExecNotificationQueryAsync(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        nullptr,
        pStartSink
    );

    if (FAILED(hr)) {
        SafeLog(L"[WMI错误] 注册进程创建事件失败: " + to_wstring(hr));
        delete pStartSink;
        delete pStopSink;
        pSvc.Release();
        pLoc.Release();
        CoUninitialize();
        return;
    }

    hr = pSvc->ExecNotificationQueryAsync(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        nullptr,
        pStopSink
    );

    if (FAILED(hr)) {
        SafeLog(L"[WMI错误] 注册进程退出事件失败: " + to_wstring(hr));
        pSvc->CancelAsyncCall(pStartSink);
        delete pStartSink;
        delete pStopSink;
        pSvc.Release();
        pLoc.Release();
        CoUninitialize();
        return;
    }

    SafeLog(L"[WMI监控] 事件监听已启动");

    // 消息循环
    while (WaitForSingleObject(hExitEvent, 100) == WAIT_TIMEOUT) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    // 清理
    pSvc->CancelAsyncCall(pStartSink);
    pSvc->CancelAsyncCall(pStopSink);
    SafeLog(L"[WMI监控] 已停止");

    delete pStartSink;
    delete pStopSink;
    pSvc.Release();
    pLoc.Release();
    CoUninitialize();
}

void ProcessScanner::OnProcessCreated(DWORD pid) {
    lock_guard<mutex> lock(processLock);
    thread([this, pid] {
        ProcessScanJob(pid);
        }).detach();
}

void ProcessScanner::OnProcessExited(DWORD pid) {
    lock_guard<mutex> lock(processLock);
    RemoveProcessRecord(pid);
    SafeLog(L"[进程退出] PID: " + to_wstring(pid));
}

void ProcessScanner::StartMonitoring() {
    scanThread = thread([this] {
        SafeLog(L"[监控启动] 全盘扫描线程");
        RunFullScan();

        // 定期扫描
        while (WaitForSingleObject(hExitEvent, 300000) == WAIT_TIMEOUT) { // 5分钟
            SafeLog(L"[定期扫描] 开始新一轮扫描");
            RunFullScan();
        }
        });

    wmiThread = thread([this] {
        SafeLog(L"[监控启动] WMI监控线程");
        WMIEventLoop();
        });
}

void ProcessScanner::StopMonitoring() {
    SetEvent(hExitEvent);

    if (scanThread.joinable()) {
        scanThread.join();
    }
    if (wmiThread.joinable()) {
        wmiThread.join();
    }

    SafeLog(L"[监控停止] 所有线程已退出");
}