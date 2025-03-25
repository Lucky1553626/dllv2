#include "SecurityAnalyzer.h"
#include <chrono>
#include <random>
#include <psapi.h>
#include <sstream>
#include <comdef.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "advapi32.lib")

SecurityAnalyzer::SecurityAnalyzer() {
    m_detectors = {
        { [this]() { return CheckHypervisorFlags(); }, 0.20f },
        { [this]() { return CheckKVM(); }, 0.18f },
        { [this]() { return CheckVMPerformance(); }, 0.15f },
        { [this]() { return CheckCPUBrand(); }, 0.15f },
        { [this]() { return CheckDeviceTree(); }, 0.12f },
        { [this]() { return CheckRAMSize(); }, 0.10f },
        { [this]() { return CheckGPUPresence(); }, 0.10f }
    };
}

bool SecurityAnalyzer::CheckRegistryEntries() {
    const wchar_t* suspectKeys[] = {
        L"HARDWARE\\ACPI\\DSDT\\VBOX__",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE&DEV_CAFE",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
    };

    for (auto key : suspectKeys) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

bool SecurityAnalyzer::CheckProcessList() {
    const wchar_t* sandboxProcesses[] = {
        L"vboxservice.exe",   // VirtualBox
        L"vmwaretray.exe",    // VMware
        L"xenservice.exe",    // Xen
        L"qemu-ga.exe",       // QEMU
        L"prl_cc.exe"         // Parallels
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    bool found = false;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            for (auto name : sandboxProcesses) {
                if (_wcsicmp(pe.szExeFile, name) == 0) {
                    found = true;
                    break;
                }
            }
        } while (!found && Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return found;
}

bool SecurityAnalyzer::CheckDiskSize() {
    ULARGE_INTEGER totalBytes;
    if (!GetDiskFreeSpaceExW(L"C:\\", nullptr, &totalBytes, nullptr)) {
        return false;
    }
    return (totalBytes.QuadPart < (40LL * 1024 * 1024 * 1024)); // 小于40GB视为可疑
}

bool SecurityAnalyzer::AnalyzeEnvironment() {
    if (!IsRunAsAdmin()) {
        LogDetection(L"需要管理员权限运行");
        SafeExit();
    }

    float suspicionScore = 0;
    for (const auto& detector : m_detectors) {
        if (detector.detector()) {
            suspicionScore += detector.weight;
            std::wstringstream wss;
            wss << L"检测到风险特征，当前评分: " << suspicionScore;
            LogDetection(wss.str().c_str());

            if (suspicionScore >= THRESHOLD) {
                LogDetection(L"达到风险阈值，终止进程");
                SafeExit();
                return true;
            }
        }
    }
    return false;
}

// 完整检测方法实现
bool SecurityAnalyzer::CheckHypervisorFlags() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

bool SecurityAnalyzer::CheckKVM() {
    unsigned int eax = 0;
    __cpuid(0x40000000, eax, 0, 0, 0);
    return (eax >= 0x40000010);
}

bool SecurityAnalyzer::CheckCPUBrand() {
    char brand[49] = { 0 };
    __cpuid(0x80000002, reinterpret_cast<int*>(&brand[0]),
        reinterpret_cast<int*>(&brand[4]),
        reinterpret_cast<int*>(&brand[8]),
        reinterpret_cast<int*>(&brand[12]));
    __cpuid(0x80000003, reinterpret_cast<int*>(&brand[16]),
        reinterpret_cast<int*>(&brand[20]),
        reinterpret_cast<int*>(&brand[24]),
        reinterpret_cast<int*>(&brand[28]));
    __cpuid(0x80000004, reinterpret_cast<int*>(&brand[32]),
        reinterpret_cast<int*>(&brand[36]),
        reinterpret_cast<int*>(&brand[40]),
        reinterpret_cast<int*>(&brand[44]));
    return strstr(brand, "KVM") || strstr(brand, "QEMU");
}

bool SecurityAnalyzer::CheckRAMSize() {
    MEMORYSTATUSEX statex = { sizeof(statex) };
    GlobalMemoryStatusEx(&statex);
    return (statex.ullTotalPhys < (4LL * 1024 * 1024 * 1024));
}

bool SecurityAnalyzer::CheckGPUPresence() {
    ID3D11Device* pDevice = nullptr;
    D3D_FEATURE_LEVEL featureLevel;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION, &pDevice, &featureLevel, nullptr);

    if (SUCCEEDED(hr)) {
        pDevice->Release();
        return false;
    }
    return true;
}

bool SecurityAnalyzer::CheckDeviceTree() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr, DIGCF_ALLCLASSES);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    DWORD devIndex = 0;
    int vmDevicesFound = 0;

    while (SetupDiEnumDeviceInfo(hDevInfo, devIndex++, &devInfoData)) {
        WCHAR hwId[512] = { 0 };
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_HARDWAREID,
            nullptr, reinterpret_cast<PBYTE>(hwId), sizeof(hwId), nullptr)) {
            if (wcsstr(hwId, L"VEN_80EE") || wcsstr(hwId, L"VEN_15AD")) {
                vmDevicesFound++;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return vmDevicesFound >= 2;
}

void SecurityAnalyzer::SafeExit() const {
    ExitProcess(0);
}

bool SecurityAnalyzer::IsRunAsAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL ok = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
    if (ok) CheckTokenMembership(nullptr, AdministratorsGroup, &ok);
    return ok == TRUE;
}

void SecurityAnalyzer::LogDetection(const wchar_t* message) {
    OutputDebugStringW((std::wstring(L"[Security] ") + message + L"\n").c_str());
}

std::wstring SecurityAnalyzer::GetLastErrorString() {
    DWORD error = GetLastError();
    _com_error err(error);
    return err.ErrorMessage();
}