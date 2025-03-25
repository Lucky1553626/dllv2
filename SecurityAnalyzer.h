#pragma once
#include <windows.h>
#include <intrin.h>
#include <pdh.h>
#include <setupapi.h>
#include <d3d11.h>
#include <vector>
#include <functional>
#include <string>
#include <wincrypt.h>
#include <tchar.h>

class SecurityAnalyzer {
public:
    SecurityAnalyzer();
    bool AnalyzeEnvironment();
    static bool IsRunAsAdmin();

private:
    struct DetectionWeight {
        std::function<bool()> detector;
        float weight;
    };

    std::vector<DetectionWeight> m_detectors;
    static constexpr float THRESHOLD = 0.65f;

    // Detection methods
    bool CheckHypervisorFlags();
    bool CheckKVM();
    bool CheckVMPerformance();
    bool CheckDeviceTree();
    bool CheckGPUPresence();
    bool CheckCPUBrand();
    bool CheckRAMSize();
    bool CheckProcessList();
    bool CheckRegistryEntries();
    bool CheckDiskSize();

    // Utility methods
    void SafeExit() const;
    static void LogDetection(const wchar_t* message);
    static std::wstring GetLastErrorString();
};