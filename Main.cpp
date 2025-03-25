#include "pch.h"
#include "ProcessScanner.h"
#include <mutex>

std::mutex g_instanceMutex;
std::unique_ptr<ProcessScanner> g_scanner;
const wchar_t* MUTEX_NAME = L"Global\\{5C7A7B4E-3A2F-4F1C-9E8D-3D1D8C7D7E8A}";

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        HANDLE hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(hMutex);
            return FALSE;
        }

        DisableThreadLibraryCalls(hModule);
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        try {
            g_scanner = std::make_unique<ProcessScanner>();
            g_scanner->StartMonitoring();
        }
        catch (...) {
            return FALSE;
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        if (g_scanner) {
            g_scanner->StopMonitoring();
            g_scanner.reset();
        }
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL __stdcall StartMonitor() {
    std::lock_guard<std::mutex> lock(g_instanceMutex);
    if (!g_scanner) {
        g_scanner = std::make_unique<ProcessScanner>();
        g_scanner->StartMonitoring();
        return TRUE;
    }
    return FALSE;
}

extern "C" __declspec(dllexport) void __stdcall StopMonitor() {
    std::lock_guard<std::mutex> lock(g_instanceMutex);
    if (g_scanner) {
        g_scanner->StopMonitoring();
        g_scanner.reset();
    }
}