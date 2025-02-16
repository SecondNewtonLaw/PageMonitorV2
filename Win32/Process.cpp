//
// Created by Dottik on 15/2/2025.
//

#include "Process.hpp"
#include <libassert/assert.hpp>
#include <Windows.h>
#include <TlHelp32.h>


namespace Dottik::Win32::Process {
    std::optional<DWORD> GetProcessIdByName(const char *szProcessName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                ASSERT(hSnapshot != nullptr && hSnapshot != INVALID_HANDLE_VALUE, "failed to create snapshot.");

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(PROCESSENTRY32);
                ASSERT(Process32First(hSnapshot, &entry) == TRUE, "failed to obtain first module");

        std::optional<DWORD> pid{std::nullopt};
        do {
            if (strcmp(entry.szExeFile, szProcessName) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &entry));
        CloseHandle(hSnapshot);

        return pid;
    }

    DWORD WaitForProcessToBeCreated(const char *szProcessName) {
        std::optional<DWORD> pid = GetProcessIdByName(szProcessName);

        while (!pid.has_value()) {
            Sleep(5);
            pid = GetProcessIdByName(szProcessName);

            if (pid.has_value())
                Sleep(1000);

            pid = GetProcessIdByName(szProcessName);
        }

                ASSUME(pid.has_value() == true, "pid has no value.");

        return pid.value();
    }
} // Dottik::Win32::Process
