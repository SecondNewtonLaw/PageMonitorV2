//
// Created by Dottik on 15/2/2025.
//

#pragma once

#include <Windows.h>
#include <optional>

namespace Dottik::Win32::Process {
    std::optional<DWORD> GetProcessIdByName(const char *szProcessName);

    DWORD WaitForProcessToBeCreated(const char *szProcessName);
} // Dottik::Win32::Process