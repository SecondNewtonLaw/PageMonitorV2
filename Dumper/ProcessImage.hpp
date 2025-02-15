//
// Created by Dottik on 15/2/2025.
//

#pragma once

#include <string>
#include <cstdint>
#include <Windows.h>

struct ProcessImage {
    std::wstring wszModuleName;
    std::wstring wszModulePath;
    std::uint32_t dwOwnedBy;
    std::uint32_t dwModuleSize;
    HMODULE rhModule;
    void *rlpModuleBase;

    ProcessImage() {

    }

    ProcessImage(wchar_t *wszModuleName, wchar_t *wszModulePath, std::uint32_t dwOwnerProcessId,
                 std::uint32_t dwModuleSizeFromBaseAddress, HMODULE rhModule, void *rlpModuleBaseAddress) {
        this->wszModuleName = wszModuleName;
        this->wszModulePath = wszModulePath;
        this->dwOwnedBy = dwOwnerProcessId;
        this->dwModuleSize = dwModuleSizeFromBaseAddress;
        this->rhModule = rhModule;
        this->rlpModuleBase = rlpModuleBaseAddress;
    }
};