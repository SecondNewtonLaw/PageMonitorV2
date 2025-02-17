//
// Created by Dottik on 15/2/2025.
//

#pragma once

#include <string>
#include <cstdint>
#include <Windows.h>

struct ProcessImage {
    std::wstring wszModuleName = L"";
    std::wstring wszModulePath = L"";
    std::uint32_t dwOwnedBy{UINT_MAX};
    std::uint32_t dwModuleSize{UINT_MAX};
    HMODULE rhModule{nullptr};
    void *rlpModuleBase{nullptr};

    ProcessImage() = default;

    ProcessImage(const wchar_t *wszModuleName, const wchar_t *wszModulePath, const std::uint32_t dwOwnerProcessId,
                 const std::uint32_t dwModuleSizeFromBaseAddress, const HMODULE rhModule, void *rlpModuleBaseAddress) {
        this->wszModuleName = wszModuleName;
        this->wszModulePath = wszModulePath;
        this->dwOwnedBy = dwOwnerProcessId;
        this->dwModuleSize = dwModuleSizeFromBaseAddress;
        this->rhModule = rhModule;
        this->rlpModuleBase = rlpModuleBaseAddress;
    }
};
