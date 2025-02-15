//
// Created by Dottik on 12/12/2024.
//

#pragma once

#include <optional>
#include <vector>
#include <cstdint>
#include <Windows.h>
#include "RemoteReader.hpp"


namespace Dottik::Dumper {
    class WinApi final : public RemoteReader {
        HANDLE m_hProcess;

    public:
        explicit WinApi(DWORD dwProcessId);

        std::optional<std::vector<std::byte>> Read(void *rpAddress, std::size_t memSize) override;

        std::optional<std::vector<std::byte>> ReadAligned(void *rpAddress, std::size_t memSize) override;

        std::optional<MEMORY_BASIC_INFORMATION> QueryAddressInformaton(void *rpAddress) override {
            MEMORY_BASIC_INFORMATION basicInfo{};
            if (!VirtualQueryEx(this->m_hProcess, rpAddress, &basicInfo, sizeof(MEMORY_BASIC_INFORMATION)))
                return std::nullopt;

            return basicInfo;
        }
    };
} // Dumper
// Dottik
