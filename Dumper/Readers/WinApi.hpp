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
    };
} // Dumper
// Dottik
