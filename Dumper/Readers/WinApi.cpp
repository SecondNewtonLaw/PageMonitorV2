//
// Created by Dottik on 12/12/2024.
//

#include "WinApi.hpp"
#include <vector>
#include <format>
#include "../../../Logger.hpp"

namespace Dottik::Dumper {
    WinApi::WinApi(const DWORD dwProcessId) {
        this->m_hProcess = OpenProcess(PROCESS_ALL_ACCESS,
                                       false,
                                       dwProcessId);
    }

    std::optional<std::vector<std::byte>> WinApi::Read(void *rpAddress, const std::size_t memSize) {
        auto tmpBuffer = std::vector<std::byte>{};
        tmpBuffer.resize(memSize);
        auto readBytes = 0ull;
        if (!ReadProcessMemory(this->m_hProcess, rpAddress, tmpBuffer.data(), memSize, &readBytes)) {
            auto dwError = GetLastError();
            DottikLog(Dottik::LogType::Debug, Dottik::WinAPI,
                      std::format("failed to ReadProcessMemory from a remote process -> Last Error: {}",
                                  reinterpret_cast<void *>(dwError)));
            return std::nullopt;
        }

        return tmpBuffer;
    }

    std::optional<std::vector<std::byte>> WinApi::ReadAligned(void *rpAddress, const std::size_t memSize) {
        return Read(
                reinterpret_cast<void *>(RemoteReader::AlignAddress(reinterpret_cast<std::uintptr_t>(rpAddress))),
                memSize);
    }
} // Dumper
// Dottik
