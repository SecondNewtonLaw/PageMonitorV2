//
// Created by Dottik on 12/12/2024.
//

#include "WinApi.hpp"


namespace Dottik::Dumper {
    WinApi::WinApi(const DWORD dwProcessId) {
        this->m_hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION,
                                       false,
                                       dwProcessId);
    }

    std::optional<std::byte *> WinApi::Read(void *rpAddress, const std::size_t memSize) {
        auto *tmpBuffer = new std::byte[memSize];
        auto readBytes = 0ull;
        if (!ReadProcessMemory(this->m_hProcess, rpAddress, tmpBuffer, memSize, &readBytes)) {
            delete[] tmpBuffer;
            return std::nullopt;
        }

        return tmpBuffer;
    }

    std::optional<std::byte *> WinApi::ReadAligned(void *rpAddress, const std::size_t memSize) {
        return Read(
            reinterpret_cast<void *>(RemoteReader::AlignAddress(reinterpret_cast<std::uintptr_t>(rpAddress))),
            memSize);
    }
} // Dumper
// Dottik
