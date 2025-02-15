//
// Created by Dottik on 12/12/2024.
//

#include <Windows.h>
#include <TlHelp32.h>
#include <libassert/assert.hpp>

#include "Dumper.hpp"

namespace Dottik::Dumper {
    Dumper::Dumper(const std::int32_t dwProcessId, std::shared_ptr<Dottik::Dumper::RemoteReader> &reader) {
        this->m_dwProcessId = dwProcessId;
        this->m_reader = reader;
    }

    std::vector<ProcessImage> Dumper::GetAllRemoteProcessModules() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->m_dwProcessId);

                ASSERT(hSnapshot != nullptr && hSnapshot != INVALID_HANDLE_VALUE, "failed to create snapshot.");

        MODULEENTRY32W entry{};
                ASSERT(Module32FirstW(hSnapshot, &entry), "failed to obtain first module");

        std::vector<ProcessImage> images{};
        do {
            images.emplace_back(entry.szModule, entry.szExePath, entry.th32ProcessID, entry.modBaseSize,
                                entry.hModule, static_cast<void *>(entry.modBaseAddr));
        } while (Module32NextW(hSnapshot, &entry));

        return images;
    }
} // Dumper
// Dottik
