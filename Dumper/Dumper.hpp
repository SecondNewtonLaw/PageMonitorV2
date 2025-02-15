//
// Created by Dottik on 12/12/2024.
//

#pragma once

#include <cstdint>
#include <memory>
#include "Readers/RemoteReader.hpp"
#include "ProcessImage.hpp"
#include "Dumper/Readers/WinApi.hpp"
#include <map>

namespace Dottik::Dumper {
    class Dumper final {
        std::shared_ptr<Dottik::Dumper::RemoteReader> m_reader;
        std::uint32_t m_dwProcessId;
        HANDLE m_hProcess;

    public:
        explicit Dumper(std::uint32_t dwProcessId, std::shared_ptr<Dottik::Dumper::WinApi> reader);

        explicit Dumper(std::uint32_t dwProcessId, std::shared_ptr<Dottik::Dumper::RemoteReader> reader,
                        HANDLE hProcess);

        std::vector<ProcessImage> GetAllRemoteProcessModules();

        std::vector<std::map<ProcessImage, std::byte>> DumpAllModules();

        HANDLE GetProcessHandle() const;
    };
}
