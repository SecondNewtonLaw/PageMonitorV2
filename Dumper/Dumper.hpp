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
        std::uint32_t m_dwProcessId{};
        HANDLE m_hProcess{};
        bool m_bUsable;
    public:
        Dumper();

        explicit Dumper(std::uint32_t dwProcessId, const std::shared_ptr<Dottik::Dumper::WinApi> &reader);

        explicit Dumper(std::uint32_t dwProcessId, std::shared_ptr<Dottik::Dumper::RemoteReader> reader,
                        HANDLE hProcess);

        ~Dumper();

        std::vector<ProcessImage> GetAllRemoteProcessModules();

        std::vector<std::map<ProcessImage, std::byte>> DumpAllModules();

        [[nodiscard]] HANDLE GetProcessHandle() const;

        [[nodiscard]] bool IsUsable() const;

        std::vector<std::byte> DumpRemoteModule(ProcessImage &processImage);

        std::vector<std::byte> DumpMainModule();
    };
}
