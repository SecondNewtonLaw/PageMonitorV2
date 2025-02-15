//
// Created by Dottik on 12/12/2024.
//

#pragma once
#include <cstdint>
#include <memory>
#include "Readers/RemoteReader.hpp"
#include "ProcessImage.hpp"
#include <map>

namespace Dottik::Dumper {
    class Dumper final {
        std::shared_ptr<Dottik::Dumper::RemoteReader> m_reader;
        std::int32_t m_dwProcessId;

    public:
        explicit Dumper(std::int32_t dwProcessId, std::shared_ptr<Dottik::Dumper::RemoteReader> reader);

        std::vector<ProcessImage> GetAllRemoteProcessModules();

        std::vector<std::map<ProcessImage, std::byte>> DumpAllModules();
    };
}
