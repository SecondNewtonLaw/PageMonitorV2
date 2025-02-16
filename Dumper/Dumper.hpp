//
// Created by Dottik on 12/12/2024.
//

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "Readers/RemoteReader.hpp"
#include "ProcessImage.hpp"
#include "Dumper/Readers/WinApi.hpp"
#include <map>

namespace Dottik::Dumper {
    namespace PE {
        class ImageDumper;
    }

    class Dumper final {
        std::shared_ptr<Dottik::Dumper::RemoteReader> m_reader;
        std::vector<std::shared_ptr<Dottik::Dumper::PE::ImageDumper> > m_moduleDumpers;
        std::uint32_t m_dwProcessId{};
        HANDLE m_hProcess{};
        bool m_bUsable;
        bool m_bPatchDump;
        bool m_bUseNewPatchingLogic;

    public:
        Dumper();

        void EnableDumpPatching(bool dumpPatching);

        void MigrateReaderAndObtainNewHandle(std::uint32_t dwProcessId,
                                             const std::shared_ptr<Dottik::Dumper::WinApi> &reader);

        void WithNewPatchingLogic(bool useNewPatchingLogic);

        explicit Dumper(std::uint32_t dwProcessId, const std::shared_ptr<Dottik::Dumper::WinApi> &reader);

        explicit Dumper(std::uint32_t dwProcessId, std::shared_ptr<Dottik::Dumper::RemoteReader> reader,
                        HANDLE hProcess);

        ~Dumper();

        std::vector<ProcessImage> GetAllRemoteProcessModules();

        std::vector<std::map<ProcessImage, std::byte> > DumpAllModules();

        [[nodiscard]] HANDLE GetProcessHandle() const;

        [[nodiscard]] bool IsUsable() const;

        std::shared_ptr<std::vector<std::byte> > DumpRemoteModule(ProcessImage &processImage);

        std::shared_ptr<std::vector<std::byte> > DumpMainModule();
    };
}
