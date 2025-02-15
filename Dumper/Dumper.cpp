//
// Created by Dottik on 12/12/2024.
//

#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>
#include <future>
#include <libassert/assert.hpp>
#include <fstream>
#include <map>

#include "Dumper.hpp"
#include "ImageDumper.hpp"

namespace Dottik::Dumper {
    Dumper::Dumper(const std::int32_t dwProcessId, std::shared_ptr<Dottik::Dumper::RemoteReader> reader) {
        this->m_dwProcessId = dwProcessId;
        this->m_reader = reader;
    }

    std::vector<ProcessImage> Dumper::GetAllRemoteProcessModules() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->m_dwProcessId);

                ASSERT(hSnapshot != nullptr && hSnapshot != INVALID_HANDLE_VALUE, "failed to create snapshot.");

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(MODULEENTRY32W);
                ASSERT(Module32FirstW(hSnapshot, &entry) == TRUE, "failed to obtain first module");

        std::vector<ProcessImage> images{};
        do {
            images.emplace_back(entry.szModule, entry.szExePath, entry.th32ProcessID, entry.modBaseSize,
                                entry.hModule, static_cast<void *>(entry.modBaseAddr));
        } while (Module32NextW(hSnapshot, &entry) == TRUE);

        return images;
    }

    std::vector<std::map<ProcessImage, std::byte>> Dumper::DumpAllModules() {
        const auto modules = this->GetAllRemoteProcessModules();

        std::vector<std::future<std::pair<ProcessImage, std::vector<std::byte>>>> futures;

        for (const auto &module: modules) {
            futures.push_back(std::async(std::launch::async, [this, &module]() {
                auto imageDumper = Dottik::Dumper::PE::ImageDumper(module, this->m_reader);

                imageDumper.BuildInitialImage();

                imageDumper.ResolveInitialSections();

                imageDumper.ResolveEncryptedSections();

                // TODO: Implement Import resolution
                // TODO: Implement section resolution [Unencrypted is done!].

                return std::pair{module, imageDumper.GetRemoteImage()};
            }));
        }

        std::filesystem::path dumpDirectory{std::filesystem::current_path() / "dump_out"};

        std::filesystem::create_directory(dumpDirectory);

        while (!futures.empty()) {
            for (auto start = futures.begin(); start != futures.end() && !futures.empty();) {
                if (start->wait_for(std::chrono::milliseconds{2000}) == std::future_status::timeout) {
                    ++start;
                    continue;
                }

                const auto [module, image] = start->get();

                auto file = dumpDirectory / module.wszModuleName;

                std::ofstream moduleOut{file, std::ios::binary | std::ios::trunc};

                moduleOut.write(reinterpret_cast<const char *>(image.data()), static_cast<std::int32_t>(image.size()));
                moduleOut.flush();
                moduleOut.close();

                start = futures.erase(start);
            }
        }

        return {};
    }
} // Dumper
// Dottik
