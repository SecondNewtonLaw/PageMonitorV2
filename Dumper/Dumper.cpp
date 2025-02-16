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
#include <utility>

#include "Dumper.hpp"
#include "ImageDumper.hpp"
#include "Logger.hpp"

namespace Dottik::Dumper {
    Dumper::Dumper(const std::uint32_t dwProcessId, const std::shared_ptr<Dottik::Dumper::WinApi> &reader) {
        this->m_dwProcessId = dwProcessId;
        this->m_reader = reader;
        this->m_hProcess = reader->GetProcessHandle();
    }

    Dumper::Dumper(std::uint32_t dwProcessId, std::shared_ptr<Dottik::Dumper::RemoteReader> reader, HANDLE hProcess) {
        this->m_dwProcessId = dwProcessId;
        this->m_reader = std::move(reader);
        this->m_hProcess = hProcess;
    }

    std::vector<ProcessImage> Dumper::GetAllRemoteProcessModules() {
                ASSERT(this->m_bUsable, "This instance of Dottik::Dumper::Dumper is not usable.");

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->m_dwProcessId);

                ASSUME(hSnapshot != nullptr && hSnapshot != INVALID_HANDLE_VALUE, "failed to create snapshot.");

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(MODULEENTRY32W);
                ASSERT(Module32FirstW(hSnapshot, &entry) == TRUE, "failed to obtain first module");

        std::vector<ProcessImage> images{};
        do {
            images.emplace_back(entry.szModule, entry.szExePath, entry.th32ProcessID, entry.modBaseSize,
                                entry.hModule, static_cast<void *>(entry.modBaseAddr));
        } while (Module32NextW(hSnapshot, &entry) == TRUE);
        CloseHandle(hSnapshot);

        return images;
    }

    std::vector<std::map<ProcessImage, std::byte>> Dumper::DumpAllModules() {
                ASSERT(this->m_bUsable, "This instance of Dottik::Dumper::Dumper is not usable.");
        const auto modules = this->GetAllRemoteProcessModules();

        std::vector<std::future<std::pair<ProcessImage, std::vector<std::byte>>>> futures;

        for (const auto &module: modules) {
            auto imageDumper = std::make_shared<Dottik::Dumper::PE::ImageDumper>(module, this->m_reader, this);
            imageDumper->BuildInitialImage();

            imageDumper->ResolveInitialSections();
            imageDumper->GetOrGenerateSectionInformation();
            futures.push_back(std::async(std::launch::async, [this, imageDumper, &module]() {
                auto hasEncryptedSections = imageDumper->ContainsEncryptedSections();
                if (hasEncryptedSections)
                    imageDumper->ResolveEncryptedSections();

                // TODO: Implement Import resolution
                // TODO: Implement section resolution [Unencrypted is done!].

                return std::pair{module, imageDumper->GetRemoteImage()};
            }));
        }

        std::filesystem::path dumpDirectory{std::filesystem::current_path() / "dump_out"};

        std::filesystem::create_directory(dumpDirectory);

        while (!futures.empty()) {
            for (auto start = futures.begin(); start != futures.end() && !futures.empty();) {
                if (start->wait_for(std::chrono::milliseconds{20}) == std::future_status::timeout) {
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

    std::vector<std::byte> Dumper::DumpMainModule() {
                ASSERT(this->m_bUsable, "This instance of Dottik::Dumper::Dumper is not usable.");
        auto modules = this->GetAllRemoteProcessModules();
        return this->DumpRemoteModule(modules.front());
    }

    std::vector<std::byte> Dumper::DumpRemoteModule(ProcessImage &processImage) {
                ASSERT(this->m_bUsable, "This instance of Dottik::Dumper::Dumper is not usable.");
        auto imageDumper = std::make_shared<Dottik::Dumper::PE::ImageDumper>(processImage, this->m_reader, this);
        imageDumper->BuildInitialImage();

        imageDumper->ResolveInitialSections();
        imageDumper->GetOrGenerateSectionInformation();

        auto hasEncryptedSections = imageDumper->ContainsEncryptedSections();
        if (hasEncryptedSections)
            imageDumper->ResolveEncryptedSections();

        auto finalImage = imageDumper->GetRemoteImage();

        std::filesystem::path dumpDirectory{std::filesystem::current_path() / "dump_out"};

        std::filesystem::create_directory(dumpDirectory);

        auto file = dumpDirectory / processImage.wszModuleName;

        std::ofstream moduleOut{file, std::ios::binary | std::ios::trunc};

        moduleOut.write(reinterpret_cast<const char *>(finalImage.data()),
                        static_cast<std::int32_t>(finalImage.size()));
        moduleOut.flush();
        moduleOut.close();

        return finalImage;
    }

    HANDLE Dumper::GetProcessHandle() const {
                ASSERT(this->m_bUsable, "This instance of Dottik::Dumper::Dumper is not usable.");
        return this->m_hProcess;
    }

    Dumper::~Dumper() {
        if (this->m_bUsable) {
            DottikLog(Dottik::LogType::Debug, Dottik::DumpingEngine, "Cleaning up HANDLE objects...");
            CloseHandle(this->m_hProcess);
        }
    }

    bool Dumper::IsUsable() const {
        return this->m_bUsable;
    }

    Dumper::Dumper() {
        this->m_bUsable = false;
    }
} // Dumper
// Dottik
