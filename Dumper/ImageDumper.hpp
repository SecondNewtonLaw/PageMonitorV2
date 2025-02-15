//
// Created by Dottik on 15/2/2025.
//

#pragma once

#include <cstdint>
#include <unordered_set>
#include <vector>
#include <memory>
#include <future>
#include "ProcessImage.hpp"
#include "Readers/RemoteReader.hpp"
#include "libassert/assert.hpp"
#include "Dumper.hpp"
#include <winternl.h>
#include <Windows.h>

namespace Dottik::Dumper::PE {
    struct SectionInformation {
        void *rpSectionBegin;   // Remote buffer address.
        void *rpSectionEnd;     // Remote buffer address.
        const char *szSectionName;
        bool bRequiresDecryption;
        PIMAGE_SECTION_HEADER pSectionHeader;

        void *pSectionBegin;    // Local buffer address.
        void *pSectionEnd;      // Local buffer address.
        std::uint32_t dwSectionSize;
    };

    class ImageDumper final {
        Dottik::Dumper::Dumper *m_dumper;
        std::vector<std::byte> m_remoteImage;
        std::vector<SectionInformation> m_remoteImageSections;
        ProcessImage m_procImage;
        std::shared_ptr<Dottik::Dumper::RemoteReader> m_reader;
    public:
        [[maybe_unused]] explicit ImageDumper(const ProcessImage &image,
                                              std::shared_ptr<Dottik::Dumper::RemoteReader> &reader,
                                              Dottik::Dumper::Dumper *dumper);

        void BuildInitialImage();

#define RVAToVA(x, y) (void *)((std::uintptr_t)(x) + y)
#define AlignUp(x, align) (((x) + ((align)-1)) & ~((align)-1))

        std::vector<SectionInformation> GetOrGenerateSectionInformation() {
            if (!this->m_remoteImageSections.empty())
                return m_remoteImageSections;

            /*
             *  This is fairly simple stuff. We must grab the initial image reconstruction present on this->m_remoteImage and define the sections and initiate a dumper instance for them.
             *  This is not that complicated, it's just a bunch of garbage VA translation shit.
             */

            auto baseAddress = reinterpret_cast<std::uintptr_t>(this->m_remoteImage.data());
            auto imageBase = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);

            auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(RVAToVA(baseAddress, imageBase->e_lfanew));
            auto optionalHeaders = &ntHeaders->OptionalHeader;
            auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

            std::vector<SectionInformation> sections{};
            sections.reserve(ntHeaders->FileHeader.NumberOfSections);

            for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
                sectionHeader->Misc.VirtualSize = AlignUp(sectionHeader->Misc.VirtualSize,
                                                          ntHeaders->OptionalHeader.SectionAlignment);

                const auto sectionBaseAddress = reinterpret_cast<void *>(RVAToVA(optionalHeaders->ImageBase,
                                                                                 sectionHeader->VirtualAddress));

                //
                // If the section is possibly encrypted, then we will decrypt it.
                //

                // SectionInformation sectionInformation{};
                // sectionInformation.rpSectionBegin = sectionBaseAddress;
                // sectionInformation.rpSectionEnd = reinterpret_cast<void *>(
                //         sectionHeader->SizeOfRawData + reinterpret_cast<std::uintptr_t>(sectionBaseAddress));
                // sectionInformation.szSectionName = reinterpret_cast<const char *>(sectionHeader->Name);
                // sectionInformation.pSectionHeader = sectionHeader;


                auto startAddress = reinterpret_cast<std::uintptr_t>(sectionBaseAddress);
                auto endAddress = sectionHeader->SizeOfRawData +
                                  reinterpret_cast<std::uintptr_t>(sectionBaseAddress);

                auto hasEncryption = false;
                while (startAddress < endAddress) {
                    auto addressInformation = this->m_reader->QueryAddressInformaton((void *) startAddress);

                            ASSERT(addressInformation.has_value() == true, "Memory query failed.");

                    auto memInfo = addressInformation.value();
                    if ((memInfo.Protect & PAGE_NOACCESS) == PAGE_NOACCESS) {
                        // This section is encrypted! Pre-Fill with 0xCC!
                        hasEncryption = true;
                        memset(reinterpret_cast<void *>(RVAToVA(baseAddress,
                                                                sectionHeader->PointerToRawData)),
                               0xCC,    // fill with breakpoints.
                               sectionHeader->SizeOfRawData);
                        break;
                    }

                    startAddress += memInfo.RegionSize;
                }

                sections.emplace_back(
                        sectionBaseAddress,
                        reinterpret_cast<void *>(
                                sectionHeader->SizeOfRawData + reinterpret_cast<std::uintptr_t>(sectionBaseAddress)
                        ),
                        reinterpret_cast<const char *>(sectionHeader->Name),
                        hasEncryption,
                        sectionHeader,
                        reinterpret_cast<void *>(RVAToVA(baseAddress,
                                                         sectionHeader->PointerToRawData)),
                        reinterpret_cast<void *>(sectionHeader->SizeOfRawData +
                                                 reinterpret_cast<std::uintptr_t>(RVAToVA(baseAddress,
                                                                                          sectionHeader->PointerToRawData))),

                        sectionHeader->SizeOfRawData
                );
            }

            this->m_remoteImageSections = sections;

            return sections;
        }

        void ResolveInitialSections();

        std::vector<std::byte> GetRemoteImage() {
            return this->m_remoteImage; // TODO: Ensure that everything is complete before allowing the user to call this function???
        }

        void DecryptSection(const SectionInformation &section) {
            std::vector<uint32_t> encryptedPages{};
            auto pageCount = section.dwSectionSize / 0x1000;
            auto pagesRequiredToDecrypt = round((float) pageCount * 1.0f);
            encryptedPages.reserve(pageCount);

            for (auto pageIndex = 0; pageIndex < pageCount; pageIndex++)
                encryptedPages.emplace_back(pageIndex);

            auto timePassed = 0;
            auto kys = false;
            while ((pageCount - pagesRequiredToDecrypt) < encryptedPages.size() && !kys) {
                Sleep(50);
                timePassed += 50;
                for (auto beginning = encryptedPages.begin(); beginning != encryptedPages.end();) {
                    if (DWORD exitCode; GetExitCodeProcess(this->m_dumper->GetProcessHandle(), &exitCode) &&
                                        exitCode != STILL_ACTIVE) {
                        kys = true;
                        break;
                    }

                    if (timePassed > 5000 && encryptedPages.size() <= pageCount * 0.125) {
                        kys = true;
                        break;
                    }

                    const auto currentPageRva = *beginning * 0x1000;   // 0x1000 == PAGE_SIZE

                    const auto rpPageAddress = reinterpret_cast<void *>(RVAToVA(section.rpSectionBegin,
                                                                                currentPageRva));
                    const auto pLocalPageAddress = reinterpret_cast<void *>(RVAToVA(section.pSectionBegin,
                                                                                    currentPageRva));

                    auto info = this->m_reader->QueryAddressInformaton(rpPageAddress);

                    if (!info.has_value()) {
                        beginning++;
                        continue;   // Process may have died or API failure.
                    }

                    auto memInfo = info.value();

                    if (memInfo.Protect == PAGE_NOACCESS) {
                        beginning++;
                        continue;   // Encrypted
                    }

                    auto pageContent = this->m_reader->Read(rpPageAddress, 0x1000);

                            ASSUME(pageContent.has_value() == true,
                                   "Failed to read page. ReadProcessMemory (WinApi) failed?");

                    memcpy(pLocalPageAddress, pageContent.value().data(), pageContent.value().size());

                    beginning = encryptedPages.erase(beginning);
                }
            }

        }

        void ResolveEncryptedSections() {
            /*
             *  The real meat and potatoes. We must track all possibly encrypted sections parallely to obtain a good idea of the binary's true face.
             *  (because I love encrypted binaries!).
             */

            auto sectionInformation = this->GetOrGenerateSectionInformation();

            std::vector<std::future<void>> futures{};

            for (const auto &section: sectionInformation) {
                if (!section.bRequiresDecryption)
                    continue;   // Skip sections which require decryption.


                futures.emplace_back(std::async(std::launch::async, [this, section]() {
                    this->DecryptSection(section);
                }));
            }

            while (!futures.empty()) {
                for (auto start = futures.begin(); start != futures.end() && !futures.empty();) {
                    if (start->wait_for(std::chrono::milliseconds{100}) == std::future_status::timeout) {
                        ++start;
                        continue;
                    }

                    start = futures.erase(start);
                }
            }
        }

        bool ContainsEncryptedSections() {
            return std::ranges::any_of(this->GetOrGenerateSectionInformation(), [](const auto &obj) {
                return obj.bRequiresDecryption;
            });
        }
    };
} // PE
// Dumper
// Dottik
