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
        std::vector<std::byte> m_remoteImage;
        std::vector<SectionInformation> m_remoteImageSections;
        ProcessImage m_procImage;
        std::shared_ptr<Dottik::Dumper::RemoteReader> m_reader;
    public:
        [[maybe_unused]] explicit ImageDumper(const ProcessImage &image,
                                              std::shared_ptr<Dottik::Dumper::RemoteReader> &reader) {
            this->m_procImage = image;
            this->m_reader = reader;

            this->m_remoteImage = {};
            this->m_remoteImage.resize(
                    image.dwModuleSize); // reserve memory to use .data() directly on other places (because it's easier to manage lmao)
        }

        void BuildInitialImage() {
                    ASSUME(this->m_procImage.dwModuleSize > 0x1000,
                           "dwModuleSize is under the sizeof(WindowsPage). What the hell happened?");

            auto remoteBaseAddress = this->m_procImage.rlpModuleBase;

            auto peHeader = this->m_reader->Read(remoteBaseAddress, 0x1000);

                    ASSERT(peHeader.has_value(), "Failed to read memory from remote process. Wtf?");

            const auto &mem = peHeader.value();

            memcpy(this->m_remoteImage.data(), mem.data(), mem.size());
        }

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
                        hasEncryption = true;
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

        void ResolveInitialSections() {
            /*
             *  As for the time being we only support Hyperion, Hyperion's page re-encryption works by tagging encrypted pages as NO_ACCESS.
             *  This means that to value whether a page is encrypted we simply must sweep from beginning to end of a section in search of NO_ACCESS.
             *  If the tag is not present, we can build it as an initial section, and it will not have to be decrypted by monitoring.
             */

            auto sectionInformation = this->GetOrGenerateSectionInformation();

            std::vector<std::future<void>> futures{};

            for (const auto &section: sectionInformation) {
                if (section.bRequiresDecryption)
                    continue;   // Skip sections which require decryption.

                futures.push_back(std::async(std::launch::async, [this, &section]() {
                    auto read = this->m_reader->Read(section.rpSectionBegin, section.dwSectionSize);

                            ASSERT(read.has_value() == true, "Failed to read section from remote process memory");

                    memcpy(section.pSectionBegin, read.value().data(), section.dwSectionSize);
                }));
            }

            while (!futures.empty()) {
                for (auto start = futures.begin(); start != futures.end() && !futures.empty();) {
                    if (start->wait_for(std::chrono::milliseconds{500}) == std::future_status::timeout) {
                        ++start;
                        continue;
                    }

                    start = futures.erase(start);
                }
            }

        }

        std::vector<std::byte> GetRemoteImage() {
            return this->m_remoteImage; // TODO: Ensure that everything is complete before allowing the user to call this function???
        }

        void DecryptSection(const SectionInformation &section) {
            std::unordered_set<std::uintptr_t> pageMap{};

            /*
             *  Hyperion loves to touch pages. Thus we will iterate all the pages on the section and save them to the unordered_map.
             *  This way we can quickly discern encrypted from decrypted pages.
             */

            auto localBufferSectionBegin = section.
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
                    if (start->wait_for(std::chrono::milliseconds{500}) == std::future_status::timeout) {
                        ++start;
                        continue;
                    }

                    start = futures.erase(start);
                }
            }
        }
    };
} // PE
// Dumper
// Dottik
