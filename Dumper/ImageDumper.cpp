//
// Created by Dottik on 15/2/2025.
//

#include "ImageDumper.hpp"
#include "Logger.hpp"
#include "Utilities.hpp"


namespace Dottik::Dumper::PE {
    ImageDumper::ImageDumper(const ProcessImage &image, std::shared_ptr<Dottik::Dumper::RemoteReader> &reader,
                             Dottik::Dumper::Dumper *dumper) : m_dumper(dumper) {
        this->m_procImage = image;
        this->m_reader = reader;
        this->m_dumper = dumper;

        this->m_remoteImage = {};
        this->m_remoteImage.resize(
                image.dwModuleSize); // reserve memory to use .data() directly on other places (because it's easier to manage lmao)
    }

    void ImageDumper::BuildInitialImage() {
                ASSUME(this->m_procImage.dwModuleSize > 0x1000,
                       "dwModuleSize is under the sizeof(WindowsPage). What the hell happened?");

        auto remoteBaseAddress = this->m_procImage.rlpModuleBase;

        auto peHeader = this->m_reader->Read(remoteBaseAddress, 0x1000);

                ASSERT(peHeader.has_value() == true, "Failed to read memory from remote process. Wtf?");

        const auto &mem = peHeader.value();

        memcpy(this->m_remoteImage.data(), mem.data(), mem.size());

        DottikLog(
                Dottik::LogType::Information, Dottik::DumpingEngine,
                std::format("Initial PE Image built for Module {}.",
                            Dottik::Utilities::WcharToString(this->m_procImage.wszModuleName.c_str())));
    }

    void ImageDumper::ResolveInitialSections() {
        /*
         *  As for the time being we only support Hyperion, Hyperion's page re-encryption works by tagging encrypted pages as NO_ACCESS. (re-encryption? re-encrypting no_access pages? ur not ok)
         *  This means that to value whether a page is encrypted we simply must sweep from beginning to end of a section in search of NO_ACCESS.
         *  If the tag is not present, we can build it as an initial section, and it will not have to be decrypted by monitoring.
         */

        auto sectionInformation = this->GetOrGenerateSectionInformation();

        std::vector<std::future<void>> futures{};

        for (const auto &section: sectionInformation) {
            if (section.bRequiresDecryption)
                continue;   // Skip sections which require decryption.

            auto read = this->m_reader->Read(section.rpSectionBegin, section.dwSectionSize);

            if (!read.has_value()) {
                DottikLog(
                        Dottik::LogType::Warning, Dottik::DumpingEngine,
                        std::format(
                                "A read into section {} for module {} has failed! The content in the section has been set to 0xCC!",
                                section.szSectionName,
                                Dottik::Utilities::WcharToString(this->m_procImage.wszModuleName.c_str())));
                memset(section.pSectionBegin, 0xCC, section.dwSectionSize);
            } else {
                // ASSUME(read.has_value() == true, "Failed to read section from remote process memory");
                memcpy(section.pSectionBegin, read.value().data(), section.dwSectionSize);
            }
        }

        DottikLog(
                Dottik::LogType::Information, Dottik::DumpingEngine,
                std::format("Resolved initial sections for Module {}.",
                            Dottik::Utilities::WcharToString(this->m_procImage.wszModuleName.c_str())));
    }

    void ImageDumper::DecryptSection(const SectionInformation &section) {
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

                if (!pageContent.has_value()) {
                    beginning++;
                    continue;   // API failure?
                }

                        ASSUME(pageContent.has_value() == true,
                               "Failed to read page. ReadProcessMemory (WinApi) failed?");

                /*
                 *  100 - pageCount
                 *  x   - pageCount - encryptedPages.size()
                 *  encryptedPages.size() * 100 / pageCount
                 */

                auto percentage = std::round(
                        ((pageCount - encryptedPages.size()) * (double) 100.0 / pageCount) * (double) 10000.0) /
                                  (double) 10000.0;

                DottikLog(
                        Dottik::LogType::Information, Dottik::DumpingEngine,
                        std::format("Decrypted page of section '{}::{}' . {}/{} pages decrypted | {}%",
                                    Dottik::Utilities::WcharToString(this->m_procImage.wszModuleName.c_str()),
                                    section.szSectionName, pageCount - encryptedPages.size(), pageCount,
                                    percentage));

                memcpy(pLocalPageAddress, pageContent.value().data(), pageContent.value().size());

                beginning = encryptedPages.erase(beginning);
            }
        }

    }

    void ImageDumper::ResolveEncryptedSections() {
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

        DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                std::format(
                        "Resolved encrypted sections for module {}",
                        Dottik::Utilities::WcharToString(this->m_procImage.wszModuleName.c_str())));
    }

    bool ImageDumper::ContainsEncryptedSections() {
        return std::ranges::any_of(this->GetOrGenerateSectionInformation(), [](const auto &obj) {
            return obj.bRequiresDecryption;
        });
    }

    std::vector<SectionInformation> ImageDumper::GetOrGenerateSectionInformation() {
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

    std::vector<std::byte> ImageDumper::GetRemoteImage() {
        return this->m_remoteImage; // TODO: Ensure that everything is complete before allowing the user to call this function???
    }
} // PE
// Dumper
// Dottik
