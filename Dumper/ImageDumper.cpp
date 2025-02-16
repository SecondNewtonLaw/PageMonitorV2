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

        this->m_remoteImage = std::make_shared<std::vector<std::byte> >();
        this->m_remoteImage->resize(
            image.dwModuleSize);
        this->m_bHasProcessImageMigrated = false;
        // reserve memory to use ->data() directly on other places (because it's easier to manage lmao)
    }

    void ImageDumper::MigrateImage(const ProcessImage &image) {
        this->m_bHasProcessImageMigrated = true;
        this->m_procImage = image;
    }

    void ImageDumper::MigrateReader(const std::shared_ptr<Dottik::Dumper::RemoteReader> &reader) {
        this->m_reader = reader;
    }

    ProcessImage ImageDumper::GetProcessImage() const {
        return this->m_procImage;
    }

    void ImageDumper::BuildInitialImage() {
        ASSUME(this->m_procImage.dwModuleSize > 0x1000,
               "dwModuleSize is under the sizeof(WindowsPage). What the hell happened?");

        const auto remoteBaseAddress = this->m_procImage.rlpModuleBase;

        const auto peHeader = this->m_reader->Read(remoteBaseAddress, 0x1000);

        ASSERT(peHeader.has_value() == true, "Failed to read memory from remote process. Wtf?");

        const auto &mem = peHeader.value();

        memcpy(this->m_remoteImage->data(), mem.data(), mem.size());

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

        const auto sectionInformation = this->GetOrGenerateSectionInformation();

        std::vector<std::future<void> > futures{};

        for (const auto &section: sectionInformation) {
            if (section.bRequiresDecryption)
                continue; // Skip sections which require decryption.

            if (const auto read = this->m_reader->Read(section.rpSectionBegin, section.dwSectionSize); !read.
                has_value()) {
                DottikLog(
                    Dottik::LogType::Warning, Dottik::DumpingEngine,
                    std::format(
                        "A read into section {} for module {} has failed! The content in the section has been set to 0xCC!"
                        ,
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

    void ImageDumper::DecryptSection(SectionInformation &section) {
        auto pageCount = section.dwSectionSize / 0x1000;
        const auto pagesRequiredToDecrypt = round(static_cast<float>(pageCount) * 1.0f);

        auto timePassed = 0;
        auto kys = false;
        while ((pageCount - pagesRequiredToDecrypt) < section.decryptionTracking.size() && !kys) {
            Sleep(50);
            timePassed += 50;
            for (auto beginning = section.decryptionTracking.begin(); beginning != section.decryptionTracking.end();) {
                if (DWORD exitCode; GetExitCodeProcess(this->m_dumper->GetProcessHandle(), &exitCode) &&
                                    exitCode != STILL_ACTIVE) {
                    kys = true;
                    break;
                }

                if (timePassed > 5000 && section.decryptionTracking.size() <= pageCount * 0.125) {
                    kys = true;
                    break;
                }

                const auto currentPageRva = *beginning * 0x1000; // 0x1000 == PAGE_SIZE

                const auto rpPageAddress = reinterpret_cast<void *>(RVAToVA(section.rpSectionBegin,
                                                                            currentPageRva));
                const auto pLocalPageAddress = reinterpret_cast<void *>(RVAToVA(section.pSectionBegin,
                    currentPageRva));

                auto info = this->m_reader->QueryAddressInformaton(rpPageAddress);

                if (!info.has_value()) {
                    ++beginning;
                    continue; // Process may have died or API failure.
                }

                auto memInfo = info.value();

                if (memInfo.Protect == PAGE_NOACCESS) {
                    ++beginning;
                    continue; // Encrypted
                }

                auto pageContent = this->m_reader->Read(rpPageAddress, 0x1000);

                if (!pageContent.has_value()) {
                    ++beginning;
                    continue; // API failure?
                }

                ASSUME(pageContent.has_value() == true,
                       "Failed to read page. ReadProcessMemory (WinApi) failed?");

                /*
                 *  100 - pageCount
                 *  x   - pageCount - encryptedPages.size()
                 *  encryptedPages.size() * 100 / pageCount
                 */

                auto percentage = std::round(
                                      ((pageCount - section.decryptionTracking.size()) * (double) 100.0 / pageCount) * (
                                          double)
                                      10000.0) /
                                  (double) 10000.0;

                DottikLog(
                    Dottik::LogType::Information, Dottik::DumpingEngine,
                    std::format("Decrypted page of section '{}::{}' . {}/{} pages decrypted | {}%",
                        Dottik::Utilities::WcharToString(this->m_procImage.wszModuleName.c_str()),
                        section.szSectionName, pageCount - section.decryptionTracking.size(), pageCount,
                        percentage));

                memcpy(pLocalPageAddress, pageContent.value().data(), pageContent.value().size());

                beginning = section.decryptionTracking.erase(beginning);
            }
        }
    }

    void ImageDumper::ResolveEncryptedSections() {
        /*
         *  The real meat and potatoes. We must track all possibly encrypted sections parallely to obtain a good idea of the binary's true face.
         *  (because I love encrypted binaries!).
         */

        const auto &sectionInformation = this->GetOrGenerateSectionInformation();

        std::vector<std::future<void> > futures{};

        auto idx = 0;
        for (const auto &section: sectionInformation) {
            if (!section.bRequiresDecryption)
                continue; // Skip sections which require decryption.

            futures.emplace_back(std::async(std::launch::async, [this, idx, section]() {
                auto sectionAgain = section;
                DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                          std::format("Attempting to resolve encrypted section: {}", sectionAgain.szSectionName));
                this->DecryptSection(sectionAgain);
                DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                          std::format(
                              "Decryption sequence ended fully/prematurely. Saving data into section information vector: {}; vector index: {}"
                              , sectionAgain.szSectionName, idx));
                this->GetOrGenerateSectionInformation()[idx] = std::move(sectionAgain);
            }));
            idx += 1;
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

    std::vector<SectionInformation> GenerateInitialSectionInformation(
        const std::shared_ptr<std::vector<std::byte> > &remoteImage,
        const std::shared_ptr<Dottik::Dumper::RemoteReader> &reader
    ) {
        const auto baseAddress = reinterpret_cast<std::uintptr_t>(remoteImage->data());
        const auto imageBase = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);

        auto ntHeaders = static_cast<PIMAGE_NT_HEADERS>(RVAToVA(baseAddress, imageBase->e_lfanew));
        const auto optionalHeaders = &ntHeaders->OptionalHeader;
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
            const auto endAddress = sectionHeader->SizeOfRawData +
                                    reinterpret_cast<std::uintptr_t>(sectionBaseAddress);

            auto hasEncryption = false;
            while (startAddress < endAddress) {
                auto addressInformation = reader->QueryAddressInformaton((void *) startAddress);

                ASSERT(addressInformation.has_value() == true, "Memory query failed.");

                auto memInfo = addressInformation.value();
                if ((memInfo.Protect & PAGE_NOACCESS) == PAGE_NOACCESS) {
                    // This section is encrypted! Pre-Fill with 0xCC!
                    hasEncryption = true;
                    memset(reinterpret_cast<void *>(RVAToVA(baseAddress,
                                                            sectionHeader->PointerToRawData)),
                           0xCC, // fill with breakpoints.
                           sectionHeader->SizeOfRawData);
                    break;
                }

                startAddress += memInfo.RegionSize;
            }

            auto decryptionList = std::vector<std::uint32_t>{};

            if (hasEncryption) {
                auto pageCount = sectionHeader->SizeOfRawData / 0x1000;
                decryptionList.reserve(pageCount);

                for (auto pageIndex = 0; pageIndex < pageCount; pageIndex++)
                    decryptionList.emplace_back(pageIndex);
            }


            DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                      std::format("Cached new section: {}. Section Size: {}. Section Pages: {}. IsEncrypted: {}",
                          reinterpret_cast<char *>(sectionHeader->Name), sectionHeader->SizeOfRawData, sectionHeader->
                          SizeOfRawData / 0x1000,
                          (hasEncryption ? "Yes" : "No")));

            sections.emplace_back(
                sectionBaseAddress,
                reinterpret_cast<void *>(
                    sectionHeader->SizeOfRawData + reinterpret_cast<std::uintptr_t>(sectionBaseAddress)
                ),
                reinterpret_cast<const char *>(sectionHeader->Name),
                decryptionList,
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

        return sections;
    }

    std::vector<SectionInformation> &ImageDumper::GetOrGenerateSectionInformation() {
        if (!this->m_remoteImageSections.empty() && !this->m_bHasProcessImageMigrated)
            return this->m_remoteImageSections;


        if (!this->m_bHasProcessImageMigrated) {
            /*
             *  This is fairly simple stuff. We must grab the initial image reconstruction present on this->m_remoteImage and define the sections and initiate a dumper instance for them.
             *  This is not that complicated, it's just a bunch of garbage VA translation shit.
             */

            this->m_remoteImageSections = GenerateInitialSectionInformation(this->m_remoteImage, this->m_reader);

            return this->m_remoteImageSections;
        }


        const auto remoteBaseAddress = this->m_procImage.rlpModuleBase;

        const auto peHeader = this->m_reader->Read(remoteBaseAddress, 0x1000);

        const auto &peHeadersAsVector = peHeader.value();

        const auto baseAddress = reinterpret_cast<std::uintptr_t>(peHeadersAsVector.data());
        const auto imageBase = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);

        auto ntHeaders = static_cast<PIMAGE_NT_HEADERS>(RVAToVA(baseAddress, imageBase->e_lfanew));
        const auto optionalHeaders = &ntHeaders->OptionalHeader;
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        /*
         *  For partial image re-construction we have a few issues. Our image has to have its VirtualAddress and BaseAddress modified from its respective original,
         *  however we needn't do much other than modifying the REMOTE pointers into the actual sections.
         */

        for (auto &section: this->m_remoteImageSections) {
            // NOTE: this->m_remoteImageSections is in order with the section headers; this means the first in the vector is the first in the actual section definitions.
            const auto sectionBaseAddress = reinterpret_cast<void *>(RVAToVA(optionalHeaders->ImageBase,
                                                                             sectionHeader->VirtualAddress));

            section.rpSectionBegin = sectionBaseAddress;
            section.rpSectionEnd = reinterpret_cast<void *>(
                sectionHeader->SizeOfRawData + reinterpret_cast<std::uintptr_t>(sectionBaseAddress)
            );

            sectionHeader++;
        }

        this->m_bHasProcessImageMigrated = false;
        return this->m_remoteImageSections;
    }

    std::shared_ptr<std::vector<std::byte> > ImageDumper::GetRemoteImage() {
        return this->m_remoteImage;
        // TODO: Ensure that everything is complete before allowing the user to call this function???
    }
} // PE
// Dumper
// Dottik
