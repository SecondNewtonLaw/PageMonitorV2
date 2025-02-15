//
// Created by Dottik on 15/2/2025.
//

#include "ImageDumper.hpp"


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

                ASSERT(peHeader.has_value(), "Failed to read memory from remote process. Wtf?");

        const auto &mem = peHeader.value();

        memcpy(this->m_remoteImage.data(), mem.data(), mem.size());
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
                memset(section.pSectionBegin, 0xCC, section.dwSectionSize);
            } else {
                // ASSUME(read.has_value() == true, "Failed to read section from remote process memory");
                memcpy(section.pSectionBegin, read.value().data(), section.dwSectionSize);
            }
        }

    }
} // PE
// Dumper
// Dottik
