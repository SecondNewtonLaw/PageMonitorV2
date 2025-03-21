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

#include "capstone/capstone.h"

namespace Dottik::Dumper::PE {
    struct SectionInformation {
        void *rpSectionBegin; // Remote buffer address.
        void *rpSectionEnd; // Remote buffer address.
        const char *szSectionName;
        std::vector<std::uint32_t> encryptedPages;
        std::vector<std::uint32_t> decryptedPages;
        bool bRequiresDecryption;
        PIMAGE_SECTION_HEADER pSectionHeader;
        PIMAGE_DOS_HEADER lpParentImageDosHeader;

        void *pSectionBegin; // Local buffer address.
        void *pSectionEnd; // Local buffer address.
        std::uint32_t dwSectionSize;
    };

    class ImageDumper final {
        Dottik::Dumper::Dumper *m_dumper;
        std::shared_ptr<std::vector<std::byte> > m_remoteImage;
        std::vector<SectionInformation> m_remoteImageSections;
        ProcessImage m_procImage;
        std::shared_ptr<Dottik::Dumper::RemoteReader> m_reader;
        bool m_bHasProcessImageMigrated;
        std::vector<std::string> m_sectionBlacklist;
        std::uint8_t m_bStubByte;

    public:
        [[maybe_unused]] explicit ImageDumper(const ProcessImage &image,
                                              std::shared_ptr<Dottik::Dumper::RemoteReader> &reader,
                                              Dottik::Dumper::Dumper *dumper);

        void WithStubByte(std::uint8_t stub);

        std::map<std::string, void*> GetExports();

        void RebaseImage(void *lpNewBase);

        void MigrateImage(const ProcessImage &image);

        void MigrateReader(const std::shared_ptr<Dottik::Dumper::RemoteReader> &reader);

        [[nodiscard]] ProcessImage GetProcessImage() const;

        void WithSectionBlacklist(const std::vector<std::string> &blacklistedSections);

        void FunctionPatchSection(csh csh, const SectionInformation &value);

        void PagePatchSection(csh csh, const SectionInformation &section);

        void PatchImage(bool useNewPatchingLogic);

        void BuildInitialImage();

        std::vector<SectionInformation> &GetOrGenerateSectionInformation();

        void ResolveInitialSections();

        std::shared_ptr<std::vector<std::byte> > GetRemoteImage();

        void DecryptSection(SectionInformation &section);

        void ResolveEncryptedSections();

        bool ContainsEncryptedSections();
    };
} // PE
// Dumper
// Dottik
