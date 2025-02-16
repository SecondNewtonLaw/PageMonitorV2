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

        std::vector<SectionInformation> GetOrGenerateSectionInformation();

        void ResolveInitialSections();

        std::vector<std::byte> GetRemoteImage();

        void DecryptSection(const SectionInformation &section);

        void ResolveEncryptedSections();

        bool ContainsEncryptedSections();
    };
} // PE
// Dumper
// Dottik
