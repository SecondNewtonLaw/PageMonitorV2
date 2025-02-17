//
// Created by Dottik on 15/2/2025.
//

#include "ImageDumper.hpp"
#include "Logger.hpp"
#include "SectionPatcher.hpp"
#include "Utilities.hpp"
#include "capstone/capstone.h"

#define RVAToVA(x, y) (void *)((std::uintptr_t)(x) + y)
#define AlignUp(x, align) (((x) + ((align)-1)) & ~((align)-1))

namespace Dottik::Dumper::PE {
    ImageDumper::ImageDumper(const ProcessImage &image, std::shared_ptr<Dottik::Dumper::RemoteReader> &reader,
                             Dottik::Dumper::Dumper *dumper) : m_dumper(dumper) {
        this->m_procImage = image;
        this->m_reader = reader;
        this->m_dumper = dumper;

        this->m_sectionBlacklist = {};
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

    void ImageDumper::WithSectionBlacklist(const std::vector<std::string> &blacklistedSections) {
        this->m_sectionBlacklist = blacklistedSections;
    }

    void ImageDumper::NewPatchSection(csh csh, const SectionInformation &section) {
        /*
         *  The section we must patch is encrypted, but we have the complete boundaries of it.
         *  if not that disassembling like a brute would be expensive, we wouldn't be having to manage our resources that greatly.
         *
         *  How to find functions?
         *      - Using call instructions we can determine function beginnings, however determining the end of functions is a completely different story.
         *  How to find the ending of functions?
         *      - We can iterate from the beginning of it downward, after which when we find a ret instruction, we can end the function there. However, if the function is a NO_RETURN,
         *      this means a CALL instruction will be present followed of INT3s we must continue until we hit a sub rsp, ... instruction. This is a stack setup, which should _not_ be present on a function's end.
         */

        SectionPatcher patcher{csh, section};

        for (const auto functions = patcher.FindFunctions(); const auto &function: functions) {
            patcher.PatchFunction(function);
            DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                      std::format("Patched sub_{:X}", reinterpret_cast<std::uintptr_t>(section.rpSectionBegin) +
                          reinterpret_cast<std::uintptr_t>(section.
                              pSectionBegin )- function.lpFunctionStart)); // Address rebasing to match PE BVA
        }
    }

    void ImageDumper::LegacyPatchSection(const csh csh, const SectionInformation &section) {
        /*
         *  Port of PageMonitor V1's patcher.
         */

        const auto ModifiesProcessorFlags = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_TEST == insn ||
                   ::x86_insn::X86_INS_CMP == insn ||
                   ::x86_insn::X86_INS_CMPPD == insn ||
                   ::x86_insn::X86_INS_CMPPS == insn ||
                   ::x86_insn::X86_INS_CMPSB == insn ||
                   ::x86_insn::X86_INS_CMPSD == insn ||
                   ::x86_insn::X86_INS_CMPSQ == insn ||
                   ::x86_insn::X86_INS_CMPSS == insn ||
                   ::x86_insn::X86_INS_CMPSW == insn ||
                   ::x86_insn::X86_INS_CMPXCHG == insn ||
                   ::x86_insn::X86_INS_CMPXCHG8B == insn ||
                   ::x86_insn::X86_INS_CMPXCHG16B == insn;
        };
        const auto IsInterrupt = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_INT == insn ||
                   ::x86_insn::X86_INS_INT1 == insn ||
                   ::x86_insn::X86_INS_INT3 == insn ||
                   ::x86_insn::X86_INS_INTO == insn ||
                   ::x86_insn::X86_INS_SYSCALL == insn;
        };
        const auto IsReturn = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_RET == insn ||
                   ::x86_insn::X86_INS_RETF == insn ||
                   ::x86_insn::X86_INS_RETFQ == insn;
        };
        const auto IsCall = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_CALL == insn;
        };
        const auto IsJump = [](const x86_insn &insn) {
            return ::x86_insn::X86_INS_JMP == insn ||
                   ::x86_insn::X86_INS_JAE == insn ||
                   ::x86_insn::X86_INS_JA == insn ||
                   ::x86_insn::X86_INS_JBE == insn ||
                   ::x86_insn::X86_INS_JB == insn ||
                   ::x86_insn::X86_INS_JCXZ == insn ||
                   ::x86_insn::X86_INS_JECXZ == insn ||
                   ::x86_insn::X86_INS_JE == insn ||
                   ::x86_insn::X86_INS_JGE == insn ||
                   ::x86_insn::X86_INS_JG == insn ||
                   ::x86_insn::X86_INS_JLE == insn ||
                   ::x86_insn::X86_INS_JL == insn ||
                   ::x86_insn::X86_INS_JNE == insn ||
                   ::x86_insn::X86_INS_JNO == insn ||
                   ::x86_insn::X86_INS_JNP == insn ||
                   ::x86_insn::X86_INS_JNS == insn ||
                   ::x86_insn::X86_INS_JO == insn ||
                   ::x86_insn::X86_INS_JP == insn ||
                   ::x86_insn::X86_INS_JRCXZ == insn ||
                   ::x86_insn::X86_INS_JS == insn;
        };
        const auto insn = cs_malloc(csh);

        for (auto i = 0; i < section.dwSectionSize / 0x1000; i++) {
            auto pageSize = static_cast<std::size_t>(0x1000);
            auto startChunk = reinterpret_cast<const std::uint8_t *>(
                reinterpret_cast<std::uintptr_t>(section.pSectionBegin) + 0x1000 * i);
            auto currentAddress =
                    reinterpret_cast<std::uintptr_t>(section.pSectionBegin) + 0x1000 * i;

            auto PREVIOUS_INSTRUCTION = ::x86_insn::X86_INS_NOP;

            while (cs_disasm_iter(csh, &startChunk, &pageSize,
                                  &currentAddress, insn)) {
                /*
                 *  To determine if an INT3 is ignorable, we must first consider that if the instruction coming before an int3 is CALL or an
                 *  instruction which causes any kind of branching, this means the instruction is LIKELY to mark the end of the function
                 *
                 *  OpCodes like CALL, JMP and RET may delimit functions endings if they come before INT3, but INT3 after other instructions are
                 *  traps placed by obfuscation tools or just plain garbage we read from the proc, but bad, lol.
                 */

                constexpr auto interrupt = unsigned char{0xCC};

                if ((!IsJump(PREVIOUS_INSTRUCTION) && !IsReturn(PREVIOUS_INSTRUCTION) && !IsInterrupt(
                         PREVIOUS_INSTRUCTION) && IsInterrupt(
                         static_cast<::x86_insn>(insn->id)) && memcmp(
                         reinterpret_cast<void *>(insn->address + insn->size),
                         &interrupt, 1) != 0)
                    || (IsCall(PREVIOUS_INSTRUCTION) || ModifiesProcessorFlags(PREVIOUS_INSTRUCTION)) && IsInterrupt(
                        static_cast<::x86_insn>(insn->id))) {
                    /*
                     *  The next instruction is not an interrupt, the previous instruction was not a jump (Which would denote an end in an execution block)
                     *  - Implementation note:
                     *      - Hyperion appears to be (IN PURPOSE) modifying CPU flags before interrupts, possibly relating to tripping
                     *        their IC and passing the Interrupt and ignoring it if such is the case that the flag is set?
                     *      - Hyperion appears to sometimes use the INT3 to perform return-based programming, possibly to break analysis (?)
                     */

                    memset(reinterpret_cast<void *>(insn->address), 0x90, insn->size); // Address is canonical.

                    if (IsCall(PREVIOUS_INSTRUCTION) && IsInterrupt(static_cast<::x86_insn>(insn->id))) {
                        /*
                         *  Due to this function likely ending here, we must replace the INT3 with a ret instruction.
                         */
                        memset(reinterpret_cast<void *>(insn->address), 0xC3, 1);
                    }

                    if ((ModifiesProcessorFlags(PREVIOUS_INSTRUCTION)) && IsInterrupt(
                            static_cast<::x86_insn>(insn->id))) {
                        auto addy = insn->address;
                        while (memcmp(reinterpret_cast<void *>(++addy), &interrupt, 1) == 0) {
                            memset(reinterpret_cast<void *>(addy), 0x90, 1);
                        }
                    }

                    PREVIOUS_INSTRUCTION = ::x86_insn::X86_INS_NOP;
                    continue;
                }

                PREVIOUS_INSTRUCTION = static_cast<::x86_insn>(insn->id);
            }
        }
        cs_free(insn, 1);
    }

    void ImageDumper::PatchImage(bool useNewPatchingLogic) {
        /*
         *  We must walk all segments which are encrypted and from them, we must get the assembly.
         *  Once we have the assembly, we will simply find all functions, and then if one of them
         *  has an int3 before a control-flow change occurs (i.e.: ret, jmp, jne, ...) we will simply
         *  patch the following chain of int3 into NOP, and continue.
         */

        DottikLog(
            Dottik::LogType::Information, Dottik::DumpingEngine,
            "Initializing capstone...");

        csh capstoneHandle{0};

        if (auto status = cs_open(cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_64, &capstoneHandle);
            status != cs_err::CS_ERR_OK) {
            throw std::exception("cannot initialize disassembler. Reason: capstone couldn't be initialized!");
        }

        cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(capstoneHandle, CS_OPT_SKIPDATA, CS_OPT_ON);

        for (const auto &section: this->GetOrGenerateSectionInformation()) {
            if (!section.bRequiresDecryption)
                continue;

            DottikLog(
                Dottik::LogType::Information, Dottik::DumpingEngine,
                std::format("Beginning patching on section {}... | Section space: {} - {} | Pages: {}", section.
                    szSectionName,
                    section.pSectionBegin, section.pSectionEnd, section.dwSectionSize / 0x1000));

            if (useNewPatchingLogic)
                this->NewPatchSection(capstoneHandle, section);
            else
                this->LegacyPatchSection(capstoneHandle, section);
        }
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
        const std::shared_ptr<Dottik::Dumper::RemoteReader> &reader,
        const std::vector<std::string> &blacklistedSections
    ) {
        const auto baseAddress = reinterpret_cast<std::uintptr_t>(remoteImage->data());
        const auto imageBase = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);

        auto ntHeaders = static_cast<PIMAGE_NT_HEADERS>(RVAToVA(baseAddress, imageBase->e_lfanew));
        const auto optionalHeaders = &ntHeaders->OptionalHeader;
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        std::vector<SectionInformation> sections{};
        sections.reserve(ntHeaders->FileHeader.NumberOfSections);

        for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
            auto skipSection = false;
            for (const auto &blacklistedSection: blacklistedSections) {
                if (strcmp(blacklistedSection.c_str(), reinterpret_cast<char *>(sectionHeader->Name)) == 0) {
                    skipSection = true;
                    break;
                }
            }

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

            if (skipSection) {
                memset(RVAToVA(baseAddress,
                               sectionHeader->PointerToRawData),
                       0xCC,
                       sectionHeader->SizeOfRawData);
                continue;
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

            this->m_remoteImageSections = GenerateInitialSectionInformation(
                this->m_remoteImage, this->m_reader, this->m_sectionBlacklist);

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
            auto skipSection = false;
            for (const auto &blacklistedSection: this->m_sectionBlacklist) {
                if (strcmp(blacklistedSection.c_str(), reinterpret_cast<char *>(sectionHeader->Name)) == 0) {
                    skipSection = true;
                    break;
                }
            }
            if (skipSection) {
                sectionHeader++;
                continue;
            }

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
