//
// Created by Dottik on 16/2/2025.
//

#include "SectionPatcher.hpp"

#include <functional>

#include "Logger.hpp"

namespace Dottik::Dumper {
    Function::Function(const std::uintptr_t functionStart, const std::uintptr_t functionEnd) {
        this->lpFunctionStart = functionStart;
        this->lpFunctionEnd = functionEnd;
    }

    SectionPatcher::SectionPatcher(const csh &csh, const PE::SectionInformation &sectionData) {
        this->m_csHandle = csh;
        this->m_sectionInformation = sectionData;
    }

    std::vector<Function> SectionPatcher::FindFunctions() {
        std::vector<Function> functions{};

        const auto dosHeader = this->m_sectionInformation.lpParentImageDosHeader;
        const auto headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                lpParentImageDosHeader) + dosHeader->e_lfanew);

        const auto dataDirectory = &headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        const auto exceptionEntryCount = dataDirectory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        functions.reserve(exceptionEntryCount);
        // Approximately these more of these functions we will find on real apps.

        const auto runtimeFunctionEntry = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(
            reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                lpParentImageDosHeader) + static_cast<std::uintptr_t>(dataDirectory->VirtualAddress));

        const auto endOfExceptionDirectory = runtimeFunctionEntry + exceptionEntryCount;

        for (auto currentException = runtimeFunctionEntry; currentException < endOfExceptionDirectory; currentException
             ++) {
            if (currentException->BeginAddress == 0 && currentException->EndAddress == 0) {
                DottikLog(Dottik::LogType::Warning, Dottik::DumpingEngine,
                          std::format(
                              "Failed to determine Exceptions by data directories, relying on the assumption that .pdata contains the exception directory!."
                              , functions.size()));
                break;
            }
            functions.emplace_back(
                reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                    lpParentImageDosHeader) + currentException->BeginAddress,
                reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                    lpParentImageDosHeader) + currentException->EndAddress - 1
            );
        }

        if (functions.empty()) {
            auto firstSection = IMAGE_FIRST_SECTION(headers);

            int sectionNumber = 0;
            while (strcmp(reinterpret_cast<char const *>(firstSection->Name), ".pdata") != 0) {
                if (sectionNumber >= headers->FileHeader.NumberOfSections) {
                    break;
                }
                sectionNumber++;
                firstSection++;
            }

            if (sectionNumber <= headers->FileHeader.NumberOfSections) {
                const auto exceptionDirectory = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(
                    reinterpret_cast<std::uintptr_t>(dosHeader) + static_cast<std::uintptr_t>(firstSection->
                        PointerToRawData));

                auto newEndOfExceptionDirectory = exceptionDirectory + exceptionEntryCount;

                for (auto currentException = exceptionDirectory; currentException < newEndOfExceptionDirectory;
                     currentException
                     ++) {
                    functions.emplace_back(
                        reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                            lpParentImageDosHeader) + currentException->BeginAddress,
                        reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                            lpParentImageDosHeader) + currentException->EndAddress - 1
                    );
                }
            }
        }

        DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                  std::format("Obtained {} functions from Exception Unwinding Information.", functions.size()));

        return functions;
    }

    void SectionPatcher::PatchFunction(const Function &function) {
        const auto insn = cs_malloc(this->m_csHandle);

        do {
            auto functionSize = static_cast<std::size_t>(function.lpFunctionEnd - function.lpFunctionStart);

            const auto comparisonBuffer = new std::uint8_t[functionSize];
            memset(comparisonBuffer, 0xCC, functionSize);

            if (memcmp(comparisonBuffer, reinterpret_cast<void *>(function.lpFunctionStart), functionSize) == 0) {
                // This function is in a page that was not dumped by PageMonitor V2, skip the patching, or the analysis time will explode.
                delete[] comparisonBuffer;
                if (functionSize < 4) {
                    DottikLog(Dottik::LogType::Warning, Dottik::DumpingEngine,
                              "The function will not return anything, as we cannot fit the required bytes. Replaced the functions' instructions with 0xC3 (ret)")
                    memset(reinterpret_cast<void *>(function.lpFunctionStart), 0xC3, functionSize);
                    return;
                }
                memset(reinterpret_cast<void *>(function.lpFunctionStart), 0xC3, functionSize);
                const auto functionStart = reinterpret_cast<std::uint8_t *>(function.lpFunctionStart);
                *functionStart = 0x48;
                *(functionStart + 1) = 0x31;
                *(functionStart + 2) = 0xC0;
                *(functionStart + 3) = 0xC3;

                DottikLog(Dottik::LogType::Warning, Dottik::DumpingEngine,
                          "Added immediate xor rax, rax (48 31 C0) followed by ret (0xC3) instruction to function, as it exists in an encrypted page and may break analysis!")
                return;
            }

            auto startChunk = reinterpret_cast<const std::uint8_t *>(function.lpFunctionStart);
            auto currentAddress = static_cast<std::uintptr_t>(function.lpFunctionStart);

            while (cs_disasm_iter(this->m_csHandle, &startChunk, &functionSize,
                                  &currentAddress, insn)) {
                int counter = 0;
                while (counter <= insn->detail->groups_count) {
                    if (insn->detail->groups[counter++] == CS_GRP_INT) {
                        memset(reinterpret_cast<void *>(insn->address), 0x90, insn->size);
                        break;
                    }
                }
            }
        } while (false);

        cs_free(insn, 1);
    }

    void SectionPatcher::PatchPages() {
        /*
         * The pages that remain encrypted are known in the map.
         * We walk them all and replace interrupts with 0x90.
         */

        const auto insn = cs_malloc(this->m_csHandle);

        for (auto rvaIndex = this->m_sectionInformation.decryptedPages.begin();
             rvaIndex != this->m_sectionInformation.decryptedPages.end(); rvaIndex++) {
            auto currentSize = static_cast<std::size_t>(0x1000);
            auto startChunk = reinterpret_cast<const std::uint8_t *>(
                reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.pSectionBegin) + (0x1000 * *rvaIndex));
            auto currentAddress = reinterpret_cast<std::uintptr_t>(startChunk);

            while (cs_disasm_iter(this->m_csHandle, &startChunk, &currentSize,
                                  &currentAddress, insn)) {
                int counter = 0;
                while (counter <= insn->detail->groups_count) {
                    if (insn->detail->groups[counter++] == CS_GRP_INT) {
                        memset(reinterpret_cast<void *>(insn->address), 0x90, insn->size);
                        break;
                    }
                }
            }

            DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                      std::format("Patched page 0x{:X}", reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.
                              rpSectionBegin) +
                          reinterpret_cast<std::uintptr_t>(this->m_sectionInformation.pSectionBegin) - reinterpret_cast<
                          std::uintptr_t>(this->m_sectionInformation.pSectionBegin)+ (0x1000 * *rvaIndex)));
        }
        cs_free(insn, 1);
    }
}
