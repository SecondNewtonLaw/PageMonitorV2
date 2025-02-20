//
// Created by Dottik on 17/2/2025.
//

#include "PortableExecutable.hpp"

#include <map>
#include <libassert/assert.hpp>

namespace Dottik::Win32 {
    PortableExecutable::PortableExecutable(const std::shared_ptr<std::vector<std::byte> > &rawPE) {
        this->m_peData = rawPE;
        this->m_peDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(this->m_peData->data());
        ASSERT(this->m_peDosHeader->e_magic == IMAGE_DOS_SIGNATURE, "Invalid DOS Header");
        this->m_peNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<std::uintptr_t>(this->m_peDosHeader) + this->m_peDosHeader->e_lfanew);
        ASSERT(this->m_peNTHeader->Signature == IMAGE_NT_SIGNATURE, "Invalid NT header");
    }

    bool PortableExecutable::HasDataDirectory(const Dottik::Win32::DataDirectoryEntry entry) const {
        return this->m_peNTHeader->OptionalHeader.DataDirectory[entry].VirtualAddress != 0;
    }

    PIMAGE_DATA_DIRECTORY PortableExecutable::GetDataDirectoryEntry(const Dottik::Win32::DataDirectoryEntry entry) {
        ASSERT(this->HasDataDirectory(entry), "Entry is not present on the executable");

        return this->m_peNTHeader->OptionalHeader.DataDirectory + entry;
    }

    bool PortableExecutable::CanRelocatePE() const {
        return this->HasDataDirectory(Dottik::Win32::DataDirectoryEntry::BaseRelocationsDirectory);
    }

    void PortableExecutable::RelocatePE(void *newBaseAddress) {
        ASSERT(this->CanRelocatePE(), "Cannot relocate PE. Missing relocations data directory");

        const auto relocations = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(this->GetDataDirectoryEntry(
            Dottik::Win32::DataDirectoryEntry::BaseRelocationsDirectory));

        auto baseRelocaton = this->VAToRawDataPointer(relocations->VirtualAddress);

        ASSERT(baseRelocaton.has_value(),
               "cannot reinterpret the VirtualAddress of the relocations directory into a proper data pointer");

        std::uint32_t currentRelocationOffset = 0ul;

        const auto dwDeltaImageBase = reinterpret_cast<std::uintptr_t>(newBaseAddress) - this->m_peNTHeader->
                                      OptionalHeader.
                                      ImageBase;

        while (currentRelocationOffset < relocations->Size) {
            const auto lpImageBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<std::uintptr_t>(baseRelocaton.value()) + currentRelocationOffset);
            currentRelocationOffset += sizeof(IMAGE_BASE_RELOCATION);
            const auto dwNumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof
                                           (IMAGE_RELOCATION_ENTRY);
            for (auto i = 0; i < dwNumberOfEntries; i++) {
                const auto lpImageRelocationEntry = reinterpret_cast<PIMAGE_RELOCATION_ENTRY>(
                    reinterpret_cast<std::uintptr_t>(baseRelocaton.value()) +
                    currentRelocationOffset);
                currentRelocationOffset += sizeof(IMAGE_RELOCATION_ENTRY);

                if (lpImageRelocationEntry->Type == IMAGE_REL_AMD64_ABSOLUTE)
                    continue; // Base relocation is to be skipped;

                const auto newAddressLocation = static_cast<std::uintptr_t *>(
                    this->VAToRawDataPointer(
                        lpImageBaseRelocation->VirtualAddress +
                        lpImageRelocationEntry->Offset).value());
                // This address has to be adjusted with the delta of our image base.

                *newAddressLocation = *newAddressLocation + dwDeltaImageBase; // Relocated.
            }
        }

        this->m_peNTHeader->OptionalHeader.ImageBase = reinterpret_cast<std::uintptr_t>(newBaseAddress);
    }

    std::map<std::string, void *> PortableExecutable::GetExports() {
        ASSUME(this->m_peNTHeader->OptionalHeader.NumberOfRvaAndSizes >= 0, "RVA + Sizes are less or equal to 0?");
        ASSERT(this->HasDataDirectory(Dottik::Win32::DataDirectoryEntry::ExportDirectory),
               "No export directory present on image");

        auto possibleExports = this->VAToRawDataPointer(
            this->GetDataDirectoryEntry(Dottik::Win32::DataDirectoryEntry::ExportDirectory)->VirtualAddress);

        ASSERT(possibleExports.has_value(), "No exports could be found when converting the RVA to RawDataAddress");

        const auto lpExports = static_cast<PIMAGE_EXPORT_DIRECTORY>(possibleExports.value());

        ASSERT(lpExports->NumberOfFunctions >= lpExports->NumberOfNames, "NumberOfFunctions < NumberOfNames; No clue how this can be handled lmao.");

        // Assuming that the function[i] == name[nameordinal[i]]

        const auto exportedFunctionsOptional = this->VAToRawDataPointer(lpExports->AddressOfFunctions);
        const auto exportedFunctionNamesOptional = this->VAToRawDataPointer(lpExports->AddressOfNames);
        const auto exportedFunctionNameOrdinalsOptional = this->VAToRawDataPointer(lpExports->AddressOfNameOrdinals);

        if (!exportedFunctionNamesOptional.has_value() || !exportedFunctionNameOrdinalsOptional.has_value() || !exportedFunctionsOptional.has_value())
            return {};  // Cannot parse exports, failed to convert RVA->FileAddress. Is the export table corrupted?

        const auto exportedFunctionPointersRvaTable = static_cast<std::uint32_t *>(exportedFunctionsOptional.value());
        const auto exportedFunctionNamesRvaTable = static_cast<std::uint32_t *>(exportedFunctionNamesOptional.value());
        const auto exportedFunctionNameOrdinalsRvaTable = static_cast<std::uint16_t *>(
            exportedFunctionNameOrdinalsOptional.value());

        auto exportsMap = std::map<std::string, void *>();

        for (auto i = 0; i < lpExports->NumberOfNames; i++) {
            const auto possibleExportName = this->VAToRawDataPointer(
                exportedFunctionNamesRvaTable[i]);

            ASSERT(possibleExportName.has_value(), "Failed to retrieve export name RVA in exports table.");

            const auto functionPointerTableIndex = exportedFunctionNameOrdinalsRvaTable[i];
            // Ordinal is the index into the actual func table.

            const auto possibleFunctionAddress = this->VAToRawDataPointer(
                exportedFunctionPointersRvaTable[functionPointerTableIndex]);

            ASSERT(possibleFunctionAddress.has_value(), "Failed to retrieve function pointer from RVA table");

            exportsMap[static_cast<char *>(possibleExportName.value())] = possibleFunctionAddress.value();
        }

        return exportsMap;
    }

    std::optional<void *> PortableExecutable::VAToRawDataPointer(const std::uint32_t relativeVirtualAddress) {
        const auto lpLastSection =
                IMAGE_FIRST_SECTION(this->m_peNTHeader) + this->m_peNTHeader->FileHeader.NumberOfSections;
        for (auto lpSection = IMAGE_FIRST_SECTION(this->m_peNTHeader); lpSection < lpLastSection; lpSection++) {
            const auto dwVirtualAddress = static_cast<std::uint32_t>(lpSection->VirtualAddress);
            const auto dwVirtualSize = static_cast<std::uint32_t>(lpSection->Misc.VirtualSize);

            if (dwVirtualAddress <= relativeVirtualAddress && relativeVirtualAddress < dwVirtualAddress +
                dwVirtualSize) {
                // RVA is in this section.
                return reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(this->m_peDosHeader) + (
                                                    relativeVirtualAddress - dwVirtualAddress) + lpSection->
                                                PointerToRawData);
            }
        }

        return std::nullopt;
    }
}
