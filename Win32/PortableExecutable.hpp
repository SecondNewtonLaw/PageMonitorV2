//
// Created by Dottik on 17/2/2025.
//

#pragma once
#include <complex.h>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <Windows.h>
#include <winternl.h>

// Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY {
    WORD Offset: 12;
    WORD Type: 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

namespace Dottik::Win32 {
    enum DataDirectoryEntry {
        ExportDirectory = IMAGE_DIRECTORY_ENTRY_EXPORT,
        ImportDirectory = IMAGE_DIRECTORY_ENTRY_IMPORT,
        ResourceDirectory = IMAGE_DIRECTORY_ENTRY_RESOURCE,
        ExceptionDirectory = IMAGE_DIRECTORY_ENTRY_EXCEPTION,
        SecurityDirectory = IMAGE_DIRECTORY_ENTRY_SECURITY,
        BaseRelocationsDirectory = IMAGE_DIRECTORY_ENTRY_BASERELOC,
        ArchitectureSpecificDataDirectory_RESERVED = IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
        GlobalPointerDirectory = IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
        ThreadLocalStorageDirectory = IMAGE_DIRECTORY_ENTRY_TLS,
        LoadConfigurationDirectory = IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
        BoundImportDirectoryInHeaderDirectory = IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
        ImportAddressTableDirectory = IMAGE_DIRECTORY_ENTRY_IAT,
        DelayLoadImportDescriptorsDirectory = IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
        COMRuntimeDescriptorDirectory = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    };

    class PortableExecutable final {
        std::shared_ptr<std::vector<std::byte> > m_peData = {};
        PIMAGE_DOS_HEADER m_peDosHeader = nullptr;
        PIMAGE_NT_HEADERS m_peNTHeader = nullptr;

    public:
        PortableExecutable() = default;

        explicit PortableExecutable(const std::shared_ptr<std::vector<std::byte> > &rawPE);

        [[nodiscard]] bool HasDataDirectory(Dottik::Win32::DataDirectoryEntry entry) const;

        PIMAGE_DATA_DIRECTORY GetDataDirectoryEntry(Dottik::Win32::DataDirectoryEntry entry);

        [[nodiscard]] bool CanRelocatePE() const;

        void RelocatePE(void *newBaseAddress);

        std::map<std::string, void *> GetExports();

        std::optional<void *> VAToRawDataPointer(std::uint32_t relativeVirtualAddress);
    };
}
