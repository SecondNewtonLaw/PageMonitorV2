//
// Created by Dottik on 12/12/2024.
//

#pragma once
#include <cstddef>
#include <optional>

namespace Dottik::Dumper {
    class RemoteReader abstract {
    protected:
        static std::uintptr_t AlignAddress(const std::uintptr_t address) {
            return address % 0x1000ull == 0ull ? address : address & ~(0x1000ull - 1ull);
        }

    public:
        virtual ~RemoteReader() = default;

        virtual std::optional<std::byte *> Read(void *rpAddress, std::size_t memSize) {
            throw std::exception{"RemoteReader::Read: Not Implemented"};
        }

        virtual std::optional<std::byte *> ReadAligned(void *rpAddress, std::size_t memSize) {
            throw std::exception{"RemoteReader::ReadAligned: Not Implemented"};
        }
    };
} // Dumper
// Dottik
