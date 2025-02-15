//
// Created by Dottik on 15/2/2025.
//

#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include "ProcessImage.hpp"
#include "Readers/RemoteReader.hpp"
#include "libassert/assert.hpp"

namespace Dottik::Dumper::PE {
    class ImageDumper final {
    public:
        static std::vector<std::byte>
        BuildInitialImage(const ProcessImage &image, std::shared_ptr<Dottik::Dumper::RemoteReader> &reader) {
                    ASSUME(image.dwModuleSize > 0x1000,
                           "dwModuleSize is under the sizeof(WindowsPage). What the hell happened?");
            std::vector<std::byte> buffer{};
            buffer.resize(
                    image.dwModuleSize); // reserve memory to use .data() directly on other places (because it's easier to manage lmao)
            auto remoteBaseAddress = image.rlpModuleBase;

            auto peHeader = reader->Read(remoteBaseAddress, 0x1000);

                    ASSERT(peHeader.has_value(), "Failed to read memory from remote process. Wtf?");

            const auto& mem = peHeader.value();

            memcpy(buffer.data(), mem.data(), mem.size());

            return buffer;
        }
    };
} // PE
// Dumper
// Dottik
