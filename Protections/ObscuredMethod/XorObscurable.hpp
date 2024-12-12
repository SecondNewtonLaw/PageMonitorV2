//
// Created by Dottik on 13/11/2024.
//

#pragma once
#include <cstdint>
#include "Obscurable.hpp"

namespace Dottik::Protections::Obscurables {
    template<typename T>
    class XORObscurable final : public Obscurable<T> {
        void InternalDeobscurePointer(void *pData, void *pMetadata, void **out) override {
            *out = reinterpret_cast<void *>(reinterpret_cast<std::uintptr_t>(pData) ^ reinterpret_cast<std::uintptr_t>(
                                                pMetadata));
        }

        void InternalObscure(void *pData, void *pMetadata, void **out) override {
            *out = reinterpret_cast<T *>(reinterpret_cast<std::uintptr_t>(pData) ^ reinterpret_cast<std::uintptr_t>(
                                             pMetadata));
        }

    public:
        XORObscurable() = default;
    };
}
