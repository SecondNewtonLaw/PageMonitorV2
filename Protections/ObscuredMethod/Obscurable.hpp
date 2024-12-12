//
// Created by Dottik on 13/11/2024.
//

#pragma once
#include "../../AssemblyObfuscations.hpp"

namespace Dottik::Protections::Obscurables {
    template<typename T>
    class Obscurable {
        virtual void InternalDeobscurePointer(void *pData, void *pMetadata, void **out) {
            *out = pData;
        };

        virtual void InternalObscure(void *pData, void *pMetadata, void **out) {
            *out = pData;
        };

    public:
        virtual ~Obscurable() = default;

        T *DeobscurePointer(T *pData, T *pMetadata) {
            Confuse_Analysis

            auto r = static_cast<T *>(nullptr);

            Begin_DivertControlFlow
                ObfuscateControlFlow_VariantOne(InternalDeobscurePointer, this, pData, pMetadata, &r);
            End_DivertControlFlow

            return r;
        };

        T *ObscurePointer(T *pData, T *pMetadata) {
            Confuse_Analysis

            auto r = static_cast<T *>(nullptr);

            Begin_DivertControlFlow
                ObfuscateControlFlow_VariantOne(InternalObscure, this, pData, pMetadata, &r);
            End_DivertControlFlow

            return r;
        };
    };
}
