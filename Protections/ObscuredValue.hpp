//
// Created by Dottik on 13/11/2024.
//

#pragma once
#include "../Global.hpp"
#include <cstdint>

#include "ObscuredMethod/Obscurable.hpp"

namespace Dottik {
    template<typename T>
    class ObscuredValue final {
        Dottik::Protections::Obscurables::Obscurable<T> m_obscurable;
        std::uintptr_t m_qwStorage;

    public:
        ObscuredValue(Dottik::Protections::Obscurables::Obscurable<T> obscurable, T *p) {
            this->m_obscurable = obscurable;
            this->m_qwStorage = obscurable.ObscurePointer(p, this);
        };

        ObscuredValue operator*() {
            return this->m_obscurable.DeobscurePointer(this->m_qwStorage, this);
        }
    };
} // PageMonitorV2
