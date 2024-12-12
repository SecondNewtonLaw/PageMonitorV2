//
// Created by Dottik on 27/11/2024.
//

#include "Initializable.hpp"

namespace Dottik::Miscellaneous {
    bool Initializable::IsInitialized() {
        return m_bIsInitialized;
    }

    bool Initializable::Initialize() {
        if (this->IsInitialized()) return false;

        this->m_bIsInitialized = true;
        return true;
    }
}
