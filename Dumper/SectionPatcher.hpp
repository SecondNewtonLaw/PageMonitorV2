//
// Created by Dottik on 16/2/2025.
//

#pragma once
#include "ImageDumper.hpp"
#include "capstone/capstone.h"


namespace Dottik::Dumper {
    struct Function {
        std::uintptr_t lpFunctionStart = -1;
        std::uintptr_t lpFunctionEnd = -1;

        Function() = default;

        Function(std::uintptr_t functionStart, std::uintptr_t functionEnd);;
    };

    class SectionPatcher final {
        csh m_csHandle = 0;
        PE::SectionInformation m_sectionInformation = {};

    public:
        SectionPatcher() = default;

        SectionPatcher(const csh &csh, const PE::SectionInformation &sectionData);

        std::vector<Function> FindFunctions();

        void PatchFunction(const Function &function);
    };
} // Dumper
// Dottik
