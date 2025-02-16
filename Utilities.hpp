//
// Created by Dottik on 15/2/2025.
//

#pragma once

#include <string>
#include <Windows.h>

namespace Dottik {

    class Utilities {
    public:
        static std::string WcharToString(const wchar_t *wideStr);
    };

} // Dottik
