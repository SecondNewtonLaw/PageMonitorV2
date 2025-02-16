//
// Created by Dottik on 15/2/2025.
//

#pragma once

#include <string>
#include <vector>
#include <Windows.h>

namespace Dottik {
    class Utilities {
    public:
        static std::string WcharToString(const wchar_t *wideStr);

        static std::vector<std::string> Split(const std::string &input, std::string_view divider);
    };
} // Dottik
