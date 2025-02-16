//
// Created by Dottik on 15/2/2025.
//

#include "Utilities.hpp"

namespace Dottik {
    std::string Utilities::WcharToString(const wchar_t *wideStr) {
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
        if (sizeNeeded == 0) {
            return "CONVERSION FAILED";
        }

        std::string result(sizeNeeded, 0);

        WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], sizeNeeded, nullptr, nullptr);
        result.pop_back();

        return result;
    }
} // Dottik