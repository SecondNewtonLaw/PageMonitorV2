//
// Created by Dottik on 28/11/2024.
//

#pragma once
#include "imgui.h"

namespace Dottik::Graphics::Render {
    struct Color4 {
        float r = 0.0f, g = 0.0f, b = 0.0f, a = 0.0f;

        static Color4 FromRGB(float r, float g, float b) {
            return {
                r / 255,
                g / 255,
                b / 255,
                1
            };
        }

        static Color4 FromRGBNormalized(float r, float g, float b) {
            return {
                r, g, b, 1
            };
        }

        ImVec4 ToImGuiVec4() {
            return {
                r,
                g,
                b,
                a
            };
        }
    };
}
