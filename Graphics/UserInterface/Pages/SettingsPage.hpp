//
// Created by Dottik on 28/11/2024.
//

#pragma once
#include <Miscellaneous/ListenableEvent.hpp>
#include <Graphics/Renderable.hpp>

namespace Dottik::Graphics::Render::UI::Pages {
    class SettingsPage final : public Dottik::Graphics::Render::Renderable {
    public:
        SettingsPage() = default;

        ~SettingsPage() override = default;

        void Render(ImGuiContext *pContext) override;
    };
} // namespace RbxStu::Render::UI::Pages
