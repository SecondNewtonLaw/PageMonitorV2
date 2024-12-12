//
// Created by Dottik on 28/11/2024.
//

#pragma once
#include <Miscellaneous/ListenableEvent.hpp>
#include <Graphics/Renderable.hpp>

namespace Dottik::Graphics::Render::UI::Pages {
    class SettingsPage final : public Dottik::Graphics::Render::Renderable {
        static std::shared_ptr<SettingsPage> m_pInstance;
        std::uintptr_t m_connectionId;
        std::string m_szRbxCrashKey;
        bool m_bEnableExperimentalFunctions = false;

    public:
        static std::shared_ptr<SettingsPage> GetSingleton();

        SettingsPage();

        ~SettingsPage() override = default;

        void Render(ImGuiContext *pContext) override;
    };
} // namespace RbxStu::Render::UI::Pages
