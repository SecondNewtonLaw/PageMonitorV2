//
// Created by Dottik on 28/11/2024.
//

#include "SettingsPage.hpp"

namespace Dottik::Graphics::Render::UI::Pages {
    std::shared_ptr<SettingsPage> SettingsPage::m_pInstance;


    std::shared_ptr<SettingsPage> SettingsPage::GetSingleton() { return SettingsPage::m_pInstance; }


    SettingsPage::SettingsPage() {
        SettingsPage::m_pInstance =
                std::shared_ptr<SettingsPage>(this); // WARNING: DO NOT MOVE OR YOU WILL BE ASSASSINATED, THIS HAS A
        // SIDE-EFFECT, THE ORDER MATTERS :angry:
    }

    void SettingsPage::Render(ImGuiContext *pContext) {
        Renderable::Render(pContext);
    }
} // namespace RbxStu::Render::UI::Pages
