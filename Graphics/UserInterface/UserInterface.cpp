//
// Created by Dottik on 27/11/2024.
//

#include "UserInterface.hpp"

#include <Logger.hpp>
#include <memory>
#include <mutex>

#include "Pages/CreditsPage.hpp"
#include "Pages/MainPage.hpp"
#include "Graphics/ImmediateGui/Keycodes.hpp"
#include "Graphics/ImmediateGui/PagedWindow.hpp"
#include "Graphics/RenderableStub.hpp"

namespace Dottik::Graphics::Render {
    UserInterface::UserInterface() {
        this->m_pPagedWindow = nullptr;
    }

    bool UserInterface::Initialize() {
        if (this->IsInitialized())
            return false;

        const auto pages = std::vector<UI::UIPage>{
            UI::UIPage{std::make_shared<Dottik::Graphics::Render::UI::Pages::MainPage>(), "Main"},
            UI::UIPage{std::make_shared<Dottik::Graphics::Render::UI::Pages::CreditsPage>(), "Credits"},
        };

        this->m_pPagedWindow = std::make_shared<UI::PagedWindow>(pages, "Page Monitor V2", 3);
        this->EnableRender();
        this->m_pPagedWindow->EnableRender();
        this->m_bIsInitialized = true;
        return true;
    }

    void UserInterface::Render(ImGuiContext *pContext) {
        this->m_pPagedWindow->Render(pContext);

        Renderable::Render(pContext);
    }
} // namespace RbxStu::Render
