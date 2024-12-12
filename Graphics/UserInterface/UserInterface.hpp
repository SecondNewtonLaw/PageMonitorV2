//
// Created by Dottik on 27/11/2024.
//

#pragma once
#include <memory>
#include <Miscellaneous/Initializable.hpp>

#include "Graphics/Renderable.hpp"

namespace Dottik::Graphics::Render {
    namespace UI {
        class PagedWindow;
    }

    class UserInterface final : public Miscellaneous::Initializable, public Render::Renderable {
        std::shared_ptr<Dottik::Graphics::Render::UI::PagedWindow> m_pPagedWindow;

    public:
        UserInterface();

        bool Initialize() override;

        void Render(ImGuiContext *pContext) override;

        ~UserInterface() override = default;
    };
}
