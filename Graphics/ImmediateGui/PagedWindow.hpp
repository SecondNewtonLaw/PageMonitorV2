//
// Created by Dottik on 27/11/2024.
//

#pragma once
#include <memory>
#include <string>
#include <vector>

#include "Graphics/Renderable.hpp"

struct ImGuiContext;

namespace Dottik::Graphics::Render::UI {
    struct UIPage {
        std::shared_ptr<Dottik::Graphics::Render::Renderable> pageRenderer;
        std::string szPageName;
        bool bIsStub = false;
    };

    class PagedWindow final : public Dottik::Graphics::Render::Renderable {
        std::string m_szWindowName;
        int m_dwCurrentPageIndex;
        int m_dwRowsPerColumn;
        bool m_bRenderPageList;
        std::vector<UIPage> m_pages;

    public:
        explicit PagedWindow(const std::vector<UIPage> &pages,
                             const std::string &szWindowName, int rowsPerColumn);

        ~PagedWindow() override;

        [[nodiscard]] const UIPage &GetCurrentPage() const;

        void SetCurrentPage(int newCurrentPage);

        void RenderPageButtons();

        void Render(ImGuiContext *pContext) override;;
    };
}
