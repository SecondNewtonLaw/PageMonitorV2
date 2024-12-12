//
// Created by Dottik on 11/12/2024.
//

#pragma once
#include <complex.h>
#include <list>
#include <memory>
#include <Miscellaneous/Initializable.hpp>

#include "RenderBackend.hpp"
#include "Graphics/Renderable.hpp"

namespace Dottik::Graphics::Render {
    class RenderManager final : public Dottik::Miscellaneous::Initializable {
        static std::shared_ptr<RenderManager> pInstance;

        std::shared_ptr<Dottik::Graphics::Render::RenderBackend> m_pRenderBackend;
        HWND m_hWnd;
        std::list<Renderable *> m_renderList;
        WNDCLASSEXW m_hWndClass;
        bool m_bIsDisposed;

    public:
        ~RenderManager() override;;

        void ResizeRender(UINT dwWidth, UINT dwHeight);

        void PrepareRender() const;

        RenderStatus Render();

        bool UseVSync() const;

        void CleanUp();

        void AddToRenderList(Renderable *renderable);

        static std::shared_ptr<RenderManager> GetSingleton();

        bool InitializeWithBackend(const std::shared_ptr<Dottik::Graphics::Render::RenderBackend> &newRenderBackend,
                                   HWND hWnd, WNDCLASSEXW &hWndClass);

        bool IsInitialized() override;

        bool Initialize() override;

        bool IsRenderingEnabled() const;
    };
} // Dottik::Graphics::Render
