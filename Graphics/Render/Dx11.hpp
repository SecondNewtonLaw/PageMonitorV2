//
// Created by Dottik on 11/12/2024.
//

#pragma once

#include <d3d11.h>

#include "RenderBackend.hpp"
#include <dxgi.h>

namespace Dottik::Graphics::Render {
    class DX11 final : public Dottik::Graphics::Render::RenderBackend {
        HWND m_hWindow;

        bool m_bEnableVsync;

        // DX11 Specfific.
        IDXGISwapChain *m_pSwapchain;
        ID3D11Device *m_pDevice;
        ID3D11DeviceContext *m_pImmediateContext;
        bool m_bIsSwapchainOccluded;
        ID3D11RenderTargetView *m_pMainRenderViewTarget;
        bool m_bDisposed;

        void ClearRenderTarget();

        void CreateRenderTarget();

    public:
        explicit DX11(HWND hWnd);;

        ~DX11() override;

        [[maybe_unused]] void UseVsync(bool newVsync) override;

        [[maybe_unused]] bool IsVsyncEnabled() override;

        [[maybe_unused]] bool IsInitialized() override;

        bool Initialize() override;

        [[maybe_unused]] void PrepareRender() override;

        RenderStatus Render() override;

        bool CanRender() override;

        [[maybe_unused]] Dottik::Graphics::Render::Backend GetBackendIdentifier() override;

        [[maybe_unused]] void ResizeBuffers(UINT dwWidth, UINT dwHeight) override;

        void CleanUp() override;

    };
} // PageMonitor::Graphics
