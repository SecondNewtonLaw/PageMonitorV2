//
// Created by Dottik on 11/12/2024.
//

#include "Dx11.hpp"
#include <dxgi.h>
#include <d3d11.h>
#include <format>

#include "RenderManager.hpp"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include "Exceptions/RenderInitializationError.hpp"

namespace Dottik::Graphics::Render {
    DX11::DX11(const HWND hWnd): m_pSwapchain(nullptr), m_pDevice(nullptr), m_pImmediateContext(nullptr),
                                 m_bIsSwapchainOccluded(false),
                                 m_pMainRenderViewTarget(nullptr), m_hWindow(hWnd), m_bDisposed(false) {
        this->m_hWindow = hWnd;
    }

    DX11::~DX11() {
        if (!this->m_bDisposed)
            this->CleanUp();
    }

    bool DX11::IsInitialized() {
        return !this->m_bDisposed && this->m_pSwapchain != nullptr && this->m_pDevice != nullptr && this->
               m_pImmediateContext != nullptr;
    }

    bool DX11::Initialize() {
        if (this->m_bDisposed) return false;
        // Swapchain initialization //
        DXGI_SWAP_CHAIN_DESC sd;
        ZeroMemory(&sd, sizeof(sd));
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 144;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = this->m_hWindow;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        // DXGI_SWAP_EFFECT_DISCARD; (Makes you render like Windows XP :fire:)

        UINT createDeviceFlags = 0;
#if _DEBUG
        createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

        D3D_FEATURE_LEVEL featureLevel;
        const D3D_FEATURE_LEVEL featureLevelArray[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0,};
        HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
                                                    featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &this->m_pSwapchain,
                                                    &this->m_pDevice, &featureLevel, &this->m_pImmediateContext);
        if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
            res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
                                                featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &this->m_pSwapchain,
                                                &this->m_pDevice, &featureLevel, &this->m_pImmediateContext);

        if (res != S_OK)
            throw Dottik::Exceptions::RenderInitializationError(
                "Failed to initialize D3D11 render backend: cannot initialize IDXGISwapChai :(");


        this->CreateRenderTarget();

        ImGui_ImplWin32_Init(this->m_hWindow);
        ImGui_ImplDX11_Init(this->m_pDevice, this->m_pImmediateContext);

        return true;
    }

    [[maybe_unused]] void DX11::PrepareRender() {
        if (this->m_bDisposed) return;
        ImGui_ImplWin32_NewFrame();
        ImGui_ImplDX11_NewFrame();
    }

    RenderStatus DX11::Render() {
        if (this->m_bDisposed) return RenderStatus::Failure;
        if (!this->CanRender()) return RenderStatus::NotRendering;

        ImGui::Render();

        constexpr float clearColor[4] = {
            0.55f, 0.55f, 0.55f, 1.0f
        };

        // ~ Set up render target
        this->m_pImmediateContext->OMSetRenderTargets(1, &this->m_pMainRenderViewTarget, nullptr);
        this->m_pImmediateContext->ClearRenderTargetView(this->m_pMainRenderViewTarget, clearColor);

        // ~ Submit data to GPU
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // ~ Present information
        const HRESULT presentResult = this->m_pSwapchain->Present(this->IsVsyncEnabled() ? 1 : 0, 0);

        this->m_bIsSwapchainOccluded = presentResult == DXGI_STATUS_OCCLUDED;

        return presentResult != DXGI_STATUS_OCCLUDED && presentResult != S_OK
                   ? RenderStatus::Failure
                   : RenderStatus::Success;
    }

    bool DX11::CanRender() {
        if (this->m_bIsSwapchainOccluded) {
            // Swapchain is occluded, we must test and update the occlusion status.
            this->m_bIsSwapchainOccluded = this->m_pSwapchain->Present(0,DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED;
        }

        return !this->m_bIsSwapchainOccluded;
    }

    Dottik::Graphics::Render::Backend DX11::GetBackendIdentifier() {
        return Backend::D3D11;
    }

    void DX11::CreateRenderTarget() {
        // ReSharper disable once CppDFAConstantConditions
        if (this->m_bDisposed) return;

        ID3D11Texture2D *pBackBuffer;
        HRESULT res = this->m_pSwapchain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));

        if (res != S_OK)
            throw Dottik::Exceptions::RenderInitializationError(
                "Failed to obtain swapchain back buffer.");

        res = this->m_pDevice->CreateRenderTargetView(pBackBuffer, nullptr, &this->m_pMainRenderViewTarget);

        if (res != S_OK)
            throw Dottik::Exceptions::RenderInitializationError(
                "Failed to create render target.");

        pBackBuffer->Release();
    }

    void DX11::ClearRenderTarget() {
        if (nullptr != m_pMainRenderViewTarget && !this->m_bDisposed) {
            this->m_pMainRenderViewTarget->Release();
            this->m_pMainRenderViewTarget = nullptr;
        }
    }


    void DX11::ResizeBuffers(UINT dwWidth, UINT dwHeight) {
        if (this->m_bDisposed) return;

        this->ClearRenderTarget();

        HRESULT res = this->m_pSwapchain->ResizeBuffers(2, dwWidth, dwHeight, DXGI_FORMAT_UNKNOWN, 0);

        if (res != S_OK)
            throw Dottik::Exceptions::RenderInitializationError(
                std::format("Failed to resize buffers: {:x}", res));

        this->CreateRenderTarget();

        D3D11_VIEWPORT vp;
        vp.Width = static_cast<float>(dwWidth);
        vp.Height = static_cast<float>(dwHeight);
        vp.MinDepth = 0.0f;
        vp.MaxDepth = 1.0f;
        vp.TopLeftX = 0;
        vp.TopLeftY = 0;
        this->m_pImmediateContext->RSSetViewports(1, &vp);
    }

    void DX11::CleanUp() {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        if (nullptr != this->m_pSwapchain) {
            this->m_pSwapchain->Release();
            this->m_pSwapchain = nullptr;
        }

        if (nullptr != this->m_pImmediateContext) {
            this->m_pImmediateContext->Release();
            this->m_pImmediateContext = nullptr;
        }

        if (nullptr != this->m_pDevice) {
            this->m_pDevice->Release();
            this->m_pDevice = nullptr;
        }

        this->m_bDisposed = true;
    }

    bool DX11::IsVsyncEnabled() {
        return this->m_bEnableVsync;
    }

    void DX11::UseVsync(bool newVsync) {
        this->m_bEnableVsync = newVsync;
    }
} // Graphics
// PageMonitorV2
