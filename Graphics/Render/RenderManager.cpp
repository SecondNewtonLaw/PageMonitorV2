//
// Created by Dottik on 11/12/2024.
//

#include "RenderManager.hpp"

#include "backends/imgui_impl_win32.h"


namespace Dottik::Graphics::Render {
    class RenderBackend;

    std::shared_ptr<RenderManager> RenderManager::pInstance;

    RenderManager::~RenderManager() {
    }

    void RenderManager::ResizeRender(const UINT dwWidth, const UINT dwHeight) {
        if (!this->IsInitialized())
            return;

        return this->m_pRenderBackend->ResizeBuffers(dwWidth, dwHeight);
    }

    void RenderManager::PrepareRender() const {
        this->m_pRenderBackend->PrepareRender();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
    }

    RenderStatus RenderManager::Render() {
        auto currentContext = ImGui::GetCurrentContext();
        for (const auto &object: this->m_renderList) {
            object->PreRender();
            if (object->IsRenderingEnabled()) {
                object->Render(currentContext);
            }
        }

        return this->m_pRenderBackend->Render();
    }

    bool RenderManager::UseVSync() const {
        return true;
    }

    void RenderManager::CleanUp() {
        for (const auto &obj: this->m_renderList)
            delete obj;

        this->m_renderList.clear();
        this->m_pRenderBackend->CleanUp();
        ::DestroyWindow(this->m_hWnd);
        ::UnregisterClassW(this->m_hWndClass.lpszClassName, this->m_hWndClass.hInstance);
    }

    void RenderManager::AddToRenderList(Renderable *renderable) {
        this->m_renderList.emplace_back(renderable);
    }

    std::shared_ptr<RenderManager> RenderManager::GetSingleton() {
        if (pInstance == nullptr)
            pInstance = std::make_shared<RenderManager>();

        return pInstance;
    }

    bool RenderManager::InitializeWithBackend(
        const std::shared_ptr<Dottik::Graphics::Render::RenderBackend> &newRenderBackend, HWND hWnd,
        WNDCLASSEXW &hWndClass) {
        if (this->IsInitialized())
            return false;

        this->m_hWnd = hWnd;
        this->m_pRenderBackend = newRenderBackend;
        this->m_hWndClass = hWndClass;
#if _DEBUG
        IMGUI_CHECKVERSION();
#endif
        ImGui::CreateContext();

        ImGui::StyleColorsDark();
        auto &io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad; // Enable Gamepad Controls

        return this->Initialize() && this->m_pRenderBackend->Initialize();
    }

    bool RenderManager::IsInitialized() {
        return this->m_pRenderBackend != nullptr && (
                   static_cast<std::uint8_t>(this->m_pRenderBackend->IsInitialized()) & static_cast<std::uint8_t>(this->
                       m_bIsInitialized));
    }

    bool RenderManager::Initialize() {
        ImGui_ImplWin32_Init(this->m_hWnd);
        this->m_bIsInitialized = true;
        return true;
    }

    bool RenderManager::IsRenderingEnabled() const {
        return this->m_pRenderBackend->CanRender();
    }
}
