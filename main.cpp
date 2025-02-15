#include <iostream>

#include "AssemblyObfuscations.hpp"
#include "Logger.hpp"
#include "Global.hpp"
#include "backends/imgui_impl_win32.h"
#include "Protections/ObscuredValue.hpp"
#include "Protections/ObscuredMethod/XorObscurable.hpp"
#include "Graphics/Render/Dx11.hpp"
#include "Graphics/Render/RenderManager.hpp"
#include "Graphics/UserInterface/UserInterface.hpp"
#include "Dumper/Dumper.hpp"
#include "Dumper/Readers/WinApi.hpp"

#include <libassert/assert.hpp>
#include <memory>
#include <thread>

ImVec2 g_resizeTarget;

// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED)
                return 0;

            g_resizeTarget = ImVec2{
                static_cast<float>(static_cast<UINT>(LOWORD(lParam))),
                static_cast<float>(static_cast<UINT>(HIWORD(lParam)))
            };
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
                return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    }

    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

void RenderLoop(const bool &bRenderNext, std::shared_ptr<Dottik::Graphics::Render::RenderManager> renderManager) {
    while (bRenderNext) {
        if (0 != g_resizeTarget.x && 0 != g_resizeTarget.y) {
            renderManager->ResizeRender(
                static_cast<UINT>(g_resizeTarget.x), static_cast<UINT>(g_resizeTarget.y));
            g_resizeTarget = ImVec2{0.0f, 0.0f};
        }

        if (renderManager->IsRenderingEnabled()) {
            renderManager->PrepareRender();
            ASSERT(renderManager->Render() == Dottik::Graphics::Render::RenderStatus::Success);
        } else {
            DottikLog(Dottik::LogType::Warning, Dottik::Rendering,
                      "Window Occluded [X]");
        }
    }

    renderManager->CleanUp();
}

void InitializeRenderGui() {
    WNDCLASSEXW wndClass = {
            sizeof(wndClass), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
            L"DottikWnd", nullptr
    };

    ::RegisterClassExW(&wndClass);
    HWND hWnd = ::CreateWindowW(wndClass.lpszClassName, L"Page Monitor V2 ImGui UI", WS_OVERLAPPEDWINDOW, 100, 100,
                                1280,
                                800, nullptr, nullptr, wndClass.hInstance, nullptr);

    Dottik::Logger::GetSingleton()->Initialize(true);

    const auto renderManager = Dottik::Graphics::Render::RenderManager::GetSingleton();

    const auto nRenderer = std::make_shared<Dottik::Graphics::Render::DX11>(hWnd);

    ::ShowWindow(hWnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hWnd);

    renderManager->InitializeWithBackend(nRenderer, hWnd, wndClass);

    const auto ui = new Dottik::Graphics::Render::UserInterface();
    ui->Initialize();
    renderManager->AddToRenderList(ui);

    bool bRenderNext{true};

    std::thread(RenderLoop, bRenderNext, renderManager).detach();

    while (bRenderNext) {
        _mm_pause();

        MSG msg;
        if (::PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) {
                bRenderNext = false;
                break;
            }
        }
    }
}

int wmain(const int argc, const wchar_t **argv, const wchar_t **envp) {
    auto pid = 9936;
    auto winApiReader = std::make_shared<Dottik::Dumper::WinApi>(pid);
    Dottik::Dumper::Dumper dumper{pid, winApiReader};

    auto modules = dumper.GetAllRemoteProcessModules();

    dumper.DumpAllModules();
    return 0;
}
