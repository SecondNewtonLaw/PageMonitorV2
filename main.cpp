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
#include <TlHelp32.h>

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
            // DottikLog(Dottik::LogType::Warning, Dottik::Rendering,
            //           "Window Occluded [X]");
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
    HWND hWnd = ::CreateWindowW(wndClass.lpszClassName, L"Page Monitor", WS_OVERLAPPEDWINDOW, 100, 100,
                                1280,
                                800, nullptr, nullptr, wndClass.hInstance, nullptr);

    Dottik::Logger::GetSingleton()->Initialize(true);

    const auto renderManager = Dottik::Graphics::Render::RenderManager::GetSingleton();

    const auto nRenderer = std::make_shared<Dottik::Graphics::Render::DX11>(hWnd);

    ::ShowWindow(hWnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hWnd);

    nRenderer->UseVsync(true);
    renderManager->InitializeWithBackend(nRenderer, hWnd, wndClass);

    const auto ui = new Dottik::Graphics::Render::UserInterface();
    ui->Initialize();
    renderManager->AddToRenderList(ui);

    bool bRenderNext{true};

    std::thread(RenderLoop, bRenderNext, renderManager).detach();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    DottikLog(Dottik::LogType::Information, Dottik::MainThread, "Welcome to PageMonitor V2!");

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


static bool
EnableTokenPrivilege(_In_ LPCTSTR Privilege) {
    HANDLE Token;
    TOKEN_PRIVILEGES TokenPrivileges;

    Token = NULL;
    RtlZeroMemory(&TokenPrivileges, sizeof(TOKEN_PRIVILEGES));

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return false;

    if (LookupPrivilegeValue(NULL, Privilege, &TokenPrivileges.Privileges[0].Luid)) {
        TokenPrivileges.PrivilegeCount = 1;
        TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        return AdjustTokenPrivileges(Token, FALSE, &TokenPrivileges, 0, (PTOKEN_PRIVILEGES) NULL, 0);
    }

    return false;
}

int CommonEntryPoint() {
    EnableTokenPrivilege(SE_DEBUG_NAME);
    InitializeRenderGui();

    return 0;
}

int CALLBACK WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow) {
    return CommonEntryPoint();
}

int wmain(const int argc, const wchar_t **argv, const wchar_t **envp) {
    // auto winApiReader = std::make_shared<Dottik::Dumper::WinApi>(GetProcessIdByName("RobloxPlayerBeta.exe"));
    // Dottik::Dumper::Dumper dumper{GetProcessIdByName("RobloxPlayerBeta.exe"), winApiReader};
    // dumper.DumpAllModules();
    return CommonEntryPoint();
}
