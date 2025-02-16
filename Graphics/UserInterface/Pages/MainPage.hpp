//
// Created by Dottik on 28/11/2024.
//

#pragma once

#include <Miscellaneous/ListenableEvent.hpp>
#include <Graphics/Renderable.hpp>
#include <Windows.h>
#include "Dumper/Dumper.hpp"
#include "Win32/Process.hpp"
#include "libassert/assert.hpp"
#include "../../../Logger.hpp"
#include "../../../Utilities.hpp"
#include <memory>
#include <format>

namespace Dottik::Graphics::Render::UI::Pages {
    class MainPage final : public Dottik::Graphics::Render::Renderable {
        std::string m_szTargetProcessName;
        std::string m_szLogOutput;
        bool m_bMonitorProcess;
        bool m_bDumpAllImages;
        bool m_bCurrentlyDumpingProcess;
        std::unique_ptr<Dottik::Dumper::Dumper> m_pDumper;
    public:
        MainPage();;

        void Render(ImGuiContext *pContext) override;

        void DumpTarget();

        bool IsTargetProcessAlive();

    };
} // namespace RbxStu::Render::UI::Pages
