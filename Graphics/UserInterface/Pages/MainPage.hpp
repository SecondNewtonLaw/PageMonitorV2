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
        std::string m_szSectionBlacklist{""};
        std::string m_szTargetProcessName{""};
        std::string m_szLogOutput{""};
        bool m_bMonitorProcess{false};
        bool m_bDumpAllImages{false};
        bool m_bCurrentlyDumpingProcess{false};
        bool m_bAllowPartialDump{false};
        bool m_bPatchIllegalInsturctions{false};
        bool m_bUsePagePatchingLogic{false};
        bool m_bUseSectionBlacklist{false};
        bool m_bRebaseToZero{false};
        bool m_bEnableInterruptStub{false};

        std::unique_ptr<Dottik::Dumper::Dumper> m_pDumper;

    public:
        MainPage();

        void Render(ImGuiContext *pContext) override;

        void DumpTarget();

        bool IsTargetProcessAlive();

        void ApplyWorkarounds();
    };
} // namespace RbxStu::Render::UI::Pages
