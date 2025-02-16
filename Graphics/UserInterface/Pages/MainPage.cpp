//
// Created by Dottik on 28/11/2024.
//

#include "MainPage.hpp"
#include "Logger.hpp"
#include <misc/cpp/imgui_stdlib.h>
#include <thread>

namespace Dottik::Graphics::Render::UI::Pages {
    void MainPage::Render(ImGuiContext *pContext) {

        ImGui::Text("Process Name: ");
        ImGui::CxxInputText("##ProcessName", &this->m_szTargetProcessName);
        ImGui::Text("Target: %s", this->m_szTargetProcessName.c_str());
        Renderable::PushSeparator();

        ImGui::Checkbox("Process Monitoring", &this->m_bMonitorProcess);
        ImGui::BulletText("Waits until the process opens before beginning to monitor pages.");

        ImGui::Checkbox("Dump All Images", &this->m_bDumpAllImages);
        ImGui::BulletText(
                "Dumps all images loaded on memory. If disabled, only the main image of the process will be dumped.");

        Renderable::PushSeparator();

        ImGui::BeginDisabled(
                !this->IsTargetProcessAlive() || this->m_bMonitorProcess || this->m_bCurrentlyDumpingProcess);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.19f, 0.19f, 0.19f, 0.54f));

        if (this->IsTargetProcessAlive() && this->m_bMonitorProcess && !this->m_bCurrentlyDumpingProcess) {
            DottikLog(Dottik::LogType::Information, Dottik::MainThread,
                      "Found target process live in memory! Beginning dump!");
            this->m_bCurrentlyDumpingProcess = true;
            std::thread([this]() {
                this->DumpTarget();
            }).detach();
        }

        if (ImGui::Button("Dump")) {
            this->m_bCurrentlyDumpingProcess = true;
            std::thread([this]() {
                this->DumpTarget();
            }).detach();
        }

        ImGui::PopStyleColor();
        ImGui::EndDisabled();


        if (Dottik::Logger::GetSingleton()->IsNewLogAvailable()) {
            this->m_szLogOutput += Dottik::Logger::GetSingleton()->GetHistoryLog();
            Dottik::Logger::GetSingleton()->MarkRead();
        }

        ImGui::CxxInputTextMultiline("##Log", &this->m_szLogOutput, ImVec2(pContext->CurrentWindow->Size.x - 15, 200),
                                     ImGuiInputTextFlags_ReadOnly);

        Renderable::Render(pContext);
    }

    bool MainPage::IsTargetProcessAlive() {
        if (!this->m_pDumper->IsUsable()) {
            auto dwProcessId = Dottik::Win32::Process::GetProcessIdByName(this->m_szTargetProcessName.c_str());
            return dwProcessId.has_value();
        }

        DWORD exitCode{0};
        return this->m_pDumper->GetProcessHandle() != INVALID_HANDLE_VALUE &&
               GetExitCodeProcess(this->m_pDumper->GetProcessHandle(), &exitCode) && exitCode == STILL_ACTIVE;
    }

    void MainPage::ApplyWorkarounds() {
        Sleep(100);
    }

    void MainPage::DumpTarget() {
        auto dwProcessId = Dottik::Win32::Process::GetProcessIdByName(this->m_szTargetProcessName.c_str());

                ASSERT(dwProcessId.has_value() == true,
                       "No process found. DumpTarget called with an invalid state");

        this->ApplyWorkarounds();

        dwProcessId = Dottik::Win32::Process::WaitForProcessToBeCreated(
                this->m_szTargetProcessName.c_str()); // HACK: fixes issue where the PID obtained is that of an WOW64 process, for no reason.

        auto winApiReader = std::make_shared<Dottik::Dumper::WinApi>(dwProcessId.value());

        m_pDumper = std::make_unique<Dottik::Dumper::Dumper>(dwProcessId.value(), winApiReader);

        if (this->m_bDumpAllImages) {
            auto modules = m_pDumper->GetAllRemoteProcessModules();
            m_pDumper->DumpAllModules();

            for (const auto &module: modules) {
                auto moduleName = Dottik::Utilities::WcharToString(module.wszModuleName.c_str());
                DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                          std::format("Dumped {} into ./dump_out/{}!",
                                      moduleName,
                                      moduleName));
            }

        } else {
            m_pDumper->DumpMainModule();
            DottikLog(Dottik::LogType::Information, Dottik::DumpingEngine,
                      std::format("Dumped {} into ./dump_out/{}!", this->m_szTargetProcessName,
                                  this->m_szTargetProcessName));
        }

        this->m_bCurrentlyDumpingProcess = false;
    }

    MainPage::MainPage() {
        this->m_szTargetProcessName = "";
        this->m_szLogOutput = "";
        this->m_bMonitorProcess = false;
        this->m_bDumpAllImages = false;
        this->m_bCurrentlyDumpingProcess = false;
        this->m_pDumper = std::make_unique<Dottik::Dumper::Dumper>();
    }
} // namespace RbxStu::Render::UI::Pages
