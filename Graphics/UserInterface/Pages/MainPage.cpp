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

        ImGui::BeginDisabled(this->m_bCurrentlyDumpingProcess);

        ImGui::Text("Dumping Configuration");
        ImGui::Text("Allows you to configure how PageMonitor V2 dumps images from memory");

        ImGui::Checkbox("Process Monitoring", &this->m_bMonitorProcess);
        ImGui::BulletText("Waits until the process opens before beginning to monitor pages.");

        ImGui::Checkbox("Dump All Images", &this->m_bDumpAllImages);
        ImGui::BulletText(
            "Dumps all images loaded on memory. If disabled, only the main image of the process will be dumped.");

        ImGui::Checkbox("Partial Dump", &this->m_bAllowPartialDump);
        ImGui::BulletText(
            "The dumper will dump the PE as normal. However, when the dump is attempted again, it will pick right where it left off, maintaining the pages that were decrypted of the previous dump.");

        ImGui::EndDisabled();

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

        ImGui::BeginDisabled(
            this->m_pDumper == nullptr || !this->m_bAllowPartialDump);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.19f, 0.19f, 0.19f, 0.54f));

        if (ImGui::Button("Clear cached dumps")) {
            this->m_pDumper.reset();
            this->m_pDumper = nullptr;
        }

        ImGui::PopStyleColor();
        ImGui::EndDisabled();

        if (Dottik::Logger::GetSingleton()->IsNewLogAvailable()) {
            this->m_szLogOutput = Dottik::Logger::GetSingleton()->GetHistoryLog() + this->m_szLogOutput;
            Dottik::Logger::GetSingleton()->MarkRead();
        }

        Renderable::PushSeparator();
        ImGui::Text("Output Log (Console Output)");
        ImGui::CxxInputTextMultiline("##Log", &this->m_szLogOutput, ImVec2(pContext->CurrentWindow->Size.x - 15, 500),
                                     ImGuiInputTextFlags_ReadOnly);

        ImGui::BeginDisabled(this->m_szLogOutput.empty());
        if (ImGui::Button("Clear Log")) {
            this->m_szLogOutput.clear();
        }
        ImGui::EndDisabled();

        Renderable::Render(pContext);
    }

    bool MainPage::IsTargetProcessAlive() {
        return Dottik::Win32::Process::GetProcessIdByName(this->m_szTargetProcessName.c_str()).has_value();
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
            this->m_szTargetProcessName.c_str());
        // HACK: fixes issue where the PID obtained is that of an WOW64 process, for no reason.

        auto winApiReader = std::make_shared<Dottik::Dumper::WinApi>(dwProcessId.value());

        if (this->m_bAllowPartialDump && m_pDumper != nullptr && m_pDumper->IsUsable()) {
            m_pDumper->MigrateReaderAndObtainNewHandle(dwProcessId.value(), winApiReader);
        } else {
            m_pDumper = std::make_unique<Dottik::Dumper::Dumper>(dwProcessId.value(), winApiReader);
        }

        if (this->m_bDumpAllImages) {
            const auto modules = m_pDumper->GetAllRemoteProcessModules();
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
        this->m_bAllowPartialDump = false;
        this->m_bMonitorProcess = false;
        this->m_bDumpAllImages = false;
        this->m_bCurrentlyDumpingProcess = false;
        this->m_pDumper = nullptr;
    }
} // namespace RbxStu::Render::UI::Pages
