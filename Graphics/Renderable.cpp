//
// Created by Dottik on 26/11/2024.
//

#include "Renderable.hpp"

#include <Logger.hpp>

#include "Render/RenderManager.hpp"

namespace Dottik::Graphics::Render {
    float Renderable::GetDeltaTime(ImGuiContext *pContext) const { return pContext->IO.DeltaTime; }

    void Renderable::PushSeparator() {
        // Stolen from land.
        ImGui::GetWindowDrawList()->AddLine(ImVec2(ImGui::GetCursorScreenPos().x - 9999, ImGui::GetCursorScreenPos().y),
                                            ImVec2(ImGui::GetCursorScreenPos().x + 9999, ImGui::GetCursorScreenPos().y),
                                            ImGui::GetColorU32(ImGuiCol_Border));
        ImGui::Dummy(ImVec2(0.f, 5.f));
    }

    void Renderable::DisableRender() { this->m_bIsRenderingEnabled = false; }

    void Renderable::EnableRender() { this->m_bIsRenderingEnabled = true; }

    bool Renderable::IsRenderingEnabled() {
        return Dottik::Graphics::Render::RenderManager::GetSingleton()->IsRenderingEnabled();
    }

    void Renderable::PreRender() {
    }

    void Renderable::Render(ImGuiContext *pContext) {
    }
} // namespace RbxStu::Render
