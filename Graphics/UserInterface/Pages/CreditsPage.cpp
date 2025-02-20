//
// Created by Dottik on 29/11/2024.
//

#include "CreditsPage.hpp"

namespace Dottik::Graphics::Render::UI::Pages {
    void Collaborator::Render(ImGuiContext *pContext) {
        if (this->m_szRelationWithProject.has_value()) {
            ImGui::Text("%s: @%s (%s)", this->m_szRelationWithProject.value().c_str(), this->m_szDiscordName.c_str(),
                        this->m_szGithubName.c_str());
        } else {
            ImGui::Text("@%s (%s)", this->m_szDiscordName.c_str(), this->m_szGithubName.c_str());
        }

        if (!this->m_contributions.empty())
            for (const auto &contribution: this->m_contributions)
                ImGui::Text(std::format(" ~ {}", contribution).c_str());

        Renderable::Render(pContext);
    }

    CreditsPage::CreditsPage() {
        this->m_dottik = Collaborator::CreateCollaborator("Lead Programmer", "usrdottik", "SecondNewtonLaw", {});
        this->m_sourceMaterial = {};
        this->m_sourceMaterial.emplace_back(Collaborator::CreateCollaborator(
            "Contributor", "Unknown (for me)", "atrexus", {
                "Created Vulkan, the very original base of Page Monitor. "
            }));
        this->m_contributorList = {
            Collaborator::CreateCollaborator("Contributor", "pixeluted", "Pixeluted", {
                                                 "Helped with INT3 patcher by providing the method to obtain all functions in a binary, generically."
                                             }),
            Collaborator::CreateCollaborator("Contributor", "makesuredidedies", "MakeSureDudeDies", {
                                                 "Open Source project https://github.com/MakeSureDudeDies/HookChecker helped to learn how to walk exports."
                                             }),
        };
    }

    CreditsPage::~CreditsPage() {
        this->m_dottik.reset();
    }

    void CreditsPage::Render(ImGuiContext *pContext) {
        ImGui::Text(" ~~ Page Monitor V2 Development Team ~~ ");

        this->m_dottik->Render(pContext);

        ImGui::Text(" ~~ Page Monitor V2 Development Team ~~ ");
        Renderable::PushSeparator();

        if (!this->m_contributorList.empty()) {
            ImGui::Text(">> Contributors");

            for (const auto &contributor: this->m_contributorList)
                contributor->Render(pContext);
        }

        if (!this->m_sourceMaterial.empty()) {
            ImGui::Text(">> Source Material");

            for (const auto &sourceMaterialAuthors: this->m_sourceMaterial)
                sourceMaterialAuthors->Render(pContext);
        }


        Renderable::Render(pContext);
    }
} // namespace RbxStu::Render::UI::Pages
