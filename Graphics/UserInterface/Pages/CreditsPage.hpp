//
// Created by Dottik on 29/11/2024.
//

#pragma once
#include <Graphics/Renderable.hpp>

namespace Dottik::Graphics::Render::UI::Pages {
    class Collaborator final : public Dottik::Graphics::Render::Renderable {
        std::optional<std::string> m_szRelationWithRbxStu;
        std::string m_szDiscordName;
        std::string m_szGithubName;
        std::vector<std::string> m_contributions;

    public:
        static std::shared_ptr<Collaborator> CreateCollaborator(const std::optional<std::string> &relationWithRbxStu,
                                                                const std::string &discordName,
                                                                const std::string &githubName,
                                                                const std::vector<std::string> &contributions) {
            auto collaborator = std::make_shared<Collaborator>();

            collaborator->m_szRelationWithRbxStu = relationWithRbxStu;
            collaborator->m_szDiscordName = discordName;
            collaborator->m_szGithubName = githubName;
            collaborator->m_contributions = contributions;
            return collaborator;
        }

        void Render(ImGuiContext *pContext) override;
    };

    class CreditsPage final : public Dottik::Graphics::Render::Renderable {
        std::vector<std::shared_ptr<Collaborator>> m_contributorList;
        std::shared_ptr<Collaborator> m_dottik;
        std::shared_ptr<Collaborator> m_pixeluted;

    public:
        CreditsPage();
        ~CreditsPage() override = default;
        void Render(ImGuiContext *pContext) override;
    };

} // namespace RbxStu::Render::UI::Pages
