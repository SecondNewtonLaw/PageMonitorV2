//
// Created by Dottik on 11/12/2024.
//

#pragma once
#include <memory>
#include <Miscellaneous/Initializable.hpp>

#include "AssemblyObfuscations.hpp"

namespace Dottik::Graphics::Render {
    enum class Backend {
        D3D11,

        Unknown
    };

    enum class RenderStatus {
        Success,
        NotRendering,
        Failure,
    };

    /*
     *  Defines an abstract way to render dear ImGui using an API directly.
     */

    class RenderBackend abstract : public Dottik::Miscellaneous::Initializable {
    public:
        virtual void PrepareRender() {
        }

        virtual RenderStatus Render() {
            return RenderStatus::NotRendering; // Implement your own when overriding.
        }

        virtual bool CanRender() {
            return false;
        }

        virtual void ResizeBuffers(UINT dwWidth, UINT dwHeight) {
        }

        virtual Dottik::Graphics::Render::Backend GetBackendIdentifier() {
            return Backend::Unknown;
        }

        virtual void CleanUp() {

        }
    };
} // Dottik::Graphics
