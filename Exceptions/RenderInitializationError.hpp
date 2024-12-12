//
// Created by Dottik on 11/12/2024.
//

#pragma once

#include <exception>
#include <string>
#include <utility>

namespace Dottik::Exceptions {
    class RenderInitializationError final : public std::exception {
        std::string szError;

    public:
        explicit RenderInitializationError(std::string szError) : szError(std::move(szError)) {
        }

        ~RenderInitializationError() noexcept override = default;

        [[nodiscard]] const char *what() const override {
            return this->szError.c_str();
        }
    };
}
