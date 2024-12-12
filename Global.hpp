//
// Created by Dottik on 13/11/2024.
//

#pragma once
#include <type_traits>

namespace Dottik::Concepts {
    template<typename Derived, typename Base>
    concept TypeConstraint = std::is_base_of_v<Base, Derived>;
};
