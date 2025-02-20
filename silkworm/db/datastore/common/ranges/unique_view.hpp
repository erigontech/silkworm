/*
   Copyright 2025 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include "merge_unique_view.hpp"

namespace silkworm::views {

template <
    std::ranges::input_range TRange,
    class Comp = MergeUniqueCompareFunc,
    class Proj = std::identity>
using UniqueView = MergeUniqueView<TRange, std::ranges::empty_view<std::iter_value_t<std::ranges::iterator_t<TRange>>>, Comp, Proj, Proj>;

template <class Comp = MergeUniqueCompareFunc, class Proj = std::identity>
struct UniqueViewFactory {
    template <class TRange>
    constexpr UniqueView<TRange, Comp, Proj> operator()(
        TRange&& range,
        Comp comp = {}, Proj proj = {}) const {
        return UniqueView<TRange, Comp, Proj>{std::forward<TRange>(range), {}, std::move(comp), proj, proj};
    }

    template <class TRange>
    friend constexpr UniqueView<TRange, Comp, Proj> operator|(TRange&& range, const UniqueViewFactory& unique) {
        return unique(std::forward<TRange>(range));
    }
};

template <class Comp = MergeUniqueCompareFunc, class Proj = std::identity>
inline constexpr UniqueViewFactory<Comp, Proj> unique;

}  // namespace silkworm::views
