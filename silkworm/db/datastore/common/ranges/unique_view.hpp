// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "merge_unique_view.hpp"

namespace silkworm::views {

template <
    std::ranges::input_range TRange,
    class Comp = MergeCompareFunc,
    class Proj = std::identity>
using UniqueView = MergeUniqueView<TRange, std::ranges::empty_view<std::iter_value_t<std::ranges::iterator_t<TRange>>>, Comp, Proj, Proj>;

template <class Comp = MergeCompareFunc, class Proj = std::identity>
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

template <class Comp = MergeCompareFunc, class Proj = std::identity>
inline constexpr UniqueViewFactory<Comp, Proj> unique;  // NOLINT(*-identifier-naming)

}  // namespace silkworm::views
