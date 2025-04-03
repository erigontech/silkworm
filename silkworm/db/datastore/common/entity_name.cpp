// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "entity_name.hpp"

#include <algorithm>

#include <silkworm/core/common/assert.hpp>

namespace silkworm::datastore {

std::vector<std::string> EntityName::pool_;

std::string_view EntityName::intern(std::string_view name) {
    auto it = std::ranges::find(pool_, name);
    if (it != pool_.end()) {
        return *it;
    }

    static constexpr size_t kMaxEntityNames = 64;
    pool_.reserve(kMaxEntityNames);
    SILKWORM_ASSERT(pool_.size() < pool_.capacity());

    pool_.push_back(std::string{name});
    return pool_.back();
}

}  // namespace silkworm::datastore
