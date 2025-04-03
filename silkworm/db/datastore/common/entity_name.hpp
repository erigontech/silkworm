// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <absl/container/flat_hash_map.h>

namespace silkworm::datastore {

struct EntityName {
    const std::string_view name;

    explicit EntityName(std::string_view name1) : name{intern(name1)} {}

    friend bool operator==(const EntityName& lhs, const EntityName& rhs) {
        return lhs.name.data() == rhs.name.data();
    }
    friend bool operator!=(const EntityName& lhs, const EntityName& rhs) {
        return lhs.name.data() != rhs.name.data();
    }
    friend bool operator<(const EntityName& lhs, const EntityName& rhs) {
        return lhs.name < rhs.name;
    }

    std::string to_string() const { return std::string{name}; }

  private:
    static std::string_view intern(std::string_view name);
    static std::vector<std::string> pool_;
};

template <typename TValue>
using EntityMap = absl::flat_hash_map<EntityName, TValue, std::hash<EntityName>>;

}  // namespace silkworm::datastore

namespace std {

//! for using EntityName as a key of std::unordered_map
template <>
struct hash<silkworm::datastore::EntityName> {
    size_t operator()(const silkworm::datastore::EntityName& value) const noexcept {
        return reinterpret_cast<uintptr_t>(value.name.data());
    }
};

}  // namespace std
