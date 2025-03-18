/*
   Copyright 2024 The Silkworm Authors

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

#include <string>
#include <string_view>

#include <absl/container/flat_hash_map.h>

namespace silkworm::datastore {

struct EntityName {
    const std::string_view name;

    friend bool operator==(const EntityName& lhs, const EntityName& rhs) {
        return lhs.name.data() == rhs.name.data();
    }
    friend bool operator!=(const EntityName& lhs, const EntityName& rhs) {
        return lhs.name.data() != rhs.name.data();
    }

    std::string to_string() const { return std::string{name}; }
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
