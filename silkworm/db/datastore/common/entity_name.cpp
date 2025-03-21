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
