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

#include <map>
#include <memory>
#include <optional>

#include <silkworm/core/common/bytes.hpp>

#include "../common/entity_name.hpp"
#include "../common/step.hpp"
#include "common/cache.hpp"

namespace silkworm::snapshots {

struct DomainGetLatestCacheData {
    BytesOrByteView value;
    std::optional<datastore::Step> range_end{0};
};
using DomainGetLatestCache = Cache<DomainGetLatestCacheData>;
using DomainGetLatestCaches = std::map<datastore::EntityName, std::unique_ptr<DomainGetLatestCache>>;

}  // namespace silkworm::snapshots
