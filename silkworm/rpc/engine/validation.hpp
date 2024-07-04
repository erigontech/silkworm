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

#include <optional>
#include <string>
#include <vector>

#include <tl/expected.hpp>

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::rpc::engine {

using BlobVersionedHashes = std::vector<Hash>;
using ValidationResult = tl::expected<void, std::string>;

ValidationResult validate_blob_hashes(const Block&, const std::optional<BlobVersionedHashes>&);

}  // namespace silkworm::rpc::engine
