// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
