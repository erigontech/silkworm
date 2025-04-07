// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "validation.hpp"

#include <silkworm/core/types/transaction.hpp>

namespace silkworm::rpc::engine {

ValidationResult validate_blob_hashes(const Block& block, const std::optional<BlobVersionedHashes>& expected_blob_versioned_hashes) {
    BlobVersionedHashes blob_versioned_hashes;
    for (const auto& tx : block.transactions) {
        if (tx.type == TransactionType::kBlob) {
            blob_versioned_hashes.insert(blob_versioned_hashes.end(),
                                         tx.blob_versioned_hashes.cbegin(), tx.blob_versioned_hashes.cend());
        }
    }
    if (expected_blob_versioned_hashes && blob_versioned_hashes != *expected_blob_versioned_hashes) {
        return tl::make_unexpected("computed blob versioned hashes list does not match expected one");
    }
    if (!expected_blob_versioned_hashes && !blob_versioned_hashes.empty()) {
        return tl::make_unexpected("computed blob versioned hashes list is not empty");
    }
    return {};
}

}  // namespace silkworm::rpc::engine
