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
