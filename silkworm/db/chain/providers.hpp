/*
   Copyright 2023 The Silkworm Authors

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

#include <functional>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::db::chain {

using BlockProvider = std::function<Task<bool>(BlockNum, HashAsSpan, bool, Block&)>;
using BlockNumberFromTxnHashProvider = std::function<Task<BlockNum>(HashAsSpan)>;
using BlockNumberFromBlockHashProvider = std::function<Task<std::optional<BlockNum>>(HashAsSpan)>;
using CanonicalBlockHashFromNumberProvider = std::function<Task<std::optional<evmc::bytes32>>(BlockNum)>;
using CanonicalBodyForStorageProvider = std::function<Task<std::optional<Bytes>>(BlockNum)>;

struct Providers {
    BlockProvider block;
    BlockNumberFromTxnHashProvider block_number_from_txn_hash;
    BlockNumberFromBlockHashProvider block_number_from_hash;
    CanonicalBlockHashFromNumberProvider canonical_block_hash_from_number;
    CanonicalBodyForStorageProvider canonical_body_for_storage;
};

}  // namespace silkworm::db::chain
