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

#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/db/kv/api/transaction.hpp>

namespace silkworm::db::chain {

// TODO(canepat) BlockReader or migrate to ChainStorage?

using Transactions = std::vector<silkworm::Transaction>;

Task<uint64_t> read_header_number(kv::api::Transaction& tx, const evmc::bytes32& block_hash);

Task<std::optional<intx::uint256>> read_total_difficulty(kv::api::Transaction& tx, const evmc::bytes32& block_hash, BlockNum block_number);

Task<evmc::bytes32> read_head_header_hash(kv::api::Transaction& tx);

}  // namespace silkworm::db::chain
