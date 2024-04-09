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
#include <nlohmann/json.hpp>

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/chain_config.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc::core::rawdb {

using Addresses = std::vector<evmc::address>;
using Transactions = std::vector<silkworm::Transaction>;

Task<uint64_t> read_header_number(const DatabaseReader& reader, const evmc::bytes32& block_hash);

Task<ChainConfig> read_chain_config(const DatabaseReader& reader);

Task<uint64_t> read_chain_id(const DatabaseReader& reader);

Task<evmc::bytes32> read_canonical_block_hash(const DatabaseReader& reader, BlockNum block_number);

Task<intx::uint256> read_total_difficulty(const DatabaseReader& reader, const evmc::bytes32& block_hash, BlockNum block_number);

Task<silkworm::BlockHeader> read_current_header(const DatabaseReader& reader);

Task<evmc::bytes32> read_head_header_hash(const DatabaseReader& reader);

Task<uint64_t> read_cumulative_transaction_count(const DatabaseReader& reader, BlockNum block_number);

Task<std::optional<Receipts>> read_raw_receipts(const DatabaseReader& reader, BlockNum block_number);
Task<std::optional<Receipts>> read_raw_receipts2(const DatabaseReader& reader, BlockNum block_number);

Task<std::optional<Receipts>> read_receipts(const DatabaseReader& reader, const silkworm::BlockWithHash& block_with_hash);

Task<intx::uint256> read_total_issued(const core::rawdb::DatabaseReader& reader, BlockNum block_number);

Task<intx::uint256> read_total_burnt(const core::rawdb::DatabaseReader& reader, BlockNum block_number);

Task<intx::uint256> read_cumulative_gas_used(const core::rawdb::DatabaseReader& reader, BlockNum block_number);

}  // namespace silkworm::rpc::core::rawdb
