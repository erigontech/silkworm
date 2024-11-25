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

#include "block_reader.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/state/state_reader.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

using db::state::StateReader;

void to_json(nlohmann::json& json, const BalanceChanges& balance_changes) {
    for (const auto& entry : balance_changes) {
        json[address_to_hex(entry.first)] = to_quantity(entry.second);
    }
}

Task<void> BlockReader::read_balance_changes(BlockCache& cache, const BlockNumberOrHash& block_num_or_hash, BalanceChanges& balance_changes) const {
    const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(cache, chain_storage_, transaction_, block_num_or_hash);
    if (!block_with_hash) {
        throw std::invalid_argument("read_balance_changes: block not found");
    }
    const auto block_num = block_with_hash->block.header.number;

    SILK_TRACE << "read_balance_changes: block_num: " << block_num;

    StateReader state_reader{transaction_, block_num + 1};

    const auto start_txn_number = co_await transaction_.first_txn_num_in_block(block_num);
    const auto end_txn_number = co_await transaction_.first_txn_num_in_block(block_num + 1);

    db::kv::api::HistoryRangeQuery query{
        .table = db::table::kAccountDomain,
        .from_timestamp = static_cast<db::kv::api::Timestamp>(start_txn_number),
        .to_timestamp = static_cast<db::kv::api::Timestamp>(end_txn_number),
        .ascending_order = true};

    auto paginated_result = co_await transaction_.history_range(std::move(query));
    auto it = co_await paginated_result.begin();

    while (const auto value = co_await it.next()) {
        intx::uint256 old_balance{0};
        intx::uint256 current_balance{0};

        if (!value->second.empty()) {
            const auto account{Account::from_encoded_storage_v3(value->second)};
            if (account) {
                old_balance = account->balance;
            }
        }

        evmc::address address = bytes_to_address(value->first);

        if (auto current_account = co_await state_reader.read_account(address)) {
            current_balance = current_account->balance;
        }

        if (current_balance != old_balance) {
            balance_changes[address] = current_balance;
        }
    }

    SILK_DEBUG << "Changed balances: " << balance_changes.size();
}

}  // namespace silkworm::rpc
