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

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/remote/kv/api/cursor.hpp>
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

Task<void> BlockReader::read_balance_changes(BlockCache& cache, const BlockNumberOrHash& bnoh, BalanceChanges& balance_changes) const {
    const auto block_with_hash = co_await core::read_block_by_number_or_hash(cache, chain_storage_, transaction_, bnoh);
    if (!block_with_hash) {
        throw std::invalid_argument("read_balance_changes: block not found");
    }
    const auto block_number = block_with_hash->block.header.number;

    SILK_TRACE << "read_balance_changes: block_number: " << block_number;

    StateReader state_reader{transaction_};

    co_await load_addresses(block_number, balance_changes);
    BalanceChanges::iterator it;
    for (it = balance_changes.begin(); it != balance_changes.end();) {
        auto account = co_await state_reader.read_account(it->first, block_number + 1);
        if (account.has_value()) {
            auto balance = account.value().balance;
            if (it->second == balance) {
                it = balance_changes.erase(it);
            } else {
                SILK_DEBUG << "Address "
                           << it->first << ": balance changed from " << to_quantity(it->second) << " to " << to_quantity(balance);
                it->second = balance;
                it++;
            }
        }
    }

    SILK_DEBUG << "Changed balances " << balance_changes.size();

    co_return;
}

Task<void> BlockReader::load_addresses(BlockNum block_number, BalanceChanges& balance_changes) const {
    auto acs_cursor = co_await transaction_.cursor(db::table::kAccountChangeSetName);
    const auto block_number_key = silkworm::db::block_key(block_number);

    auto decode = [](silkworm::ByteView value) {
        auto address = bytes_to_address(value.substr(0, kAddressLength));
        auto remain = value.substr(silkworm::kAddressLength);
        auto account{silkworm::Account::from_encoded_storage(remain)};

        return std::pair<evmc::address, intx::uint256>{address, account.value().balance};
    };

    auto kv = co_await acs_cursor->seek(block_number_key);
    auto pair = decode(kv.value);
    balance_changes.emplace(pair.first, pair.second);

    auto number = block_number;
    while (number == block_number) {
        kv = co_await acs_cursor->next();
        pair = decode(kv.value);
        balance_changes.emplace(pair.first, pair.second);
        number = static_cast<BlockNum>(std::stol(silkworm::to_hex(kv.key), nullptr, 16));
    }
}

}  // namespace silkworm::rpc
