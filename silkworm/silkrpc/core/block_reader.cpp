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

#include <set>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/rawdb/util.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const BalanceChanges&) {
    json = {{}};
}

awaitable<void> BlockReader::read_balance_changes(BlockCache& cache, const BlockNumberOrHash& bnoh, BalanceChanges& /*balance_changes*/) const {
    ethdb::TransactionDatabase tx_database{transaction_};

    const auto block_with_hash = co_await core::read_block_by_number_or_hash(cache, tx_database, bnoh);
    const auto block_number = block_with_hash->block.header.number;

    SILK_INFO << "read_balance_changes: block_number: " << block_number;

    // const auto chain_id = co_await core::rawdb::read_chain_id(database_reader_);
    // const auto chain_config_ptr = lookup_chain_config(chain_id);
    auto current_executor = co_await boost::asio::this_coro::executor;
    auto state = transaction_.create_state(current_executor, database_reader_, block_number - 1);

    auto ps_cursor = co_await transaction_.cursor(db::table::kAccountChangeSetName);

    std::set<evmc::address> addresses;
    core::rawdb::Walker walker = [&](const silkworm::Bytes& key, const silkworm::Bytes& value) {
        auto bn = static_cast<uint64_t>(std::stol(silkworm::to_hex(key), nullptr, 16));
        if (bn <= block_number) {
            auto address = silkworm::to_evmc_address(value.substr(0, silkworm::kAddressLength));

            SILK_INFO << "Walker: processing block " << bn << " address 0x" << silkworm::to_hex(address);
            addresses.insert(address);
        }
        return bn != block_number;
    };

    const auto key = silkworm::db::block_key(block_number);
    SILK_INFO << "Ready to walk block " << block_number << ", starting key: " << silkworm::to_hex(key);

    co_await database_reader_.walk(db::table::kAccountChangeSetName, key, 0, walker);

    // dump_accounts.root = block_with_hash->block.header.state_root;

    // std::vector<silkworm::KeyValue> collected_data;

    // AccountWalker::Collector collector = [&](silkworm::ByteView k, silkworm::ByteView v) {
    //     if (max_result > 0 && collected_data.size() >= static_cast<std::size_t>(max_result)) {
    //         dump_accounts.next = silkworm::to_evmc_address(k);
    //         return false;
    //     }

    //     if (k.size() > silkworm::kAddressLength) {
    //         return true;
    //     }

    //     silkworm::KeyValue kv;
    //     kv.key = k;
    //     kv.value = v;
    //     collected_data.push_back(kv);
    //     return true;
    // };

    // AccountWalker walker{transaction_};
    // co_await walker.walk_of_accounts(block_number + 1, start_address, collector);

    // co_await load_accounts(tx_database, collected_data, dump_accounts, exclude_code);
    // if (!exclude_storage) {
    //     co_await load_storage(block_number, dump_accounts);
    // }

    co_return;
}
}  // namespace silkworm::rpc
