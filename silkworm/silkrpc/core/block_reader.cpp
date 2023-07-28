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
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/rawdb/util.hpp>

namespace silkworm::rpc {

awaitable<void> BlockReader::read_balance_changes(BlockCache& cache, const BlockNumberOrHash& bnoh, BalanceChanges& /*balance_changes*/) const {
    ethdb::TransactionDatabase tx_database{transaction_};

    /*const auto block_with_hash = */ co_await core::read_block_by_number_or_hash(cache, tx_database, bnoh);
    // const auto block_number = block_with_hash->block.header.number;

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
