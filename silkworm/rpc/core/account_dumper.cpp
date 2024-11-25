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

#include "account_dumper.hpp"

#include <utility>

#include <silkworm/core/common/decoding_result.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/state/state_reader.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/storage_walker.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::core {

using db::state::StateReader;

Task<DumpAccounts> AccountDumper::dump_accounts(
    BlockCache& cache,
    const BlockNumberOrHash& bnoh,
    const evmc::address& start_address,
    int16_t max_result,
    bool exclude_code,
    bool exclude_storage) {
    DumpAccounts dump_accounts;
    const auto chain_storage = transaction_.create_storage();

    const auto block_with_hash = co_await core::read_block_by_number_or_hash(cache, *chain_storage, transaction_, bnoh);
    if (!block_with_hash) {
        throw std::invalid_argument("dump_accounts: block not found");
    }

    dump_accounts.root = block_with_hash->block.header.state_root;

    std::vector<KeyValue> collected_data;

    auto key = db::code_domain_key(start_address);
    auto block_number = block_with_hash->block.header.number + 1;
    const auto start_txn_number = co_await transaction_.first_txn_num_in_block(block_number);

    db::kv::api::DomainRangeQuery query{
        .table = db::table::kAccountDomain,
        .from_key = key,
        .timestamp = start_txn_number,
        .ascending_order = true};

    auto paginated_result = co_await transaction_.range_as_of((std::move(query)));
    auto it = co_await paginated_result.begin();

    std::set<evmc::address> addresses;
    while (const auto value = co_await it.next()) {
        if (value->first.empty()) {
            continue;
        }

        if (max_result > 0 && collected_data.size() >= static_cast<size_t>(max_result)) {
            dump_accounts.next = bytes_to_address(value->first);
            break;
        }

        ByteView encoded_view(value->second);
        evmc::address address{bytes_to_address(value->first)};

        auto account{Account::from_encoded_storage(encoded_view)};
        success_or_throw(account);
        DumpAccount dump_account;
        dump_account.balance = account->balance;
        dump_account.nonce = account->nonce;
        dump_account.incarnation = account->incarnation;

        if (account->incarnation > 0 && account->code_hash != kEmptyHash && !exclude_code) {
            dump_account.code_hash = account->code_hash;

            db::kv::api::DomainPointQuery query_code{
                .table = db::table::kCodeDomain,
                .key = db::account_domain_key(address)};

            const auto code = co_await transaction_.get_latest(std::move(query_code));
            if (code.success) {
                dump_account.code = code.value;
            }
        }
        dump_accounts.accounts.insert(std::pair<evmc::address, DumpAccount>(address, dump_account));
    }

    if (!exclude_storage) {
        co_await load_storage(block_number, dump_accounts);
    }

    co_return dump_accounts;
}

Task<void> AccountDumper::load_storage(BlockNum block_number, DumpAccounts& dump_accounts) {
    SILK_TRACE << "block_number " << block_number << " START";
    StorageWalker storage_walker{transaction_};
    const auto txn_number = co_await transaction_.first_txn_num_in_block(block_number);

    for (auto& it : dump_accounts.accounts) {
        auto& address = it.first;
        auto& account = it.second;

        auto to = db::code_domain_key(address);
        increment(to);

        db::kv::api::DomainRangeQuery query{
            .table = db::table::kStorageDomain,
            .from_key = db::code_domain_key(address),
            .to_key = to,
            .timestamp = txn_number,
            .ascending_order = true};

        auto paginated_result = co_await transaction_.range_as_of(std::move(query));
        auto sit = co_await paginated_result.begin();

        while (const auto value = co_await sit.next()) {
            if (value->second.empty())
                continue;

            if (!account.storage.has_value()) {
                account.storage = Storage{};
            }
            auto& storage = *account.storage;
            auto loc = value->first.substr(20);
            storage[to_bytes32(loc)] = value->second;
        }
    }
    SILK_TRACE << "block_number " << block_number << " END";
    co_return;
}

}  // namespace silkworm::rpc::core
