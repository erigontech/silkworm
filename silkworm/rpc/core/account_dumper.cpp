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
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/kv/state_reader.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/storage_walker.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::core {

Task<DumpAccounts> AccountDumper::dump_accounts(
    BlockCache& cache,
    const BlockNumOrHash& block_num_or_hash,
    const evmc::address& start_address,
    int16_t max_result,
    bool exclude_code,
    bool exclude_storage) {
    DumpAccounts dump_accounts;
    const auto chain_storage = transaction_.create_storage();

    const auto block_with_hash = co_await core::read_block_by_block_num_or_hash(cache, *chain_storage, transaction_, block_num_or_hash);
    if (!block_with_hash) {
        throw std::invalid_argument("dump_accounts: block not found");
    }

    dump_accounts.root = block_with_hash->block.header.state_root;

    auto key = db::code_domain_key(start_address);
    const auto block_num = block_with_hash->block.header.number + 1;
    const auto start_txn_number = co_await transaction_.first_txn_num_in_block(block_num);

    db::kv::api::DomainRangeQuery query{
        .table = db::table::kAccountDomain,
        .from_key = key,
        .timestamp = start_txn_number,
        .ascending_order = true};

    auto paginated_result = co_await transaction_.range_as_of((std::move(query)));
    auto it = co_await paginated_result.begin();

    while (const auto value = co_await it->next()) {
        DumpAccount dump_account;
        evmc::address address{bytes_to_address(value->first)};

        if (value->second.empty()) {
            continue;
        }

        if (max_result > 0 && dump_accounts.accounts.size() >= static_cast<size_t>(max_result)) {
            dump_accounts.next = bytes_to_address(value->first);
            break;
        }

        auto account{db::state::AccountCodec::from_encoded_storage_v3(value->second)};
        success_or_throw(account);

        dump_account.balance = account->balance;
        dump_account.nonce = account->nonce;
        dump_account.incarnation = account->incarnation;
        dump_account.code_hash = account->code_hash;
        dump_account.root = kZeroHash;

        if (account->code_hash != kZeroHash && !exclude_code) {
            db::kv::api::GetLatestQuery query_code{
                .table = db::table::kCodeDomain,
                .key = db::account_domain_key(address)};

            const auto code = co_await transaction_.get_latest(std::move(query_code));
            if (!code.value.empty()) {
                dump_account.code = code.value;
            }
        }
        dump_accounts.accounts.insert(std::pair<evmc::address, DumpAccount>(address, dump_account));
    }

    if (!exclude_storage) {
        co_await load_storage(block_num, dump_accounts);
    }

    co_return dump_accounts;
}

Task<void> AccountDumper::load_storage(BlockNum block_num, DumpAccounts& dump_accounts) {
    SILK_TRACE << "block_number " << block_num << " START";
    const auto txn_number = co_await transaction_.first_txn_num_in_block(block_num);

    for (auto& [address, account] : dump_accounts.accounts) {
        auto to = db::code_domain_key(address);
        increment(to);

        db::kv::api::DomainRangeQuery query{
            .table = db::table::kStorageDomain,
            .from_key = db::code_domain_key(address),
            .to_key = to,
            .timestamp = txn_number,
            .ascending_order = true};

        auto paginated_result = co_await transaction_.range_as_of(std::move(query));
        std::map<Bytes, Bytes> collected_entries;
        auto it = co_await paginated_result.begin();

        while (const auto value = co_await it->next()) {
            if (value->second.empty())
                continue;

            if (!account.storage.has_value()) {
                account.storage = Storage{};
            }
            auto& storage = *account.storage;
            SILKWORM_ASSERT(value->first.size() >= kAddressLength);
            const auto loc = value->first.substr(kAddressLength);
            storage[to_bytes32(loc)] = value->second;
            const auto hash = hash_of(loc);
            collected_entries[Bytes{hash.bytes, kHashLength}] = value->second;
        }

        trie::HashBuilder hb;
        for (const auto& [key, value] : collected_entries) {
            Bytes encoded{};
            rlp::encode(encoded, value);
            Bytes unpacked = trie::unpack_nibbles(key);

            hb.add_leaf(unpacked, encoded);
        }

        account.root = hb.root_hash();
    }
    SILK_TRACE << "block_number " << block_num << " END";
    co_return;
}

}  // namespace silkworm::rpc::core
