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
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/state/state_reader.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/account_walker.hpp>
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
    const auto block_number = block_with_hash->block.header.number;

    dump_accounts.root = block_with_hash->block.header.state_root;

    std::vector<KeyValue> collected_data;

    AccountWalker::Collector collector = [&](ByteView k, ByteView v) {
        if (max_result > 0 && collected_data.size() >= static_cast<std::size_t>(max_result)) {
            dump_accounts.next = bytes_to_address(k);
            return false;
        }

        if (k.size() > kAddressLength) {
            return true;
        }

        KeyValue kv;
        kv.key = k;
        kv.value = v;
        collected_data.push_back(kv);
        return true;
    };

    AccountWalker walker{transaction_};
    co_await walker.walk_of_accounts(block_number + 1, start_address, collector);

    co_await load_accounts(collected_data, dump_accounts, exclude_code);
    if (!exclude_storage) {
        co_await load_storage(block_number + 1, dump_accounts);
    }

    co_return dump_accounts;
}

Task<void> AccountDumper::load_accounts(const std::vector<KeyValue>& collected_data, DumpAccounts& dump_accounts, bool exclude_code) {
    StateReader state_reader{transaction_};
    for (const auto& kv : collected_data) {
        const auto address = bytes_to_address(kv.key);

        auto account{Account::from_encoded_storage(kv.value)};
        success_or_throw(account);

        DumpAccount dump_account;
        dump_account.balance = account->balance;
        dump_account.nonce = account->nonce;
        dump_account.code_hash = account->code_hash;
        dump_account.incarnation = account->incarnation;

        if (account->incarnation > 0 && account->code_hash == kEmptyHash) {
            const auto storage_key{db::storage_prefix(address.bytes, account->incarnation)};
            auto code_hash{co_await transaction_.get_one(db::table::kPlainCodeHashName, storage_key)};
            if (code_hash.length() == kHashLength) {
                std::memcpy(dump_account.code_hash.bytes, code_hash.data(), kHashLength);
            }
        }
        if (!exclude_code) {
            auto code = co_await state_reader.read_code(dump_account.code_hash);
            dump_account.code.swap(code);
        }
        dump_accounts.accounts.insert(std::pair<evmc::address, DumpAccount>(address, dump_account));
    }

    co_return;
}

Task<void> AccountDumper::load_storage(BlockNum block_number, DumpAccounts& dump_accounts) {
    SILK_TRACE << "block_number " << block_number << " START";
    StorageWalker storage_walker{transaction_};
    evmc::bytes32 start_location{};
    for (auto& it : dump_accounts.accounts) {
        auto& address = it.first;
        auto& account = it.second;

        std::map<Bytes, Bytes> collected_entries;  // TODO(canepat) switch to ByteView?
        StorageWalker::AccountCollector collector = [&](const evmc::address& /*address*/, ByteView loc, ByteView data) {
            if (!account.storage.has_value()) {
                account.storage = Storage{};
            }
            auto& storage = *account.storage;
            storage[to_bytes32(loc)] = data;
            const auto hash = hash_of(loc);
            collected_entries[Bytes{hash.bytes, kHashLength}] = data;

            return true;
        };

        co_await storage_walker.walk_of_storages(block_number, address, start_location, account.incarnation, collector);

        trie::HashBuilder hb;
        for (const auto& [key, value] : collected_entries) {
            Bytes encoded{};
            rlp::encode(encoded, value);
            Bytes unpacked = trie::unpack_nibbles(key);

            hb.add_leaf(unpacked, encoded);
        }

        account.root = hb.root_hash();
    }
    SILK_TRACE << "block_number " << block_number << " END";
    co_return;
}

}  // namespace silkworm::rpc::core
