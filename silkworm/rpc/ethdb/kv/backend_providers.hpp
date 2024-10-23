/*
   Copyright 2024 The Silkworm Authors

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

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>

namespace silkworm::rpc::ethdb::kv {

inline db::chain::BlockProvider block_provider(ethbackend::BackEnd* backend) {
    return [backend](auto block_num, HashAsSpan hash, bool read_senders, auto& block) -> Task<bool> {
        co_return co_await backend->get_block(block_num, hash, read_senders, block);
    };
}

inline db::chain::BlockNumberFromTxnHashProvider block_number_from_txn_hash_provider(ethbackend::BackEnd* backend) {
    return [backend](HashAsSpan hash) -> Task<BlockNum> {
        co_return co_await backend->get_block_number_from_txn_hash(hash);
    };
}

inline db::chain::BlockNumberFromBlockHashProvider block_number_from_block_hash_provider(ethbackend::BackEnd* backend) {
    return [backend](HashAsSpan hash) -> Task<BlockNum> {
        co_return co_await backend->get_block_number_from_hash(hash);
    };
}

inline db::chain::CanonicalBlockHashFromNumberProvider canonical_block_hash_from_number_provider(ethbackend::BackEnd* backend) {
    return [backend](BlockNum number) -> Task<evmc::bytes32> {
        co_return co_await backend->get_block_hash_from_block_number(number);
    };
}

inline db::chain::CanonicalBodyForStorageProvider canonical_body_for_storage_provider(ethbackend::BackEnd* backend) {
    return [backend](BlockNum number) -> Task<Bytes> {
        co_return co_await backend->canonical_body_for_storage(number);
    };
}

inline db::chain::Providers make_backend_providers(ethbackend::BackEnd* backend) {
    return {
        ethdb::kv::block_provider(backend),
        ethdb::kv::block_number_from_txn_hash_provider(backend),
        ethdb::kv::block_number_from_block_hash_provider(backend),
        ethdb::kv::canonical_block_hash_from_number_provider(backend),
        ethdb::kv::canonical_body_for_storage_provider(backend)};
}

}  // namespace silkworm::rpc::ethdb::kv
