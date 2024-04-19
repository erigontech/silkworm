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

#include <optional>
#include <string>

#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/ethdb/kv/state_cache.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc::ethdb::kv {

class CachedDatabase : public core::rawdb::DatabaseReader {
  public:
    explicit CachedDatabase(BlockNumberOrHash block_id, Transaction& txn, kv::StateCache& state_cache);

    CachedDatabase(const CachedDatabase&) = delete;
    CachedDatabase& operator=(const CachedDatabase&) = delete;

    Task<KeyValue> get(const std::string& table, silkworm::ByteView key) const override;

    Task<silkworm::Bytes> get_one(const std::string& table, silkworm::ByteView key) const override;

    Task<std::optional<silkworm::Bytes>> get_both_range(
        const std::string& table,
        silkworm::ByteView key,
        silkworm::ByteView subkey) const override;

    Task<void> walk(
        const std::string& table,
        silkworm::ByteView start_key,
        uint32_t fixed_bits,
        core::rawdb::Walker w) const override;
    Task<void> walk_worker(
        const std::string& table,
        silkworm::ByteView start_key,
        uint32_t fixed_bits,
        core::rawdb::Worker w,
        uint32_t max_size) const override;

    Task<void> for_prefix(
        const std::string& table,
        silkworm::ByteView prefix,
        core::rawdb::Walker w) const override;

  private:
    BlockNumberOrHash block_id_;
    Transaction& txn_;
    kv::StateCache& state_cache_;
    TransactionDatabase txn_database_;
};

}  // namespace silkworm::rpc::ethdb::kv
