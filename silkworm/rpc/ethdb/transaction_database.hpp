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

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>

namespace silkworm::rpc::ethdb {

class TransactionDatabase : public core::rawdb::DatabaseReader {
  public:
    explicit TransactionDatabase(Transaction& tx) : tx_(tx) {}

    TransactionDatabase(const TransactionDatabase&) = delete;
    TransactionDatabase& operator=(const TransactionDatabase&) = delete;

    [[nodiscard]] Task<KeyValue> get(const std::string& table, ByteView key) const override;

    [[nodiscard]] Task<silkworm::Bytes> get_one(const std::string& table, ByteView key) const override;

    [[nodiscard]] Task<std::optional<Bytes>> get_both_range(const std::string& table, ByteView key, ByteView subkey) const override;

    [[nodiscard]] Task<void> walk(const std::string& table, ByteView start_key, uint32_t fixed_bits, core::rawdb::Walker w) const override;
    [[nodiscard]] Task<void> walk_worker(const std::string& table, ByteView start_key, uint32_t fixed_bits, core::rawdb::Worker w) const override;

    [[nodiscard]] Task<void> for_prefix(const std::string& table, ByteView prefix, core::rawdb::Walker w) const override;

    Transaction& get_tx() { return tx_; }

  private:
    Transaction& tx_;
};

}  // namespace silkworm::rpc::ethdb
