/*
   Copyright 2020 The Silkrpc Authors

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
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>

namespace silkrpc::ethdb {

class TransactionDatabase : public core::rawdb::DatabaseReader {
public:
    explicit TransactionDatabase(Transaction& tx) : tx_(tx) {}

    TransactionDatabase(const TransactionDatabase&) = delete;
    TransactionDatabase& operator=(const TransactionDatabase&) = delete;

    boost::asio::awaitable<KeyValue> get(const std::string& table, const silkworm::ByteView& key) const override;

    boost::asio::awaitable<silkworm::Bytes> get_one(const std::string& table, const silkworm::ByteView& key) const override;

    boost::asio::awaitable<std::optional<silkworm::Bytes>> get_both_range(const std::string& table, const silkworm::ByteView& key, const silkworm::ByteView& subkey) const override;

    boost::asio::awaitable<void> walk(const std::string& table, const silkworm::ByteView& start_key, uint32_t fixed_bits, core::rawdb::Walker w) const override;

    boost::asio::awaitable<void> for_prefix(const std::string& table, const silkworm::ByteView& prefix, core::rawdb::Walker w) const override;

private:
    Transaction& tx_;
};

} // namespace silkrpc::ethdb

