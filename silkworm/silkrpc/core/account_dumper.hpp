/*
   Copyright 2021 The Silkrpc Authors

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
#include <map>
#include <vector>

#include <nlohmann/json.hpp>
#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#include <evmc/evmc.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>

#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/dump_account.hpp>

namespace silkrpc {

class AccountDumper {
public:
    explicit AccountDumper(silkrpc::ethdb::Transaction& transaction) : transaction_(transaction) {}

    AccountDumper(const AccountDumper&) = delete;
    AccountDumper& operator=(const AccountDumper&) = delete;

    boost::asio::awaitable<DumpAccounts> dump_accounts(BlockCache& cache, const BlockNumberOrHash& bnoh, const evmc::address& start_address, int16_t max_result,
                                                bool exclude_code, bool exclude_storage);

private:
    boost::asio::awaitable<void> load_accounts(ethdb::TransactionDatabase& tx_database, const std::vector<silkrpc::KeyValue>& collected_data, DumpAccounts& dump_accounts, bool exclude_code);
    boost::asio::awaitable<void> load_storage(uint64_t block_number, DumpAccounts& dump_accounts);

    silkrpc::ethdb::Transaction& transaction_;
};

} // namespace silkrpc

