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

#include <vector>

#include <boost/asio/awaitable.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>
#include <silkworm/rpc/types/filter.hpp>
#include <silkworm/rpc/types/log.hpp>

namespace silkworm::rpc {

using boost::asio::awaitable;

class LogsWalker {
  public:
    explicit LogsWalker(ethbackend::BackEnd* backend, BlockCache& block_cache, ethdb::TransactionDatabase& tx_database)
        : backend_(backend), block_cache_(block_cache), tx_database_(tx_database) {}

    LogsWalker(const LogsWalker&) = delete;
    LogsWalker& operator=(const LogsWalker&) = delete;

    Task<std::pair<uint64_t, uint64_t>> get_block_numbers(const Filter& filter);
    Task<void> get_logs(std::uint64_t start, std::uint64_t end,
                        const FilterAddresses& addresses, const FilterTopics& topics, std::vector<Log>& logs) {
        LogFilterOptions options;
        co_return co_await get_logs(start, end, addresses, topics, options, true, logs);
    }
    Task<void> get_logs(std::uint64_t start, std::uint64_t end,
                        const FilterAddresses& addresses, const FilterTopics& topics,
                        const LogFilterOptions& options, bool desc_order,
                        std::vector<Log>& logs);

  private:
    void filter_logs(const std::vector<Log>&& logs, const FilterAddresses& addresses, const FilterTopics& topics, std::vector<Log>& filtered_logs, size_t max_logs);

    ethbackend::BackEnd* backend_;
    BlockCache& block_cache_;
    ethdb::TransactionDatabase& tx_database_;
};

}  // namespace silkworm::rpc
