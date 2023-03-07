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

#include <string>
#include <utility>

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/types/block.hpp>

namespace silkrpc::core {

constexpr const char* kEarliestBlockId{"earliest"};
constexpr const char* kLatestBlockId{"latest"};
constexpr const char* kPendingBlockId{"pending"};
constexpr const char* kFinalizedBlockId{"finalized"};
constexpr const char* kSafeBlockId{"safe"};
constexpr const char* kLatestExecutedBlockId{"latestExecuted"};

constexpr uint64_t kEarliestBlockNumber{0ul};


boost::asio::awaitable<bool> is_latest_block_number(uint64_t block_number, const core::rawdb::DatabaseReader& db_reader);

boost::asio::awaitable<uint64_t> get_block_number_by_tag(const std::string& block_id, const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<std::pair<uint64_t, bool>> get_block_number(const std::string& block_id, const core::rawdb::DatabaseReader& reader, bool latest_is_required);

boost::asio::awaitable<uint64_t> get_block_number(const std::string& block_id, const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<uint64_t> get_current_block_number(const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<uint64_t> get_highest_block_number(const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<uint64_t> get_latest_block_number(const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<uint64_t> get_latest_executed_block_number(const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<uint64_t> get_forkchoice_finalized_block_number(const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<uint64_t> get_forkchoice_safe_block_number(const core::rawdb::DatabaseReader& reader);

boost::asio::awaitable<bool> is_latest_block_number(const BlockNumberOrHash& bnoh, const core::rawdb::DatabaseReader& reader);

}  // namespace silkrpc::core

