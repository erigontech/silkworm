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

#include "logs_walker.hpp"

#include <string>

#include <boost/endian/conversion.hpp>

#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/chain/chain.hpp>
#include <silkworm/db/kv/txn_num.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/receipts.hpp>
#include <silkworm/rpc/ethdb/bitmap.hpp>
#include <silkworm/rpc/ethdb/cbor.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/ethdb/walk.hpp>

namespace silkworm::rpc {

using namespace db::chain;

Task<std::pair<uint64_t, uint64_t>> LogsWalker::get_block_nums(const Filter& filter) {
    uint64_t start{}, end{};

    if (filter.block_hash.has_value()) {
        auto block_hash_bytes = silkworm::from_hex(filter.block_hash.value());
        if (!block_hash_bytes.has_value()) {
            start = end = std::numeric_limits<uint64_t>::max();
        } else {
            auto block_hash = silkworm::to_bytes32(block_hash_bytes.value());
            auto block_num = co_await read_header_number(tx_, block_hash);
            start = end = block_num;
        }
    } else {
        uint64_t last_block_num = std::numeric_limits<uint64_t>::max();
        if (filter.from_block.has_value()) {
            start = co_await block_reader_.get_block_num(filter.from_block.value());
        } else {
            last_block_num = co_await block_reader_.get_latest_block_num();
            start = last_block_num;
        }
        if (filter.to_block.has_value()) {
            end = co_await block_reader_.get_block_num(filter.to_block.value());
        } else {
            if (last_block_num == std::numeric_limits<uint64_t>::max()) {
                last_block_num = co_await block_reader_.get_latest_block_num();
            }
            end = last_block_num;
        }
    }
    co_return std::make_pair(start, end);
}

class RangePaginatedIterator : public db::kv::api::PaginatedIterator<db::kv::api::Timestamp> {
  public:
    RangePaginatedIterator(db::kv::api::Timestamp from, db::kv::api::Timestamp to)
        : current_(from), to_(to) {}

    Task<bool> has_next() override {
        co_return current_ <= to_;
    }

    Task<std::optional<db::kv::api::Timestamp>> next() override {
        if (current_ > to_) {
            co_return std::nullopt;
        }
        co_return current_++;
    }

  private:
    db::kv::api::Timestamp current_;
    db::kv::api::Timestamp to_;
};

db::kv::api::PaginatedStream<db::kv::api::Timestamp> create_range_stream(db::kv::api::Timestamp from, db::kv::api::Timestamp to) {
    return std::make_unique<RangePaginatedIterator>(from, to);
}

struct BlockInfo {
    BlockNum block_num{0};
    BlockDetails details;
};

Task<void> LogsWalker::get_logs(std::uint64_t start,
                                std::uint64_t end,
                                const FilterAddresses& addresses,
                                const FilterTopics& topics,
                                const LogFilterOptions& options,
                                bool asc_order,
                                std::vector<Log>& logs) {
    auto provider = ethdb::kv::canonical_body_for_storage_provider(&backend_);

    db::txn::TxNum min_tx_num{0};
    if (start > 0) {
        min_tx_num = co_await db::txn::min_tx_num(tx_, start, provider);
    }
    auto max_tx_num = co_await db::txn::max_tx_num(tx_, end, provider) + 1;

    SILK_LOG << "start: " << start << ", end: " << end << ", min_tx_num: " << min_tx_num << ", max_tx_num: " << max_tx_num;

    const auto from_timestamp = static_cast<db::kv::api::Timestamp>(min_tx_num);
    const auto to_timestamp = static_cast<db::kv::api::Timestamp>(max_tx_num);

    const auto chain_storage{tx_.create_storage()};

    db::kv::api::PaginatedStream<db::kv::api::Timestamp> union_itr;
    if (!topics.empty()) {
        for (auto sub_topic = topics.begin(); sub_topic < topics.end(); ++sub_topic) {
            for (auto it = sub_topic->begin(); it < sub_topic->end(); ++it) {
                SILK_LOG << "topic: " << to_hex(*it) << ", from_timestamp: " << from_timestamp << ", to_timestamp: "
                         << to_timestamp;

                db::kv::api::IndexRangeQuery query = {.table = db::table::kLogTopicIdx,
                        .key = db::topic_domain_key(*it),
                        .from_timestamp = from_timestamp,
                        .to_timestamp = to_timestamp,
                        .ascending_order = asc_order};
                auto paginated_result = co_await tx_.index_range(std::move(query));
                union_itr = db::kv::api::set_union(std::move(union_itr), co_await paginated_result.begin());
            }
        }
    }
    if (!addresses.empty()) {
        for (auto it = addresses.begin(); it < addresses.end(); ++it) {
            SILK_LOG << "address: " << *it << ", from_timestamp: " << from_timestamp << ", to_timestamp: "
                     << to_timestamp;

            db::kv::api::IndexRangeQuery query = {.table = db::table::kLogAddrIdx,
                                                  .key = db::account_domain_key(*it),
                                                  .from_timestamp = from_timestamp,
                                                  .to_timestamp = to_timestamp,
                                                  .ascending_order = asc_order};
            auto paginated_result = co_await tx_.index_range(std::move(query));
            union_itr = db::kv::api::set_union(std::move(union_itr), co_await paginated_result.begin());
        }
    }
    if (!union_itr) {
        union_itr = db::kv::api::set_union(std::move(union_itr), create_range_stream(from_timestamp, to_timestamp));
    }

    std::map<std::string, Receipt> receipts;
    std::optional<BlockInfo> block_info;

    uint64_t block_count{0};
    uint64_t log_count{0};
    Logs filtered_chunk_logs;

    while (const auto value = co_await union_itr->next()) {
        const auto txn_id = static_cast<TxnId>(*value);
        const auto block_num_opt = co_await db::txn::block_num_from_tx_num(tx_, txn_id, provider);
        if (!block_num_opt) {
            SILK_LOG << "No block found for txn_id " << txn_id;
            break;
        }
        const auto block_num = block_num_opt.value();
        const auto max_txn_id = co_await db::txn::max_tx_num(tx_, block_num, provider);
        const auto min_txn_id = co_await db::txn::min_tx_num(tx_, block_num, provider);
        const auto txn_index = txn_id > min_txn_id ? txn_id - min_txn_id - 1 : 0;

        SILK_LOG
            << "txn_id: " << txn_id
            << " block_num: " << block_num
            << ", txn_index: " << txn_index
            << ", max_txn_id: " << max_txn_id
            << ", min_txn_id: " << min_txn_id
            << ", final txn: " << (txn_id == max_txn_id);

        if (txn_id == max_txn_id) {
            continue;
        }

        if (block_info && (block_info->block_num != block_num)) {
            block_info.reset();
            receipts.clear();
        }
        if (!block_info) {
            const auto block_with_hash = co_await rpc::core::read_block_by_number(block_cache_, *chain_storage, block_num);
            if (!block_with_hash) {
                SILK_LOG << "Not found block no.  " << block_num;
                break;
            }
            auto rr = co_await core::get_receipts(tx_, *block_with_hash, *chain_storage, workers_);
            SILK_DEBUG << "Read #" << rr.size() << " receipts from block " << block_num;

            std::for_each(rr.begin(), rr.end(), [&receipts](const auto& item) {
                receipts[silkworm::to_hex(item.tx_hash, false)] = std::move(item);
            });

            const Block extended_block{block_with_hash, false};
            const auto block_size = extended_block.get_block_size();
            const BlockDetails block_details{block_size, block_with_hash->hash, block_with_hash->block.header,
                                             block_with_hash->block.transactions.size(), block_with_hash->block.ommers,
                                             block_with_hash->block.withdrawals};
            block_info = BlockInfo{block_with_hash->block.header.number, block_details};
            ++block_count;
        }
        auto transaction = co_await chain_storage->read_transaction_by_idx_in_block(block_num, txn_index);
        if (!transaction) {
            SILK_LOG << "No transaction found in block " << block_num << " for index " << txn_index;
            break;
        }

        SILK_DEBUG << "Got transaction: block_num: " << block_num
                   << ", txn_index: " << txn_index;

        const auto& receipt = receipts.at(silkworm::to_hex(transaction.value().hash(), false));

        SILK_LOG << "#rawLogs: " << receipt.logs.size();
        filtered_chunk_logs.clear();
        filter_logs(std::move(receipt.logs), addresses, topics, filtered_chunk_logs, options.log_count == 0 ? 0 : options.log_count - log_count);
        SILK_LOG << "filtered #logs: " << filtered_chunk_logs.size();

        log_count += filtered_chunk_logs.size();
        SILK_LOG << "log_count: " << log_count;

        logs.insert(logs.end(), filtered_chunk_logs.begin(), filtered_chunk_logs.end());

        if (options.log_count != 0 && options.log_count <= log_count) {
            break;
        }
        if (options.block_count != 0 && options.block_count == block_count) {
            break;
        }
    }
    SILK_LOG << "resulting logs size: " << logs.size();

    co_return;
}

void LogsWalker::filter_logs(const std::vector<Log>&& logs, const FilterAddresses& addresses, const FilterTopics& topics, std::vector<Log>& filtered_logs,
                             size_t max_logs) {
    SILK_DEBUG << "filter_logs: addresses: " << addresses << ", topics: " << topics;
    size_t log_count = 0;
    for (auto& log : logs) {
        SILK_DEBUG << "log: " << log;
        if (!addresses.empty() && std::find(addresses.begin(), addresses.end(), log.address) == addresses.end()) {
            SILK_DEBUG << "skipped log for address: " << log.address;
            continue;
        }
        auto matches = true;
        if (!topics.empty()) {
            if (topics.size() > log.topics.size()) {
                SILK_DEBUG << "#topics: " << topics.size() << " #log.topics: " << log.topics.size();
                continue;
            }
            for (size_t i{0}; i < topics.size(); ++i) {
                SILK_DEBUG << "log.topics[i]: " << to_hex(log.topics[i]);
                auto subtopics = topics[i];
                auto matches_subtopics = subtopics.empty();  // empty rule set == wildcard
                SILK_DEBUG << "matches_subtopics: " << std::boolalpha << matches_subtopics;
                for (auto& topic : subtopics) {
                    SILK_DEBUG << "topic: " << to_hex(topic);
                    if (log.topics[i] == topic) {
                        matches_subtopics = true;
                        SILK_DEBUG << "matches_subtopics: " << std::boolalpha << matches_subtopics;
                        break;
                    }
                }
                if (!matches_subtopics) {
                    SILK_DEBUG << "No subtopic matches";
                    matches = false;
                    break;
                }
            }
        }
        SILK_DEBUG << "matches: " << std::boolalpha << matches;
        if (matches) {
            filtered_logs.push_back(log);
        }
        if (max_logs != 0 && ++log_count >= max_logs) {
            return;
        }
    }
}

}  // namespace silkworm::rpc
