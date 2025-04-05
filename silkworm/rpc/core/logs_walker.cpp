// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "logs_walker.hpp"

#include <string>

#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/kv/txn_num.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/receipts.hpp>
#include <silkworm/rpc/ethdb/cbor.hpp>

namespace silkworm::rpc {

using namespace db::chain;

Task<std::pair<BlockNum, BlockNum>> LogsWalker::get_block_nums(const Filter& filter) {
    BlockNum start{}, end{};

    if (filter.block_hash.has_value()) {
        auto block_hash_bytes = silkworm::from_hex(filter.block_hash.value());
        if (!block_hash_bytes.has_value()) {
            start = end = std::numeric_limits<uint64_t>::max();
        } else {
            auto block_hash = silkworm::to_bytes32(block_hash_bytes.value());
            auto block_num = co_await block_reader_.get_block_num(block_hash);
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

Task<void> LogsWalker::get_logs(BlockNum start,
                                BlockNum end,
                                const FilterAddresses& addresses,
                                const FilterTopics& topics,
                                const LogFilterOptions& options,
                                bool ascending_order,
                                std::vector<Log>& logs) {
    db::txn::TxNum min_tx_num{0};
    if (start > 0) {
        min_tx_num = co_await db::txn::min_tx_num(tx_, start, canonical_body_for_storage_provider_);
    }
    auto max_tx_num = co_await db::txn::max_tx_num(tx_, end, canonical_body_for_storage_provider_) + 1;

    SILK_DEBUG << "start: " << start << ", end: " << end << ", min_tx_num: " << min_tx_num << ", max_tx_num: " << max_tx_num;

    const auto from_timestamp = static_cast<db::kv::api::Timestamp>(min_tx_num);
    const auto to_timestamp = static_cast<db::kv::api::Timestamp>(max_tx_num);

    const auto chain_storage{tx_.make_storage()};

    db::kv::api::PaginatedStream<db::kv::api::Timestamp> paginated_stream;
    if (!topics.empty()) {
        for (auto sub_topic = topics.begin(); sub_topic < topics.end(); ++sub_topic) {
            if (sub_topic->empty()) {
                continue;
            }

            db::kv::api::PaginatedStream<db::kv::api::Timestamp> union_stream;
            for (auto it = sub_topic->begin(); it < sub_topic->end(); ++it) {
                SILK_DEBUG << "topic: " << to_hex(*it) << ", from_timestamp: " << from_timestamp << ", to_timestamp: "
                           << to_timestamp;

                db::kv::api::IndexRangeRequest query = {
                    .table = std::string{db::table::kLogTopicIdx},
                    .key = db::topic_domain_key(*it),
                    .from_timestamp = from_timestamp,
                    .to_timestamp = to_timestamp,
                    .ascending_order = ascending_order};
                auto paginated_result = co_await tx_.index_range(std::move(query));
                union_stream = db::kv::api::set_union(std::move(union_stream), co_await paginated_result.begin());
            }
            if (!paginated_stream) {
                paginated_stream = std::move(union_stream);
                continue;
            }
            paginated_stream = db::kv::api::set_intersection(std::move(paginated_stream), std::move(union_stream));
        }
    }
    if (!addresses.empty()) {
        db::kv::api::PaginatedStream<db::kv::api::Timestamp> union_stream;
        for (auto it = addresses.begin(); it < addresses.end(); ++it) {
            SILK_DEBUG << "address: " << *it << ", from_timestamp: " << from_timestamp << ", to_timestamp: " << to_timestamp;

            db::kv::api::IndexRangeRequest query = {
                .table = std::string{db::table::kLogAddrIdx},
                .key = db::account_domain_key(*it),
                .from_timestamp = from_timestamp,
                .to_timestamp = to_timestamp,
                .ascending_order = ascending_order};
            auto paginated_result = co_await tx_.index_range(std::move(query));
            union_stream = db::kv::api::set_union(std::move(union_stream), co_await paginated_result.begin());
        }

        if (paginated_stream) {
            paginated_stream = db::kv::api::set_intersection(std::move(paginated_stream), std::move(union_stream));
        } else {
            paginated_stream = std::move(union_stream);
        }
    }

    if (!paginated_stream) {
        paginated_stream = db::kv::api::make_range_stream(from_timestamp, to_timestamp);
    }

    Receipts receipts;
    uint64_t block_count{0};
    uint64_t log_count{0};
    Logs filtered_chunk_logs;

    uint64_t block_timestamp{0};
    silkworm::Block block;
    std::optional<BlockHeader> header;
    auto itr = db::txn::make_txn_nums_stream(std::move(paginated_stream), ascending_order, tx_, canonical_body_for_storage_provider_);
    while (const auto tnx_nums = co_await itr->next()) {
        SILK_DEBUG << " blockNum: " << tnx_nums->block_num << " txn_id: " << tnx_nums->txn_id << " txn_index: " << (tnx_nums->txn_index ? std::to_string(*(tnx_nums->txn_index)) : "nullopt");

        if (tnx_nums->block_changed) {
            receipts.clear();

            header = co_await chain_storage->read_canonical_header(tnx_nums->block_num);
            if (!header) {
                SILK_DEBUG << "Not found header no.  " << tnx_nums->block_num;
                break;
            }
            block_timestamp = header->timestamp;
            block.header = std::move(*header);
        }

        if (!tnx_nums->txn_index) {
            continue;
        }

        SILKWORM_ASSERT(header);

        const auto transaction = co_await chain_storage->read_transaction_by_idx_in_block(tnx_nums->block_num, tnx_nums->txn_index.value());
        if (!transaction) {
            SILK_DEBUG << "No transaction found in block " << tnx_nums->block_num << " for index " << tnx_nums->txn_index.value();
            continue;
        }

        auto receipt = co_await core::get_receipt(tx_, block, tnx_nums->txn_id, tnx_nums->txn_index.value(), *transaction, *chain_storage, workers_);
        if (!receipt) {
            SILK_DEBUG << "No receipt found in block " << tnx_nums->block_num << " for index " << tnx_nums->txn_index.value();
            continue;
        }

        SILK_DEBUG << "Got transaction: block_num: " << tnx_nums->block_num << ", txn_index: " << tnx_nums->txn_index.value();

        // ERIGON3 compatibility: erigon_getLatestLogs overwrites log index
        if (options.overwrite_log_index) {
            uint32_t log_index{0};
            for (auto& log : receipt->logs) {
                log.index = log_index++;
            }
        }

        filtered_chunk_logs.clear();
        filter_logs(receipt->logs, addresses, topics, filtered_chunk_logs, options.log_count == 0 ? 0 : options.log_count - log_count);
        SILK_DEBUG << "filtered #logs: " << filtered_chunk_logs.size();
        if (filtered_chunk_logs.empty()) {
            continue;
        }
        ++block_count;
        log_count += filtered_chunk_logs.size();
        SILK_DEBUG << "log_count: " << log_count;

        if (options.add_timestamp) {
            for (auto& curr_log : filtered_chunk_logs) {
                curr_log.timestamp = block_timestamp;
            }
        }
        logs.insert(logs.end(), filtered_chunk_logs.begin(), filtered_chunk_logs.end());

        if (options.log_count != 0 && options.log_count <= log_count) {
            break;
        }
        if (options.block_count != 0 && options.block_count == block_count) {
            break;
        }
    }
    SILK_DEBUG << "resulting logs size: " << logs.size();

    co_return;
}

void LogsWalker::filter_logs(const std::vector<Log>& logs, const FilterAddresses& addresses, const FilterTopics& topics, std::vector<Log>& filtered_logs,
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
