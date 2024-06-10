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
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/blocks.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/rawdb/chain.hpp>
#include <silkworm/rpc/ethdb/bitmap.hpp>
#include <silkworm/rpc/ethdb/cbor.hpp>
#include <silkworm/rpc/ethdb/walk.hpp>

namespace silkworm::rpc {

Task<std::pair<uint64_t, uint64_t>> LogsWalker::get_block_numbers(const Filter& filter) {
    uint64_t start{}, end{};
    if (filter.block_hash.has_value()) {
        auto block_hash_bytes = silkworm::from_hex(filter.block_hash.value());
        if (!block_hash_bytes.has_value()) {
            start = end = std::numeric_limits<uint64_t>::max();
        } else {
            auto block_hash = silkworm::to_bytes32(block_hash_bytes.value());
            auto block_number = co_await core::rawdb::read_header_number(tx_, block_hash);
            start = end = block_number;
        }
    } else {
        uint64_t last_block_number = std::numeric_limits<uint64_t>::max();
        if (filter.from_block.has_value()) {
            start = co_await core::get_block_number(filter.from_block.value(), tx_);
        } else {
            last_block_number = co_await core::get_latest_block_number(tx_);
            start = last_block_number;
        }
        if (filter.to_block.has_value()) {
            end = co_await core::get_block_number(filter.to_block.value(), tx_);
        } else {
            if (last_block_number == std::numeric_limits<uint64_t>::max()) {
                last_block_number = co_await core::get_latest_block_number(tx_);
            }
            end = last_block_number;
        }
    }
    co_return std::make_pair(start, end);
}

Task<void> LogsWalker::get_logs(std::uint64_t start, std::uint64_t end,
                                const FilterAddresses& addresses, const FilterTopics& topics, const LogFilterOptions& options, bool desc_order, std::vector<Log>& logs) {
    SILK_DEBUG << "start block: " << start << " end block: " << end;

    const auto chain_storage{tx_.create_storage(backend_)};
    roaring::Roaring block_numbers;
    block_numbers.addRange(start, end + 1);  // [min, max)

    if (!topics.empty()) {
        auto topics_bitmap = co_await ethdb::bitmap::from_topics(tx_, db::table::kLogTopicIndexName, topics, start, end);
        SILK_TRACE << "topics_bitmap: " << topics_bitmap.toString();
        if (topics_bitmap.isEmpty()) {
            block_numbers = topics_bitmap;
        } else {
            block_numbers &= topics_bitmap;
        }
    }

    if (!addresses.empty()) {
        auto addresses_bitmap = co_await ethdb::bitmap::from_addresses(tx_, db::table::kLogAddressIndexName, addresses, start, end);
        if (addresses_bitmap.isEmpty()) {
            block_numbers = addresses_bitmap;
        } else {
            block_numbers &= addresses_bitmap;
        }
    }
    SILK_DEBUG << "block_numbers.cardinality(): " << block_numbers.cardinality();
    SILK_TRACE << "block_numbers: " << block_numbers.toString();

    if (block_numbers.cardinality() == 0) {
        co_return;
    }

    std::vector<BlockNum> matching_block_numbers;
    matching_block_numbers.reserve(block_numbers.cardinality());
    for (const auto& block_to_match : block_numbers) {
        matching_block_numbers.push_back(block_to_match);
    }
    if (desc_order) {
        std::reverse(matching_block_numbers.begin(), matching_block_numbers.end());
    }

    std::uint64_t log_count{0};
    std::uint64_t block_count{0};

    Logs chunk_logs;
    Logs filtered_chunk_logs;
    Logs filtered_block_logs;
    chunk_logs.reserve(512);
    filtered_chunk_logs.reserve(64);
    filtered_block_logs.reserve(256);

    for (const auto& block_to_match : matching_block_numbers) {
        uint32_t log_index{0};

        filtered_block_logs.clear();
        const auto block_key = silkworm::db::block_key(block_to_match);
        SILK_DEBUG << "block_to_match: " << block_to_match << " block_key: " << silkworm::to_hex(block_key);
        co_await for_prefix(tx_, db::table::kLogsName, block_key, [&](const silkworm::Bytes& k, const silkworm::Bytes& v) {
            chunk_logs.clear();
            const bool decoding_ok{cbor_decode(v, chunk_logs)};
            if (!decoding_ok) {
                return false;
            }
            for (auto& log : chunk_logs) {
                log.index = log_index++;
            }
            SILK_DEBUG << "chunk_logs.size(): " << chunk_logs.size();

            filtered_chunk_logs.clear();
            filter_logs(std::move(chunk_logs), addresses, topics, filtered_chunk_logs, options.log_count == 0 ? 0 : options.log_count - log_count);

            if (!filtered_chunk_logs.empty()) {
                const auto tx_index = boost::endian::load_big_u32(&k[sizeof(uint64_t)]);
                SILK_TRACE << "Transaction index: " << tx_index;
                for (auto& log : filtered_chunk_logs) {
                    log.tx_index = tx_index;
                }
                log_count += filtered_chunk_logs.size();
                SILK_TRACE << "log_count: " << log_count;
                filtered_block_logs.insert(filtered_block_logs.end(), filtered_chunk_logs.rbegin(), filtered_chunk_logs.rend());
            }
            return options.log_count == 0 || options.log_count > log_count;
        });
        SILK_DEBUG << "filtered_block_logs.size(): " << filtered_block_logs.size();

        if (!filtered_block_logs.empty()) {
            const auto block_with_hash = co_await core::read_block_by_number(block_cache_, *chain_storage, block_to_match);
            if (!block_with_hash) {
                throw std::invalid_argument("read_block_by_number: block not found " + std::to_string(block_to_match));
            }
            SILK_TRACE << "assigning block_hash: " << silkworm::to_hex(block_with_hash->hash);
            for (auto& log : filtered_block_logs) {
                const auto tx_hash{block_with_hash->block.transactions[log.tx_index].hash()};
                log.block_number = block_to_match;
                log.block_hash = block_with_hash->hash;
                log.tx_hash = silkworm::to_bytes32({tx_hash.bytes, silkworm::kHashLength});
                if (options.add_timestamp) {
                    log.timestamp = block_with_hash->block.header.timestamp;
                }
            }
            logs.insert(logs.end(), filtered_block_logs.begin(), filtered_block_logs.end());
        }
        block_count++;
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
            for (size_t i{0}; i < topics.size(); i++) {
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
