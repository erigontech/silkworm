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

#include <functional>
#include <istream>
#include <stdexcept>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <evmc/evmc.hpp>
#include <roaring/roaring.hh>

#include <silkworm/buildinfo.h>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/log_cbor.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>

using Roaring = roaring::Roaring;
using namespace silkworm;
using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;
using namespace silkworm::cmd::common;

enum class TargetIndex {
    kLogAddress,
    kLogTopic,
    kBoth
};

struct Settings {
    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    BlockNum block_from{0};
    std::optional<BlockNum> block_to;
    std::optional<evmc::address> address;
    std::optional<evmc::bytes32> topic;
    TargetIndex index{TargetIndex::kBoth};
    log::Settings log_settings;
};

Settings parse_cli_settings(int argc, char* argv[]) {
    CLI::App cli{"Check Transaction Logs => Log Indexes mapping in database"};

    Settings settings;
    try {
        cli.add_option("--chaindata", settings.chaindata, "Path to a database populated by Silkworm")
            ->capture_default_str()
            ->check(CLI::ExistingDirectory);
        cli.add_option("--from", settings.block_from, "First block number to process (inclusive)")
            ->capture_default_str()
            ->check(CLI::NonNegativeNumber);
        cli.add_option("--to", settings.block_to, "Last block number to process (inclusive)")
            ->capture_default_str()
            ->check(CLI::NonNegativeNumber);
        cli.add_option("--address", [&settings](const CLI::results_t& results) {
               settings.address = hex_to_address(results[0]);
               return true;
           })
            ->description("Target account address to match (optional)")
            ->capture_default_str();
        cli.add_option("--topic", [&settings](const CLI::results_t& results) {
               const auto topic_bytes{from_hex(results[0])};
               if (!topic_bytes) {
                   SILK_CRIT << "Invalid input for --topic option: " << results[0];
                   return false;
               }
               settings.topic = to_bytes32(*topic_bytes);
               return true;
           })
            ->description("Target topic to match (optional)")
            ->capture_default_str();
        std::map<std::string, TargetIndex> check_type_mapping{
            {"address", TargetIndex::kLogAddress},
            {"topic", TargetIndex::kLogTopic},
            {"both", TargetIndex::kBoth},
        };
        cli.add_option("--index", settings.index, "Target index to check consistency for (optional)")
            ->capture_default_str()
            ->check(CLI::Range(TargetIndex::kLogAddress, TargetIndex::kBoth))
            ->transform(CLI::Transformer(check_type_mapping, CLI::ignore_case))
            ->default_val(settings.index);

        log::Settings log_settings{};
        add_logging_options(cli, log_settings);

        cli.parse(argc, argv);
    } catch (const CLI::ParseError& pe) {
        cli.exit(pe);
        throw;
    }

    return settings;
}

std::string block_num_range_str(const Settings& settings) {
    std::stringstream stream;
    log::prepare_for_logging(stream);
    stream << "[" << settings.block_from << ", ";
    if (settings.block_to) {
        stream << *settings.block_to;
    } else {
        stream << "latest";
    }
    stream << "]";
    return stream.str();
}

void trace(const Log& log) {
    SILK_TRACE << "address: " << log.address << " topics: " << log.topics.size();
    int i{0};
    for (const auto& t : log.topics) {
        SILK_TRACE << "topic[" << i << "]: " << to_hex(t);
        ++i;
    }
}

void check_address_index(BlockNum block_num, const evmc::address& log_address, ROCursor* log_address_cursor) {
    // Transaction log address must be present in LogAddressIndex table
    const auto log_address_key{db::log_address_key(log_address, block_num)};
    const auto log_address_data{log_address_cursor->lower_bound(to_slice(log_address_key), false)};
    ensure(log_address_data.done, [&]() { return "LogAddressIndex does not contain key " + to_hex(log_address_key); });

    const auto [address_view, address_upper_bound_block] = split_log_address_key(log_address_data.key);
    const auto& address_view_ref = address_view;
    ensure(to_hex(address_view) == to_hex(log_address.bytes), [&]() { return "address mismatch in LogAddressIndex table: " + to_hex(address_view_ref); });
    ensure(address_upper_bound_block >= block_num, [&]() { return "upper bound mismatch in LogAddressIndex table: " + to_hex(address_view_ref); });

    // Retrieved chunk of the address roaring bitmap must contain the transaction log block
    const auto& log_address_value{log_address_data.value};
    const auto address_bitmap_chunk{bitmap::parse32(log_address_value)};
    ensure(address_bitmap_chunk.contains(static_cast<uint32_t>(block_num)),
           [&]() { return "address bitmap chunk " + address_bitmap_chunk.toString() + " does not contain block " + std::to_string(block_num); });
}

void check_topic_index(BlockNum block_num, const evmc::bytes32& log_topic, ROCursor* log_topic_cursor) {
    // Each transaction log topic must be present in LogTopicIndex table
    const auto log_topic_key{db::log_topic_key(log_topic, block_num)};
    const auto log_topic_data{log_topic_cursor->lower_bound(to_slice(log_topic_key), false)};
    ensure(log_topic_data.done, [&]() { return "LogTopicIndex does not contain key " + to_hex(log_topic_key); });

    const auto [topic_view, topic_upper_bound_block] = split_log_topic_key(log_topic_data.key);
    const auto& topic_view_ref = topic_view;
    ensure(to_hex(topic_view) == to_hex(log_topic.bytes), [&]() { return "topic mismatch in LogTopicIndex table: " + to_hex(topic_view_ref); });
    ensure(topic_upper_bound_block >= block_num, [&]() { return "upper bound mismatch in LogTopicIndex table: " + to_hex(topic_view_ref); });

    // Retrieved chunk of the topic roaring bitmap must contain the transaction log block
    const auto& log_topic_value{log_topic_data.value};
    const auto topic_bitmap_chunk{bitmap::parse32(log_topic_value)};
    ensure(topic_bitmap_chunk.contains(static_cast<uint32_t>(block_num)),
           [&]() { return "topic bitmap chunk " + topic_bitmap_chunk.toString() + " does not contain block " + std::to_string(block_num); });
}

int main(int argc, char* argv[]) {
    SignalHandler::init();

    try {
        // Parse command-line options and initialize settings
        Settings settings{parse_cli_settings(argc, argv)};
        log::init(settings.log_settings);

        ensure(!settings.block_to || *settings.block_to >= settings.block_from, "Invalid input: block_from is greater than block_to");

        const auto node_name{get_node_name_from_build_info(silkworm_get_buildinfo())};
        SILK_INFO << "Build info: " << node_name;

        // Set up the measurement counters and data structures
        BlockNum reached_block_num{0};
        uint64_t processed_block_nums{0};
        uint64_t processed_transaction_count{0};
        uint64_t processed_logs_count{0};
        uint64_t processed_addresses_count{0};
        uint64_t processed_topics_count{0};

        // Open the database and create a read-only txn
        auto data_dir{DataDirectory::from_chaindata(settings.chaindata)};
        data_dir.deploy();
        EnvConfig db_config{data_dir.chaindata().path().string()};
        auto env{open_env(db_config)};
        ROTxnManaged txn{env};

        auto logs_cursor = txn.ro_cursor(table::kLogs);
        auto log_address_cursor = txn.ro_cursor(table::kLogAddressIndex);
        auto log_topic_cursor = txn.ro_cursor(table::kLogTopicIndex);

        SILK_INFO << "Check transaction log indices for blocks " << block_num_range_str(settings) << " ...";

        // Start from the key having block_from as key prefix and iterate over TransactionLog on all blocks up to block_to
        auto start_key_prefix{block_key(settings.block_from)};
        auto logs_data{logs_cursor->lower_bound(to_slice(start_key_prefix), false)};
        ensure(logs_data.done, "Nonexistent block range: block_from not found");
        while (logs_data.done) {
            const auto [block_num, tx_id] = split_log_key(logs_data.key);
            if (settings.block_to && block_num > *settings.block_to) {
                SILK_INFO << "Target block " << *settings.block_to << " reached";
                break;
            }
            if (reached_block_num != block_num) {
                reached_block_num = block_num;
                ++processed_block_nums;
            }

            std::vector<Log> transaction_logs;

            // Decode CBOR value content with *stateful* consumer to build address and topic bitmaps
            ByteView cbor_encoded_logs{static_cast<uint8_t*>(logs_data.value.data()), logs_data.value.length()};
            const bool cbor_success{cbor_decode(cbor_encoded_logs, transaction_logs)};
            ensure(cbor_success, "unexpected CBOR: wrong number of logs");

            // Check that every transaction log is mapped into LogAddressIndex and LogTopicIndex tables (if required)
            for (const auto& log : transaction_logs) {
                trace(log);

                if (settings.index != TargetIndex::kLogTopic) {
                    if (log.address == settings.address) {
                        SILK_INFO << "block " << block_num << " tx " << tx_id << " generated log for " << log.address;
                    }
                    check_address_index(block_num, log.address, log_address_cursor.get());
                    ++processed_addresses_count;
                }

                if (settings.index != TargetIndex::kLogAddress) {
                    for (const auto& topic : log.topics) {
                        if (topic == settings.topic) {
                            SILK_INFO << "block " << block_num << " tx " << tx_id << " generated topic " << to_hex(topic.bytes);
                        }
                        check_topic_index(block_num, topic, log_topic_cursor.get());
                    }
                    processed_topics_count += log.topics.size();
                }
            }
            processed_logs_count += transaction_logs.size();

            ++processed_transaction_count;
            if (processed_transaction_count % 100'000 == 0) {
                SILK_INFO << "Scanned transactions " << processed_transaction_count << " processed logs " << processed_logs_count;
            }

            if (SignalHandler::signalled()) {
                break;
            }

            // Move to next transaction
            logs_data = logs_cursor->to_next(false);
        }
        SILK_INFO
            << "LogBuilder: processed blocks " << processed_block_nums
            << " transactions " << processed_transaction_count
            << " logs " << processed_logs_count
            << " addresses " << processed_addresses_count
            << " topics " << processed_topics_count;

        SILK_INFO << "Check " << (SignalHandler::signalled() ? "aborted" : "completed");

    } catch (const std::exception& ex) {
        SILK_ERROR << ex.what();
        return -1;
    }

    return 0;
}
