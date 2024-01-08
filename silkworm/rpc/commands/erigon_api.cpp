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

#include "erigon_api.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/binary_search.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/blocks.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/logs_walker.hpp>
#include <silkworm/rpc/core/rawdb/chain.hpp>
#include <silkworm/rpc/core/receipts.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#erigon_cachecheck
Task<void> ErigonRpcApi::handle_erigon_cache_check(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        reply = make_json_content(request, to_quantity(0));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getbalancechangesinblock
Task<void> ErigonRpcApi::handle_erigon_get_balance_changes_in_block(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.empty()) {
        auto error_msg = "invalid erigon_getBalanceChangesInBlock params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);

        co_return;
    }
    const auto block_number_or_hash = params[0].get<BlockNumberOrHash>();

    SILK_DEBUG << "block_number_or_hash: " << block_number_or_hash;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_storage = tx->create_storage(tx_database, backend_);

        auto start = std::chrono::system_clock::now();

        rpc::BlockReader block_reader{tx_database, *chain_storage, *tx};
        rpc::BalanceChanges balance_changes;
        co_await block_reader.read_balance_changes(*block_cache_, block_number_or_hash, balance_changes);

        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        SILK_DEBUG << "balance_changes: elapsed " << elapsed_seconds.count() << " sec";

        nlohmann::json json;
        to_json(json, balance_changes);

        reply = make_json_content(request, json);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getBlockByTimestamp
Task<void> ErigonRpcApi::handle_erigon_get_block_by_timestamp(const nlohmann::json& request, std::string& reply) {
    // Decode request parameters
    const auto& params = request["params"];
    if (params.size() != 2) {
        auto error_msg = "invalid erigon_getBlockByTimestamp params: " + params.dump();
        SILK_ERROR << error_msg;
        make_glaze_json_error(request, 100, error_msg, reply);
        co_return;
    }
    const auto block_timestamp = params[0].get<std::string>();
    const auto full_tx = params[1].get<bool>();
    SILK_DEBUG << "block_timestamp: " << block_timestamp << " full_tx: " << full_tx;

    const std::string::size_type begin = block_timestamp.find_first_not_of(" \"");
    const std::string::size_type end = block_timestamp.find_last_not_of(" \"");
    const auto timestamp = static_cast<uint64_t>(std::stol(block_timestamp.substr(begin, end - begin + 1), nullptr, 0));

    // Open a new remote database transaction (no need to close if code throws before the end)
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_storage = tx->create_storage(tx_database, backend_);

        // Lookup the first and last block headers
        const auto first_header = co_await chain_storage->read_canonical_header(core::kEarliestBlockNumber);
        const auto head_header_hash = co_await core::rawdb::read_head_header_hash(tx_database);
        const auto header_header_block_number = co_await chain_storage->read_block_number(head_header_hash);
        const auto current_header = co_await chain_storage->read_header(*header_header_block_number, head_header_hash);
        const BlockNum current_block_number = current_header->number;

        // Find the lowest block header w/ timestamp greater or equal to provided timestamp
        BlockNum block_number{0};
        if (current_header->timestamp <= timestamp) {
            block_number = current_block_number;
        } else if (first_header->timestamp >= timestamp) {
            block_number = core::kEarliestBlockNumber;
        } else {
            // Good-old binary search to find the lowest block header matching timestamp
            auto matching_block_number = co_await binary_search(current_block_number, [&](uint64_t bn) -> Task<bool> {
                const auto header = co_await chain_storage->read_canonical_header(bn);
                co_return header->timestamp >= timestamp;
            });
            // TODO(canepat) we should try to avoid this block header lookup (just done in search)
            auto matching_header = co_await chain_storage->read_canonical_header(matching_block_number);
            while (matching_header->timestamp > timestamp) {
                const auto header = co_await chain_storage->read_canonical_header(matching_block_number - 1);
                if (!header || header->timestamp < timestamp) {
                    break;
                }
                matching_block_number = matching_block_number - 1;
                matching_header = header;
            }
            block_number = matching_block_number;
        }

        // Lookup and return the matching block
        const auto block_with_hash = co_await core::read_block_by_number(*block_cache_, *chain_storage, block_number);
        if (!block_with_hash) {
            const std::string error_msg = "block not found ";
            SILK_ERROR << "erigon_get_block_by_timestamè: core::read_block_by_number: " << error_msg << request.dump();
            make_glaze_json_error(request, 100, error_msg, reply);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        const auto total_difficulty = co_await chain_storage->read_total_difficulty(block_with_hash->hash, block_number);
        const Block extended_block{block_with_hash, *total_difficulty, full_tx};

        make_glaze_json_content(request, extended_block, reply);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        make_glaze_json_error(request, 100, e.what(), reply);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        make_glaze_json_error(request, 100, "unexpected exception", reply);
    }

    // Close remote database transaction, RAII not available with coroutines
    co_await tx->close();
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getBlockReceiptsByBlockHash
Task<void> ErigonRpcApi::handle_erigon_get_block_receipts_by_block_hash(const nlohmann::json& request, nlohmann::json& reply) {
    auto params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_getBlockReceiptsByBlockHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash);

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_storage{tx->create_storage(tx_database, backend_)};

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (!block_with_hash) {
            const std::string error_msg = "block not found ";
            SILK_ERROR << "erigon_get_block_receipts_by_block_hash: core::read_block_by_hash: " << error_msg << request.dump();
            reply = make_json_content(request, {});
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        auto receipts{co_await core::get_receipts(tx_database, *block_with_hash)};
        SILK_TRACE << "#receipts: " << receipts.size();

        const auto block{block_with_hash->block};
        for (size_t i{0}; i < block.transactions.size(); i++) {
            receipts[i].effective_gas_price = block.transactions[i].effective_gas_price(block.header.base_fee_per_gas.value_or(0));
        }

        reply = make_json_content(request, receipts);
    } catch (const std::invalid_argument& iv) {
        SILK_WARN << "invalid_argument: " << iv.what() << " processing request: " << request.dump();
        reply = make_json_content(request, {});
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getHeaderByHash
Task<void> ErigonRpcApi::handle_erigon_get_header_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_getHeaderByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash);

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_storage = tx->create_storage(tx_database, backend_);

        const auto header{co_await chain_storage->read_header(block_hash)};
        if (!header) {
            reply = make_json_error(request, 100, "block not found");
        } else {
            reply = make_json_content(request, *header);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getHeaderByNumber
Task<void> ErigonRpcApi::handle_erigon_get_header_by_number(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_getHeaderByNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].is_string() ? params[0].get<std::string>() : to_quantity(params[0].get<uint64_t>());
    SILK_DEBUG << "block_id: " << block_id;

    if (block_id == core::kPendingBlockId) {
        // TODO(canepat): add pending block only known to the miner
        auto error_msg = "pending block not implemented in erigon_getHeaderByNumber";
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_storage = tx->create_storage(tx_database, backend_);

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        const auto header{co_await chain_storage->read_canonical_header(block_number)};

        if (!header) {
            reply = make_json_error(request, 100, "block not found");
        } else {
            reply = make_json_content(request, *header);
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getlatestlogs
Task<void> ErigonRpcApi::handle_erigon_get_latest_logs(const nlohmann::json& request, nlohmann::json& reply) {
    if (!request.contains("params")) {
        auto error_msg = "missing value for required argument 0";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    auto params = request["params"];
    if (params.size() > 2) {
        auto error_msg = "too many arguments, want at most 2";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }

    auto filter = params[0].get<Filter>();
    if (filter.block_hash && (filter.from_block || filter.to_block)) {
        auto error_msg = "invalid argument 0: cannot specify both BlockHash and FromBlock/ToBlock, choose one or the other";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, -32602, error_msg);
        co_return;
    }

    LogFilterOptions options{true};
    if (params.size() > 1) {
        options = params[1].get<LogFilterOptions>();
        options.add_timestamp = true;
    }

    if (options.log_count != 0 && options.block_count != 0) {
        auto error_msg = "logs count & block count are ambigious";
        SILK_ERROR << error_msg << request.dump();
        reply = make_json_error(request, -32000, error_msg);
        co_return;
    }

    if (options.log_count == 0 && options.block_count == 0) {
        options.block_count = 1;
    }
    SILK_DEBUG << "filter: {" << filter << "}, options: {" << options << "}";

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        LogsWalker logs_walker(backend_, *block_cache_, tx_database);
        const auto [start, end] = co_await logs_walker.get_block_numbers(filter);
        if (start == end && start == std::numeric_limits<std::uint64_t>::max()) {
            auto error_msg = "invalid eth_getLogs filter block_hash: " + filter.block_hash.value();
            SILK_ERROR << error_msg;
            reply = make_json_error(request, 100, error_msg);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        } else if (end < start) {
            std::ostringstream oss;
            oss << "end (" << end << ") < begin (" << start << ")";
            SILK_ERROR << oss.str();
            reply = make_json_error(request, -32000, oss.str());
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }

        std::vector<Log> logs;
        co_await logs_walker.get_logs(start, end, filter.addresses, filter.topics, options, true, logs);

        reply = make_json_content(request, logs);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_getlogsbyhash
Task<void> ErigonRpcApi::handle_erigon_get_logs_by_hash(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_getLogsByHash params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_hash = params[0].get<evmc::bytes32>();
    SILK_DEBUG << "block_hash: " << silkworm::to_hex(block_hash);

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_storage = tx->create_storage(tx_database, backend_);

        const auto block_with_hash = co_await core::read_block_by_hash(*block_cache_, *chain_storage, block_hash);
        if (!block_with_hash) {
            const std::string error_msg = "block not found ";
            SILK_ERROR << "erigon_get_logs_by_hash: core::read_block_by_hash: " << error_msg << request.dump();
            reply = make_json_error(request, 100, error_msg);
            co_await tx->close();  // RAII not (yet) available with coroutines
            co_return;
        }
        const auto receipts{co_await core::get_receipts(tx_database, *block_with_hash)};
        SILK_DEBUG << "receipts.size(): " << receipts.size();
        std::vector<Logs> logs{};
        logs.reserve(receipts.size());
        for (const auto& receipt : receipts) {
            SILK_DEBUG << "receipt.logs.size(): " << receipt.logs.size();
            logs.push_back(receipt.logs);
        }
        SILK_DEBUG << "logs.size(): " << logs.size();

        reply = make_json_content(request, logs);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_forks
Task<void> ErigonRpcApi::handle_erigon_forks(const nlohmann::json& request, nlohmann::json& reply) {
    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto chain_config{co_await core::rawdb::read_chain_config(tx_database)};
        SILK_DEBUG << "chain config: " << chain_config;

        Forks forks{chain_config};

        reply = make_json_content(request, forks);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_WatchTheBurn
Task<void> ErigonRpcApi::handle_erigon_watch_the_burn(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_watchTheBurn params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();
    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto chain_storage = tx->create_storage(tx_database, backend_);

        const auto chain_config{co_await core::rawdb::read_chain_config(tx_database)};
        SILK_DEBUG << "chain config: " << chain_config;

        Issuance issuance{};  // default is empty: no PoW => no issuance
        if (chain_config.config.count("ethash") != 0) {
            const auto block_number = co_await core::get_block_number(block_id, tx_database);
            const auto block_with_hash{co_await core::read_block_by_number(*block_cache_, *chain_storage, block_number)};
            if (!block_with_hash) {
                const std::string error_msg = "block not found ";
                SILK_ERROR << "erigon_watch_the_burn: core::read_block_by_number: " << error_msg << request.dump();
                reply = make_json_error(request, 100, error_msg);
                co_await tx->close();  // RAII not (yet) available with coroutines
                co_return;
            }
            const auto cc{silkworm::ChainConfig::from_json(chain_config.config)};
            if (!cc) {
                throw std::runtime_error("Invalid chain config");
            }
            const auto rule_set_factory = protocol::rule_set_factory(*cc);
            const auto block_reward{rule_set_factory->compute_reward(block_with_hash->block)};
            intx::uint256 total_ommer_reward = 0;
            for (const auto ommer_reward : block_reward.ommers) {
                total_ommer_reward += ommer_reward;
            }
            intx::uint256 block_issuance = block_reward.miner + total_ommer_reward;
            issuance.block_reward = "0x" + intx::hex(block_reward.miner);
            issuance.ommer_reward = "0x" + intx::hex(total_ommer_reward);
            issuance.issuance = "0x" + intx::hex(block_issuance);
            intx::uint256 burnt;
            if (block_with_hash->block.header.base_fee_per_gas) {
                burnt = *block_with_hash->block.header.base_fee_per_gas * block_with_hash->block.header.gas_used;
            } else {
                burnt = 0;
            }
            issuance.burnt = "0x" + intx::hex(burnt);

            const auto total_issued = co_await core::rawdb::read_total_issued(tx_database, block_number);
            const auto total_burnt = co_await core::rawdb::read_total_burnt(tx_database, block_number);

            issuance.total_issued = "0x" + intx::hex(total_issued);
            issuance.total_burnt = "0x" + intx::hex(total_burnt);
            intx::uint256 tips = 0;
            if (block_with_hash->block.header.base_fee_per_gas) {
                const auto receipts{co_await core::get_receipts(tx_database, *block_with_hash)};
                const auto block{block_with_hash->block};
                for (size_t i{0}; i < block.transactions.size(); i++) {
                    auto tip = block.transactions[i].effective_gas_price(block.header.base_fee_per_gas.value_or(0));
                    tips += tip * receipts[i].gas_used;
                }
            }
            issuance.tips = "0x" + intx::hex(tips);
        }
        reply = make_json_content(request, issuance);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_blockNumber
Task<void> ErigonRpcApi::handle_erigon_block_number(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    std::string block_id;
    if (params.empty()) {
        block_id = core::kLatestExecutedBlockId;
    } else if (params.size() == 1) {
        block_id = params[0];
    } else {
        auto error_msg = "invalid erigon_blockNumber params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    SILK_DEBUG << "block: " << block_id;

    auto tx = co_await database_->begin();

    try {
        ethdb::TransactionDatabase tx_database{*tx};
        const auto block_number{co_await core::get_block_number_by_tag(block_id, tx_database)};
        reply = make_json_content(request, to_quantity(block_number));
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_cumulativeChainTraffic
Task<void> ErigonRpcApi::handle_erigon_cumulative_chain_traffic(const nlohmann::json& request, nlohmann::json& reply) {
    const auto& params = request["params"];
    if (params.size() != 1) {
        auto error_msg = "invalid erigon_cumulativeChainTraffic params: " + params.dump();
        SILK_ERROR << error_msg;
        reply = make_json_error(request, 100, error_msg);
        co_return;
    }
    const auto block_id = params[0].get<std::string>();

    SILK_DEBUG << "block_id: " << block_id;

    auto tx = co_await database_->begin();

    ChainTraffic chain_traffic;

    try {
        ethdb::TransactionDatabase tx_database{*tx};

        const auto block_number = co_await core::get_block_number(block_id, tx_database);
        chain_traffic.cumulative_transactions_count = co_await core::rawdb::read_cumulative_transaction_count(tx_database, block_number);
        chain_traffic.cumulative_gas_used = co_await core::rawdb::read_cumulative_gas_used(tx_database, block_number);

        reply = make_json_content(request, chain_traffic);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_content(request, chain_traffic);
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_await tx->close();  // RAII not (yet) available with coroutines
    co_return;
}

// https://eth.wiki/json-rpc/API#erigon_nodeInfo
Task<void> ErigonRpcApi::handle_erigon_node_info(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto node_info_data = co_await backend_->engine_node_info();

        reply = make_json_content(request, node_info_data);
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what() << " processing request: " << request.dump();
        reply = make_json_error(request, 100, e.what());
    } catch (...) {
        SILK_ERROR << "unexpected exception processing request: " << request.dump();
        reply = make_json_error(request, 100, "unexpected exception");
    }

    co_return;
}

}  // namespace silkworm::rpc::commands
