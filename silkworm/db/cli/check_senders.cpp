/*
   Copyright 2022 The Silkworm Authors

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

#include <CLI/CLI.hpp>

#include <silkworm/buildinfo.h>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/cli/common.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>

using namespace silkworm;
using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;
using namespace silkworm::cmd::common;

int main(int argc, char* argv[]) {
    SignalHandler::init();

    CLI::App app{"Check Block => Senders mapping in database"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    BlockNum block_from{0}, block_to{0};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Silkworm")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    app.add_option("--from", block_from, "First block number to process (inclusive)")
        ->capture_default_str()
        ->check(CLI::NonNegativeNumber);
    app.add_option("--to", block_to, "Last block number to process (inclusive)")
        ->capture_default_str()
        ->check(CLI::NonNegativeNumber);
    log::Settings log_settings{};
    add_logging_options(app, log_settings);

    CLI11_PARSE(app, argc, argv)

    log::init(log_settings);

    const auto node_name{get_node_name_from_build_info(silkworm_get_buildinfo())};
    SILK_INFO << "Build info: " << node_name;

    auto data_dir{DataDirectory::from_chaindata(chaindata)};
    data_dir.deploy();
    EnvConfig db_config{data_dir.chaindata().path().string()};

    auto env{open_env(db_config)};
    ROTxnManaged txn{env};

    auto canonical_hashes_cursor = txn.ro_cursor(table::kCanonicalHashes);
    auto bodies_cursor = txn.ro_cursor(table::kBlockBodies);
    auto tx_cursor = txn.ro_cursor(table::kBlockTransactions);
    auto senders_cursor = txn.ro_cursor(table::kSenders);

    uint64_t expected_block_num{block_from};
    uint64_t processed_senders_count{0};

    try {
        SILK_INFO << "Checking Transaction Senders...";

        // Seek at the first block body (if any)
        Bytes first_block(8, '\0');
        endian::store_big_u64(first_block.data(), block_from);
        const bool block_from_found = bodies_cursor->seek(to_slice(first_block));
        if (block_from_found) {
            SILK_ERROR << "First block " << block_from << " not found in " << table::kBlockBodies.name << " table";
            return -1;
        }

        // Read one block body at a time until last block is reached or execution is interrupted
        auto bodies_data = bodies_cursor->current(false);
        while (bodies_data) {
            // Decode table key and check expected block number
            auto block_num = endian::load_big_u64(static_cast<uint8_t*>(bodies_data.key.data()));
            if (block_num != expected_block_num) {
                SILK_ERROR << "Block " << block_num << " does not match expected number " << expected_block_num;
                break;
            }

            // Decode block body data as RLP buffer
            auto body_rlp{from_slice(bodies_data.value)};
            auto body{unwrap_or_throw(decode_stored_block_body(body_rlp))};

            // Process block transactions one-by-one
            SILK_DEBUG << "Processing block: " << block_num << " txn count: " << body.txn_count;
            if (body.txn_count > 0) {
                // Retrieve canonical block hash
                const Bytes canonical_key{block_key(block_num)};
                const auto canonical_data{canonical_hashes_cursor->find(to_slice(canonical_key), false)};
                if (!canonical_data) {
                    SILK_ERROR << "Block " << block_num << " not found in " << table::kCanonicalHashes.name << " table";
                    continue;
                }
                SILKWORM_ASSERT(canonical_data.value.length() == kHashLength);
                auto block_hash = to_bytes32({static_cast<const uint8_t*>(canonical_data.value.data()), kHashLength});
                SILK_DEBUG << "Block hash: " << to_hex(block_hash);

                // Read the ordered sequence of block senders (one for each transaction)
                auto senders_key{block_key(block_num, block_hash.bytes)};
                auto senders_data{senders_cursor->find(to_slice(senders_key), /*throw_notfound = */ false)};
                if (!senders_data) {
                    SILK_ERROR << "Block " << block_num << " hash " << to_hex(block_hash) << " not found in " << table::kSenders.name << " table";
                    break;
                }

                std::vector<evmc::address> senders{};
                SILKWORM_ASSERT(senders_data.value.length() % kAddressLength == 0);
                SILKWORM_ASSERT(senders_data.value.length() / kAddressLength == body.txn_count);
                senders.resize(senders_data.value.length() / kAddressLength);
                std::memcpy(senders.data(), senders_data.value.data(), senders_data.value.length());

                SILK_DEBUG << "Read senders count: " << senders.size();

                Bytes tx_key(8, '\0');
                endian::store_big_u64(tx_key.data(), body.base_txn_id);

                // Read block transactions one at a time
                std::vector<Transaction> transactions;
                uint64_t i{0};
                auto tx_data{tx_cursor->find(to_slice(tx_key), false)};
                for (; i < body.txn_count && tx_data.done; ++i, tx_data = tx_cursor->to_next(false)) {
                    if (!tx_data) {
                        SILK_ERROR << "Block " << block_num << " tx " << i << " not found in " << table::kBlockTransactions.name << " table";
                        continue;
                    }
                    ByteView transaction_rlp{from_slice(tx_data.value)};

                    // Decode transaction data as RLP buffer
                    Transaction tx;
                    success_or_throw(rlp::decode(transaction_rlp, tx));

                    SILKWORM_ASSERT(tx.sender());

                    // The most important check: i-th stored sender MUST be equal to i-th transaction recomputed sender
                    if (senders[i] != tx.sender()) {
                        SILK_ERROR << "Block " << block_num << " tx " << i << " recovered sender " << senders[i]
                                   << " does not match computed sender " << *tx.sender();
                    }
                    ++processed_senders_count;

                    const auto transaction_hash{keccak256(transaction_rlp)};
                    SILK_DEBUG << "Tx hash: " << to_hex(transaction_hash.bytes) << " has sender: " << to_hex(senders[i].bytes);
                }

                if (i != body.txn_count) {
                    SILK_ERROR << "Block " << block_num << " claims " << body.txn_count << " transactions but only " << i << " read";
                }
            }

            if (expected_block_num % 100000 == 0) {
                SILK_INFO << "Scanned blocks " << expected_block_num << " processed senders " << processed_senders_count;
            }

            if (expected_block_num == block_to) {
                SILK_INFO << "Target block " << block_to << " reached";
                break;
            }

            if (SignalHandler::signalled()) {
                break;
            }

            // Move to next block body
            ++expected_block_num;
            bodies_data = bodies_cursor->to_next(false);
        }

        SILK_INFO << "Check " << (SignalHandler::signalled() ? "aborted" : "completed");

    } catch (const std::exception& ex) {
        SILK_ERROR << ex.what();
        return -1;
    }
    return 0;
}
