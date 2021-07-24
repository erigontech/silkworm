/*
   Copyright 2021 The Silkworm Authors

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

#include <csignal>
#include <filesystem>
#include <iostream>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/types/transaction.hpp>

using namespace silkworm;

std::atomic_bool should_stop_{false};  // Request for stop from user or OS

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << " Got interrupt. Stopping ..." << std::endl << std::endl;
    should_stop_.store(true);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    namespace fs = std::filesystem;

    CLI::App app{"Check Tx Hashes => BlockNumber mapping in database"};

    std::string chaindata{DataDirectory{}.get_chaindata_path().string()};
    size_t block_from;
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon", true)
        ->check(CLI::ExistingDirectory);
    app.add_option("--from", block_from, "Initial block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));

    CLI11_PARSE(app, argc, argv);

    auto data_dir{DataDirectory::from_chaindata(chaindata)};
    data_dir.create_tree();
    db::EnvConfig db_config{data_dir.get_chaindata_path().string()};
    etl::Collector collector(data_dir.get_etl_path().string().c_str(), /* flush size */ 512 * kMebi);

    auto env{db::open_env(db_config)};
    auto txn{env.start_read()};

    auto bodies_table{db::open_cursor(txn, db::table::kBlockBodies)};
    auto tx_lookup_table{db::open_cursor(txn, db::table::kTxLookup)};
    auto transactions_table{db::open_cursor(txn, db::table::kEthTx)};

    uint64_t expected_block_number{0};
    Bytes buffer{};  // To extract compacted data

    try {
        SILKWORM_LOG(LogLevel::Info) << "Checking Transaction Lookups..." << std::endl;

        auto bodies_data{bodies_table.to_first(false)};
        while (bodies_data) {
            auto block_number(boost::endian::load_big_u64(static_cast<uint8_t*>(bodies_data.key.iov_base)));
            auto body_rlp{db::from_slice(bodies_data.value)};
            auto body{db::detail::decode_stored_block_body(body_rlp)};

            if (body.txn_count > 0) {
                Bytes transaction_key(8, '\0');
                boost::endian::store_big_u64(transaction_key.data(), body.base_txn_id);

                uint64_t i{0};
                auto transaction_data{transactions_table.find(db::to_slice(transaction_key), false)};
                for (; i < body.txn_count && transaction_data.done == true;
                     i++, transaction_data = transactions_table.to_next(false)) {
                    if (!transaction_data) {
                        SILKWORM_LOG(LogLevel::Error)
                            << "Block " << block_number << " transaction " << i << " not found in "
                            << db::table::kEthTx.name << " table" << std::endl;
                        continue;
                    }

                    ByteView transaction_rlp{db::from_slice(transaction_data.value)};
                    auto transaction_hash{keccak256(transaction_rlp)};
                    auto transaction_view{full_view(transaction_hash.bytes)};
                    auto lookup_data{tx_lookup_table.find(db::to_slice(transaction_view), false)};
                    if (!lookup_data) {
                        SILKWORM_LOG(LogLevel::Error) << "Block " << block_number << " transaction " << i
                                                      << " with hash " << to_hex(transaction_view) << " not found in "
                                                      << db::table::kTxLookup.name << " table" << std::endl;
                        continue;
                    }

                    // Erigon stores block height as compact (no leading zeroes)
                    auto lookup_block_value{left_pad(db::from_slice(lookup_data.value), sizeof(uint64_t), buffer)};
                    auto actual_block_number{boost::endian::load_big_u64(lookup_block_value.data())};

                    if (actual_block_number != expected_block_number) {
                        SILKWORM_LOG(LogLevel::Error)
                            << "Mismatch: Expected block number for tx with hash: " << to_hex(transaction_view)
                            << " is " << expected_block_number << ", but got: " << actual_block_number << std::endl;
                    }
                }

                if (i != body.txn_count) {
                    SILKWORM_LOG(LogLevel::Error) << "Block " << block_number << " claims " << body.txn_count
                                                  << " transactions but only " << i << " read" << std::endl;
                }
            }

            if (expected_block_number % 100000 == 0) {
                SILKWORM_LOG(LogLevel::Info) << "Scanned blocks " << expected_block_number << std::endl;
            }

            if (should_stop_) {
                break;
            }

            expected_block_number++;
            bodies_data = bodies_table.to_next(false);
        }

        SILKWORM_LOG(LogLevel::Info) << "Check " << (should_stop_ ? "aborted" : "completed") << std::endl;

    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevel::Error) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
