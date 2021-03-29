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
#include <iostream>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>

#include <silkworm/chain/config.hpp>
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

    namespace fs = boost::filesystem;

    CLI::App app{"Check Tx Hashes => BlockNumber mapping in database"};

    std::string db_path{db::default_path()};
    size_t block_from;
    app.add_option("--chaindata", db_path, "Path to a database populated by Turbo-Geth", true)
        ->check(CLI::ExistingDirectory);
    app.add_option("--from", block_from, "Initial block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    CLI11_PARSE(app, argc, argv);

    // Check data.mdb exists in provided directory
    fs::path db_file{fs::path(db_path) / fs::path("data.mdb")};
    if (!fs::exists(db_file)) {
        SILKWORM_LOG(LogLevels::LogError) << "Can't find a valid TG data file in " << db_path << std::endl;
        return -1;
    }
    fs::path datadir(db_path);
    fs::path etl_path(datadir.parent_path() / fs::path("etl-temp"));
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path.string().c_str(), /* flush size */ 512 * kMebi);

    lmdb::DatabaseConfig db_config{db_path};
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};

    auto bodies_table{txn->open(db::table::kBlockBodies)};
    auto tx_lookup_table{txn->open(db::table::kTxLookup)};
    auto transactions_table{txn->open(db::table::kEthTx)};
    uint64_t expected_block_number{0};
    Bytes buffer{};  // To extract compacted data

    try {
        SILKWORM_LOG(LogLevels::LogInfo) << "Checking Transaction Lookups..." << std::endl;

        MDB_val mdb_key, mdb_data;
        int rc{bodies_table->get_first(&mdb_key, &mdb_data)};

        while (!rc) {
            ByteView block_key(db::from_mdb_val(mdb_key));
            auto block_number(boost::endian::load_big_u64(&block_key[0]));
            auto body_rlp{db::from_mdb_val(mdb_data)};
            auto body{db::detail::decode_stored_block_body(body_rlp)};

            if (body.txn_count > 0) {
                Bytes transaction_key(8, '\0');
                boost::endian::store_big_u64(transaction_key.data(), body.base_txn_id);
                MDB_val tx_mdb_key{db::to_mdb_val(transaction_key)};
                MDB_val tx_mdb_data;

                uint64_t i{0};
                for (int rc2{transactions_table->seek_exact(&tx_mdb_key, &tx_mdb_data)};
                     rc2 == MDB_SUCCESS && i < body.txn_count;
                     rc2 = transactions_table->get_next(&tx_mdb_key, &tx_mdb_data), ++i) {
                    lmdb::err_handler(rc2);
                    ByteView tx_rlp{db::from_mdb_val(tx_mdb_data)};
                    auto hash{keccak256(tx_rlp)};
                    auto hash_view{full_view(hash.bytes)};
                    auto lookup_data(tx_lookup_table->get(hash_view));

                    if (!lookup_data.has_value()) {
                        /* We did not find the transaction */
                        SILKWORM_LOG(LogLevels::LogError)
                            << "Block " << block_number << " transaction " << i << " not found in "
                            << db::table::kTxLookup.name << " table" << std::endl;
                        continue;
                    }

                    // TG stores block height as compact (no leading zeroes)
                    auto lookup_block_data{left_pad(*lookup_data, sizeof(uint64_t), buffer)};
                    auto actual_block_number{boost::endian::load_big_u64(lookup_block_data.data())};

                    if (actual_block_number != expected_block_number) {
                        std::cout << lookup_data->size() << "   " << to_hex(*lookup_data) << std::endl;
                        SILKWORM_LOG(LogLevels::LogError)
                            << "Mismatch: Expected block number for tx with hash: " << to_hex(hash_view) << " is "
                            << expected_block_number << ", but got: " << actual_block_number << std::endl;
                    }
                }

                if (i != body.txn_count) {
                    SILKWORM_LOG(LogLevels::LogError) << "Block " << block_number << " claims " << body.txn_count
                                                      << " transactions but only " << i << " read" << std::endl;
                }
            }

            if (expected_block_number % 100000 == 0) {
                SILKWORM_LOG(LogLevels::LogInfo) << "Scanned blocks " << expected_block_number << std::endl;
            }

            if (!should_stop_) {
                expected_block_number++;
                rc = bodies_table->get_next(&mdb_key, &mdb_data);
            } else {
                break;
            }
        }

        if (rc != MDB_NOTFOUND) {
            lmdb::err_handler(rc);
        }

        SILKWORM_LOG(LogLevels::LogInfo) << "Check " << (should_stop_ ? "aborted" : "completed") << std::endl;
    } catch (const std::exception& ex) {
        SILKWORM_LOG(LogLevels::LogError) << ex.what() << std::endl;
        return -5;
    }
    return 0;
}
