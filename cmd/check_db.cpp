/*
   Copyright 2020 The Silkworm Authors

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
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <csignal>
#include <iostream>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/bucket.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>
#include <string>

namespace bfs = boost::filesystem;
using namespace silkworm;

bool shouldStop{false};
int errorCode{0};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    shouldStop = true;
}


int main(int argc, char* argv[]) {
    CLI::App app("Tests db interfaces.");

    std::string po_db_path{silkworm::db::default_path()};
    bool po_debug{false};
    CLI::Range range32(1u, UINT32_MAX);

    // Check whether or not default db_path exists and
    // has some files in it

    bfs::path db_path(po_db_path);
    CLI::Option* db_path_set =
        app.add_option("--db", po_db_path, "Path to chain db", true)->check(CLI::ExistingDirectory);
    if (!bfs::exists(db_path) || !bfs::is_directory(db_path) || db_path.empty()) {
        db_path_set->required();
    }

    app.add_flag("-d,--debug", po_debug, "May be ignored.");

    CLI11_PARSE(app, argc, argv);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    db_path = bfs::path(po_db_path);
    if (db_path.empty()) {
        std::cerr << "Provided --db [" << po_db_path << "] is an empty directory" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    }


    // ChainConfig config{kEtcMainnetChainConfig};  // Main net config flags
    evmc::bytes32* canonical_headers{nullptr};  // Storage space for canonical headers
    uint64_t canonical_headers_count{0};        // Overall number of canonical headers collected

    try {
        auto env = db::get_env(po_db_path.c_str());
        std::cout << "Database is " << (env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
        {
            auto txn_ro = env->begin_ro_transaction();
            MDB_val key, data;
            int rc{0};

            // Uncomment the following block if you want a list
            // of named buckets stored into the database
            // auto unnamed = txn_ro->open(0);
            // unnamed->get_stat(&s);
            // std::cout << "Database contains " << s.ms_entries << " named buckets" << std::endl;
            // int rc{unnamed->get_first(&hkey, &hdata)};
            // while (!shouldStop && rc == MDB_SUCCESS)
            //{
            //    std::string_view svkey{ static_cast<char*>(hkey.mv_data), hkey.mv_size };
            //    std::cout << "Bucket " << svkey << "\n";
            //    rc = unnamed->get_next(&hkey, &hdata);
            //}
            // std::cout << "\n" << std::endl;

            auto headers = txn_ro->open(db::bucket::kBlockHeaders);

            size_t headers_records{0};
            (void)headers->get_rcount(&headers_records);
            size_t batch_size{headers_records / 50};
            uint32_t percent{0};

            std::cout << "Headers Table has " << headers_records << " records" << std::endl;

            // Dirty way to get last block number (from actually stored headers)
            uint64_t highest_block{0};
            rc = headers->get_last(&key, &data);
            while (!shouldStop && rc == MDB_SUCCESS) {
                ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
                if (v[8] != 'n') {
                    headers->get_prev(&key, &data);
                    continue;
                }
                highest_block = boost::endian::load_big_u64(&v[0]);
                break;
            }

            std::cout << "Highest canonical block number " << highest_block << std::endl;

            // Try allocate enough memory space to fit all cananonical header hashes
            // which need to be processed
            {
                void* mem{std::calloc((highest_block + 1), kHashLength)};
                if (!mem) {
                    // not enough space to store all
                    throw std::runtime_error("Can't allocate space for canonical hashes");
                }
                canonical_headers = static_cast<evmc::bytes32*>(mem);
            }

            // Navigate all headers to load canonical hashes
            rc = headers->get_first(&key, &data);
            while (!shouldStop && rc == MDB_SUCCESS) {
                // Canonical header key is 9 bytes (8 blocknumber + 'n')
                if (key.mv_size == 9) {
                    ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
                    if (v[8] == 'n') {
                        uint64_t header_block = boost::endian::load_big_u64(&v[0]);
                        memcpy((void*)&canonical_headers[header_block], data.mv_data, kHashLength);
                        canonical_headers_count++;
                    }
                }

                batch_size--;
                if (!batch_size) {
                    batch_size = headers_records / 50;
                    percent += 2;
                    std::cout << "Navigated " << percent << "% of headers bucket. Canonical records found "
                              << canonical_headers_count << std::endl;
                }
                rc = headers->get_next(&key, &data);
            }

            // Can now close headers bucket
            // It actually closes the cursor, not the bucket itself
            headers->close();

            // Open bodies bucket and iterate to load transactions (if any in the block)
            auto bodies = txn_ro->open(db::bucket::kBlockBodies);
            size_t bodies_records{0};
            (void)bodies->get_rcount(&bodies_records);

            batch_size = canonical_headers_count / 50;
            percent = 0;
            uint64_t total_transactions{0};

            std::cout << "Bodies Table has " << bodies_records << " records. Canonical headers "
                      << canonical_headers_count << std::endl;

            rc = bodies->get_first(&key, &data);
            for (uint64_t block_num = 0; !shouldStop && block_num < canonical_headers_count && rc == MDB_SUCCESS;
                 block_num++) {
                while (!shouldStop && rc == MDB_SUCCESS) {
                    ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
                    uint64_t body_block{boost::endian::load_big_u64(&v[0])};

                    if (body_block < block_num) {
                        // We're behind with bodies wrt headers
                        rc = bodies->get_next(&key, &data);
                        continue;
                    } else if (body_block > block_num) {
                        // We're ahead with bodies wrt headers
                        // Should not happen.
                        // TODO(Andrea) Raise an exception
                        break;
                    }

                    // Check header hash is the same
                    if (memcmp((void*)&v[8], (void*)&canonical_headers[block_num], 32) != 0) {
                        rc = bodies->get_next(&key, &data);
                        continue;
                    }

                    // We have a block with same canonical header in key
                    // If data contains something process it
                    if (data.mv_size > 3) {
                        ByteView bv{static_cast<uint8_t*>(data.mv_data), data.mv_size};

                        // Actually rlp-decoding the whole block adds a
                        // little overhead as transactions are decoded as
                        // well as ommers which actually are not needed
                        // in this scope. Worth optimize it ?
                        BlockBody body{};
                        rlp::decode(bv, body);

                        total_transactions += body.transactions.size();
                    }

                    // Eventually move to next block
                    rc = bodies->get_next(&key, &data);
                }

                batch_size--;
                if (!batch_size) {
                    batch_size = canonical_headers_count / 50;
                    percent += 2;
                    std::cout << "Navigated " << percent << "% of block canonical headers. Processed transactions "
                              << total_transactions << std::endl;
                }
            }

            bodies->close();
            txn_ro->commit();
        }
        env->close();
        std::cout << "Database is " << (env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
    } catch (db::lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << ex.what() << " " << ex.err() << std::endl;
    } catch (std::runtime_error& ex) {
        // This handles runtime ligic errors
        // eg. trying to open two rw txns
        std::cout << ex.what() << std::endl;
    }

    return 0;
}
