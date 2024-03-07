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

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/node/db/etl/collector.hpp>
#include <silkworm/node/db/stages.hpp>

using namespace silkworm;

int main(int argc, char* argv[]) {
    SignalHandler::init();

    CLI::App app{"Check Tx Hashes => BlockNumber mapping in database"};

    std::string chaindata{DataDirectory{}.chaindata().path().string()};
    size_t block_from{0};
    app.add_option("--chaindata", chaindata, "Path to a database populated by Erigon")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    app.add_option("--from", block_from, "Initial block number to process (inclusive)")
        ->capture_default_str()
        ->check(CLI::Range(1u, UINT32_MAX));

    CLI11_PARSE(app, argc, argv)

    auto data_dir{DataDirectory::from_chaindata(chaindata)};
    data_dir.deploy();
    db::EnvConfig db_config{data_dir.chaindata().path().string()};
    db::etl::Collector collector(data_dir.etl().path().string().c_str(), /* flush size */ 512 * kMebi);

    auto env{db::open_env(db_config)};
    auto txn{env.start_read()};

    auto bodies_table{db::open_cursor(txn, db::table::kBlockBodies)};
    auto tx_lookup_table{db::open_cursor(txn, db::table::kTxLookup)};
    auto transactions_table{db::open_cursor(txn, db::table::kBlockTransactions)};

    uint64_t expected_block_number{0};
    Bytes buffer{};  // To extract compacted data

    try {
        log::Info() << "Checking Transaction Lookups...";

        auto bodies_data{bodies_table.to_first(false)};
        while (bodies_data) {
            auto block_number(endian::load_big_u64(static_cast<uint8_t*>(bodies_data.key.data())));
            auto body_rlp{db::from_slice(bodies_data.value)};
            auto body{unwrap_or_throw(decode_stored_block_body(body_rlp))};

            if (body.txn_count > 0) {
                Bytes transaction_key(8, '\0');
                endian::store_big_u64(transaction_key.data(), body.base_txn_id);

                uint64_t i{0};
                auto transaction_data{transactions_table.find(db::to_slice(transaction_key), false)};
                for (; i < body.txn_count && transaction_data.done;
                     i++, transaction_data = transactions_table.to_next(false)) {
                    if (!transaction_data) {
                        log::Error() << "Block " << block_number << " transaction " << i << " not found in "
                                     << db::table::kBlockTransactions.name << " table";
                        continue;
                    }

                    ByteView transaction_rlp{db::from_slice(transaction_data.value)};
                    auto transaction_hash{keccak256(transaction_rlp)};
                    ByteView transaction_view{transaction_hash.bytes};
                    auto lookup_data{tx_lookup_table.find(db::to_slice(transaction_view), false)};
                    if (!lookup_data) {
                        log::Error() << "Block " << block_number << " transaction " << i << " with hash "
                                     << to_hex(transaction_view) << " not found in " << db::table::kTxLookup.name
                                     << " table";
                        continue;
                    }

                    // Erigon stores block height as compact (no leading zeroes)
                    auto lookup_block_value{db::from_slice(lookup_data.value)};
                    uint64_t actual_block_number{0};
                    if (!endian::from_big_compact(lookup_block_value, actual_block_number)) {
                        log::Error() << "Failed to read expected block number from: " << to_hex(lookup_block_value);
                    } else if (actual_block_number != expected_block_number) {
                        log::Error() << "Mismatch: Expected block number for tx with hash: " << to_hex(transaction_view)
                                     << " is " << expected_block_number << ", but got: " << actual_block_number;
                    }
                }

                if (i != body.txn_count) {
                    log::Error() << "Block " << block_number << " claims " << body.txn_count
                                 << " transactions but only " << i << " read";
                }
            }

            if (expected_block_number % 100000 == 0) {
                log::Info() << "Scanned blocks " << expected_block_number;
            }

            if (SignalHandler::signalled()) {
                break;
            }

            expected_block_number++;
            bodies_data = bodies_table.to_next(false);
        }

        log::Info() << "Check " << (SignalHandler::signalled() ? "aborted" : "completed");

    } catch (const std::exception& ex) {
        log::Error() << ex.what();
        return -5;
    }
    return 0;
}
