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

#include <atomic>
#include <string>
#include <csignal>
#include <iostream>
#include <queue>
#include <thread>

#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/signals2.hpp>
#include <CLI/CLI.hpp>
#include <ethash/keccak.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/types/block.hpp>

namespace fs = boost::filesystem;
using namespace silkworm;

std::atomic_bool should_stop_{false};           // Request for stop from user or OS
std::atomic_bool main_thread_error_{false};     // Error detected in main thread
std::atomic_bool workers_thread_error_{false};  // Error detected in one of workers threads

struct app_options_t {
    std::string datadir{};          // Provided database path
    uint64_t mapsize{0};            // Provided lmdb map size
    uint32_t numthreads{1};         // Number of recovery threads to start
    size_t batch_size{10'000};      // Number of work packages to serve e worker
    uint32_t block_from{1u};        // Initial block number to start from
    uint32_t block_to{UINT32_MAX};  // Final block number to process
    bool replay{false};             // Whether to replay already extracted senders
    bool debug{false};              // Whether to display some debug info
    bool rundry{false};             // Runs in dry mode (no data is persisted on disk)
};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << " Got interrupt. Stopping ..." << std::endl << std::endl;
    should_stop_.store(true);
}

unsigned get_host_cpus() {
    unsigned n{std::thread::hardware_concurrency()};
    return n ? n : 2;
}

class Recoverer : public silkworm::Worker {
  public:
    Recoverer(uint32_t id, size_t size) : id_(id), mysize_{size} {};

    // Recovery package
    struct package {
        uint64_t block_num;
        ethash::hash256 hash;
        uint8_t recovery_id;
        uint8_t signature[64];
    };

    // Error returned by worker thread
    struct error {
        int err;
        std::string msg;
    };

    // Provides a container of packages to process
    void set_work(uint32_t batch_id, std::vector<package>& packages) {
        std::unique_lock l{mywork_};
        std::swap(packages_, packages);
        current_batch_id_ = batch_id;
    }

    uint32_t get_id() const { return id_; };

    // Pulls results from worker
    std::vector<std::pair<uint64_t, MDB_val>>& get_results(void) { return myresults_; };

    // Signal to connected handlers the task has completed
    boost::signals2::signal<void(uint32_t sender_id, uint32_t batch_id, Recoverer::error error)> signal_completed;

   private:
     const uint32_t id_;                                      // Current worker identifier
     mutable std::mutex mywork_;                              // Work mutex
     std::vector<package> packages_{};                        // Work packages to process
     uint32_t current_batch_id_{0};                           // Identifier of the batch being processed
     size_t mysize_;                                          // Size of the recovery data
     uint8_t* mydata_{nullptr};                               // Pointer to data where rsults are stored
     std::vector<std::pair<uint64_t, MDB_val>> myresults_{};  // Results per block pointing to data area

     // Basic work loop (overrides Worker::work())
     void work() final {

         // Try allocate enough memory to store
         // results output
         mydata_ = static_cast<uint8_t*>(std::calloc(1, mysize_));
         if (!mydata_) {
             throw std::runtime_error("Unable to allocate memory");
         }

         while (!should_stop()) {

             // Wait for a set of recovery packages to get in
             bool expectedKick{true};
             if (!kicked_.compare_exchange_strong(expectedKick, false, std::memory_order_relaxed)) {
                 std::unique_lock l(xwork_);
                 kicked_signal_.wait_for(l, std::chrono::seconds(1));
                 continue;
             }

             {
                 // Lock mutex so no other jobs may be set
                 std::unique_lock l{mywork_};
                 myresults_.clear();
                 error recovery_error{};

                 uint64_t current_block{packages_.at(0).block_num};
                 size_t block_result_offset{0};
                 size_t block_result_length{0};

                 // Loop
                 for (auto const& package : packages_) {
                     // On block switching store the results
                     if (current_block != package.block_num) {
                         MDB_val result{block_result_length, (void*)&mydata_[block_result_offset]};
                         myresults_.push_back({current_block, result});
                         block_result_offset += block_result_length;
                         block_result_length = 0;
                         current_block = package.block_num;
                         if (should_stop_) break;
                     }

                     std::optional<Bytes> recovered{ecdsa::recover(full_view(package.hash.bytes),
                                                                   full_view(package.signature), package.recovery_id)};
                     if (recovered.has_value() && (int)recovered->at(0) == 4) {
                         auto keyHash{ethash::keccak256(recovered->data() + 1, recovered->length() - 1)};
                         std::memcpy(&mydata_[block_result_offset + block_result_length],
                                     &keyHash.bytes[sizeof(keyHash) - kAddressLength], kAddressLength);
                         block_result_length += kAddressLength;
                     } else {
                         recovery_error.err = -1;
                         recovery_error.msg = "Public key recovery failed at block #" + std::to_string(package.block_num);
                         break;  // No need to process other txns
                     }
                 }

                 // Store results for last block
                 if (block_result_length) {
                     MDB_val result{block_result_length, (void*)&mydata_[block_result_offset]};
                     myresults_.push_back({current_block, result});
                 }

                 // Raise finished event
                 signal_completed(id_, current_batch_id_, recovery_error);
                 packages_.clear();  // Clear here. Next set_work will swap the cleaned container to master thread
             }
         }

         std::free(mydata_);
    };
};

void process_txs_for_signing(ChainConfig& config, uint64_t block_num, std::vector<silkworm::Transaction>& transactions,
                             std::vector<Recoverer::package>& packages) {
    for (const auto& txn : transactions) {
        if (!silkworm::ecdsa::is_valid_signature(txn.r, txn.s, config.has_homestead(block_num))) {
            throw std::runtime_error("Got invalid signature in tx for block number " + std::to_string(block_num));
        }

        ecdsa::RecoveryId x{ecdsa::get_signature_recovery_id(txn.v)};

        Bytes rlp{};
        if (x.eip155_chain_id) {
            if (!config.has_spurious_dragon(block_num)) {
                throw std::runtime_error("EIP-155 signature in tx before Spurious Dragon for block number " +
                                         std::to_string(block_num));
            } else if (x.eip155_chain_id != config.chain_id) {
                throw std::runtime_error("Got invalid EIP-155 signature in tx for block number " +
                                         std::to_string(block_num) + " chain_id : expected " +
                                         std::to_string(config.chain_id) + " got " +
                                         intx::to_string(*x.eip155_chain_id));
            }
            rlp::encode(rlp, txn, true, {config.chain_id});
        } else {
            rlp::encode(rlp, txn, true, {});
        }

        auto hash{keccak256(rlp)};
        Recoverer::package rp{block_num, hash, x.recovery_id};
        intx::be::unsafe::store(rp.signature, txn.r);
        intx::be::unsafe::store(rp.signature + 32, txn.s);
        packages.push_back(rp);
    }
}

bool start_workers(std::vector<std::unique_ptr<Recoverer>>& workers) {
    for (const auto& worker : workers) {
        SILKWORM_LOG(LogLevels::LogInfo) << "Starting worker thread #" << worker->get_id() << std::endl;
        worker->start();
        // Wait for thread to init properly
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (worker->get_state() != Worker::WorkerState::kStarted) {
            return false;
        }
    }
}

void stop_workers(std::vector<std::unique_ptr<Recoverer>>& workers, bool wait) {
    for (const auto& worker : workers) {
        if (worker->get_state() == Worker::WorkerState::kStarted) {
            SILKWORM_LOG(LogLevels::LogInfo) << "Stopping worker thread #" << worker->get_id() << std::endl;
            worker->stop(wait);
        }
    }
}

uint64_t load_canonical_headers(std::unique_ptr<lmdb::Transaction>& txn, uint64_t from, uint64_t to, evmc::bytes32* out) {

    uint64_t count{0};

    SILKWORM_LOG(LogLevels::LogInfo) << "Loading canonical block headers [" << from << " ... " << to << "]" << std::endl;

    // Locate starting canonical block selected
    // and navigate headers
    auto header_key{db::header_hash_key(from)};
    auto headers_table{txn->open(db::table::kBlockHeaders)};
    MDB_val mdb_key{db::to_mdb_val(header_key)}, mdb_data{};

    uint32_t percent{0};
    uint32_t percent_step{5};  // 5% increment among batches
    size_t batch_size{(to - from + 1) / (100 / percent_step)};

    int rc{headers_table->seek_exact(&mdb_key, &mdb_data)};
    while (rc == MDB_SUCCESS) {

        // Canonical header key is 9 bytes (8 blocknumber + 'n')
        if (mdb_key.mv_size == header_key.length() && mdb_data.mv_data) {
            ByteView v{static_cast<uint8_t*>(mdb_key.mv_data), mdb_key.mv_size};
            if (v[8] == 'n') {
                auto header_block{boost::endian::load_big_u64(&v[0])};
                if (header_block > to) {
                    rc = MDB_NOTFOUND;
                    break;
                } else {
                    memcpy((void*)&out[count++], mdb_data.mv_data, kHashLength);
                    batch_size--;
                }
            }

            if (!batch_size) {
                batch_size = (to - from + 1) / (100 / percent_step);
                percent += percent_step;
                SILKWORM_LOG(LogLevels::LogInfo)
                    << "... " << std::right << std::setw(3) << std::setfill(' ') << percent << " %" << std::endl;
            }
        }
        rc = (should_stop_ ? MDB_NOTFOUND : headers_table->get_next(&mdb_key, &mdb_data));
    }
    if (rc != MDB_NOTFOUND) {
        lmdb::err_handler(rc);
    }

    return (should_stop_ ? 0 : count);
}

// Writes batch results to db
size_t bufferize_results(std::queue<std::pair<uint32_t, uint32_t>>& batches, std::mutex& batches_mtx,
                     std::vector<std::unique_ptr<Recoverer>>& workers, evmc::bytes32* headers,
                     etl::Collector& collector, uint64_t initial_block) {

    size_t ret{0};
    std::vector<std::pair<uint64_t, MDB_val>> results{};
    do {
        // Loop all completed batches until queue
        // empty. Other batches may complete while
        // writing of batch is in progress
        std::unique_lock l{batches_mtx};
        if (batches.empty()) {
            break;
        }

        // Pull result from proper worker
        auto &item{batches.front()};
        results.swap(workers.at(item.first)->get_results());
        batches.pop();
        l.unlock();

        // Bufferize results
        for (auto& [block_num, mdb_val] : results) {
            Bytes etl_key(40, '\0');
            boost::endian::store_big_u64(&etl_key[0], block_num);
            Bytes etl_data(static_cast<unsigned char*>(mdb_val.mv_data), mdb_val.mv_size);
            etl::Entry etl_entry{ etl_key, etl_data };
            collector.collect(etl_entry);
        }

        std::vector<std::pair<uint64_t, MDB_val>>().swap(results);

    } while (true);

    return ret;
}

// Unwinds Senders' table
void do_unwind(std::unique_ptr<lmdb::Transaction>& txn, uint64_t from) {

    SILKWORM_LOG(LogLevels::LogInfo) << "Unwinding Senders' table ... " << std::endl;
    auto senders{txn->open(db::table::kSenders, MDB_CREATE)};
    if (from <= 1) {
        lmdb::err_handler(senders->clear());
        return;
    }

    Bytes senders_key(40, '\0');
    boost::endian::store_big_u64(&senders_key[0], from);

    MDB_val key{}, data{};
    key.mv_data = (void*)&senders_key[0];
    key.mv_size = senders_key.length();
    int rc{senders->seek(&key, &data)};
    while (rc == MDB_SUCCESS) {
        lmdb::err_handler(senders->del_current());
        rc = senders->get_next(&key, &data);
    }
    if (rc != MDB_NOTFOUND) {
        lmdb::err_handler(rc);
    }

}

// Executes the recovery stage
int do_recover(app_options_t& options) {

    std::shared_ptr<lmdb::Environment> lmdb_env{nullptr};  // Main lmdb environment
    std::unique_ptr<lmdb::Transaction> lmdb_txn{nullptr};  // Main lmdb transaction
    ChainConfig config{kMainnetConfig};                    // Main net config flags
    evmc::bytes32* canonical_headers{nullptr};             // Storage space for canonical headers
    std::vector<Recoverer::package> recoverPackages{};     // Where to store work packages for recoverers

    uint32_t next_batch_id{0};                   // Batch identifier sent to recoverer thread
    size_t batch_size{0};                        // Progressive number of delivered work
    std::atomic<uint32_t> expected_batch_id{0};  // Holder of queue flushing order
    std::queue<std::pair<uint32_t, uint32_t>>
        batches_completed{};           // Queue of batches completed waiting to be written on disk
    std::mutex batches_completed_mtx;  // Guards the queue

    uint32_t next_worker_id{0};                  // Used to serialize the dispatch of works to threads
    std::atomic<uint32_t> workers_in_flight{0};  // Number of workers in flight
    uint64_t total_transactions{0};              // Overall number of transactions processed

    // Recoverer's signal handlers
    boost::function<void(uint32_t, uint32_t, Recoverer::error)> finishedHandler =
        [&expected_batch_id, &batches_completed, &batches_completed_mtx, &workers_in_flight](
            uint32_t sender_id, uint32_t batch_id, Recoverer::error error) {

            // Ensure threads flush in the right order to preserve key sorting
            // Threads waits for its ticket before flushing
            while (expected_batch_id.load(std::memory_order_relaxed) != batch_id) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // Store error condition if applicabile
            if (error.err) {
                workers_thread_error_.store(true);
            }

            // Save my ids in the queue of results to
            // store in db
            std::unique_lock l{batches_completed_mtx};
            std::pair<uint32_t, uint32_t> item{sender_id, batch_id};
            batches_completed.push(item);

            // Ready to serve next thread
            expected_batch_id++;
            workers_in_flight--;
        };

    // Each recoverer will allocate enough
    // storage space to hold results for
    // a full batch. Worker object is not copyable
    // thus the need of a unique_ptr.
    std::vector<std::unique_ptr<Recoverer>> recoverers_{};
    for (uint32_t i = 0; i < options.numthreads; i++) {
        recoverers_.emplace_back(new Recoverer(i, (options.batch_size * kAddressLength)));
        recoverers_.back()->signal_completed.connect(boost::bind(finishedHandler, _1, _2, _3));
    }

    // Start recoverers (here occurs allocation)
    if (!start_workers(recoverers_)) {
        SILKWORM_LOG(LogLevels::LogCritical) << "Unable to start required recoverers" << std::endl;
        stop_workers(recoverers_, true);
        recoverers_.clear();
        return -1;
    }

    // Initialize db_options
    lmdb::DatabaseConfig db_config{options.datadir};
    db_config.set_readonly(false);
    db_config.map_size = options.mapsize;

    // Compute etl temporary path
    fs::path db_path(options.datadir);
    fs::path etl_path(db_path.parent_path() / fs::path("etl-temp"));
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path.string().c_str(), /* flush size */ 512 * kMebi);

    try {
        // Open db and start transaction
        lmdb_env = lmdb::get_env(db_config);
        lmdb_txn = lmdb_env->begin_rw_transaction();

        SILKWORM_LOG(LogLevels::LogInfo) << "Checking previous stages ..." << std::endl;

        auto stage_headers_height{db::stages::get_stage_progress(lmdb_txn, db::stages::KHeaders_key)};
        auto stage_bodies_height{db::stages::get_stage_progress(lmdb_txn, db::stages::KBlockBodies_key)};
        auto stage_senders_height{db::stages::get_stage_progress(lmdb_txn, db::stages::KSenders_key)};

        SILKWORM_LOG(LogLevels::LogDebug) << "Headers height " << stage_headers_height << std::endl;
        SILKWORM_LOG(LogLevels::LogDebug) << "Bodies  height " << stage_bodies_height << std::endl;
        SILKWORM_LOG(LogLevels::LogDebug) << "Senders height " << stage_senders_height << std::endl;

        // Requested from block cannot exceed actual stage_bodies_height
        if (options.block_from > stage_bodies_height) {
            options.block_from = (stage_bodies_height ? stage_bodies_height : 1u);
        }
        if (options.block_to > stage_bodies_height) {
            options.block_to = stage_bodies_height;
        }

        // Do we have to unwind Sender's table ?
        if (options.block_from <= stage_senders_height) {
            do_unwind(lmdb_txn, options.block_from);
            SILKWORM_LOG(LogLevels::LogInfo) << "New stage height " << (options.block_from <= 1 ? 0 : static_cast<uint64_t>(options.block_from) - 1) << std::endl;
            db::stages::set_stage_progress(lmdb_txn, db::stages::KSenders_key, (options.block_from <= 1 ? 0 : static_cast<uint64_t>(options.block_from) - 1));
            lmdb_txn->commit();
            lmdb_txn = lmdb_env->begin_rw_transaction();
        }

        // Try allocate enough memory space to fit all cananonical header hashes
        // which need to be processed
        {
            void* mem{std::calloc((size_t)(options.block_to - options.block_from) + 1, kHashLength)};
            if (!mem) {
                // not enough space to store all
                throw std::runtime_error("Can't allocate enough memory for headers");
            }
            canonical_headers = static_cast<evmc::bytes32*>(mem);
        }

        // Scan headers table to collect all canonical headers
        auto headers_count{load_canonical_headers(lmdb_txn, options.block_from, options.block_to, canonical_headers)};
        if (!headers_count) {
            // Nothing to process
            throw std::logic_error("No canonical headers collected.");
        }

        SILKWORM_LOG(LogLevels::LogInfo) << "Collected " << headers_count << " canonical headers" << std::endl;

        {
            // Set to first key which is initial block number
            // plus canonical hash

            uint64_t current_block{0};
            uint64_t expected_block{options.block_from};
            size_t header_index{0};

            // Build first block key
            auto block_key{db::block_key(options.block_from, canonical_headers[header_index].bytes)};

            MDB_val mdb_key{db::to_mdb_val(block_key)};
            MDB_val mdb_data{};


            SILKWORM_LOG(LogLevels::LogInfo) << "Scanning bodies ... " << std::endl;

            auto bodies_table{lmdb_txn->open(db::table::kBlockBodies)};
            auto transactions_table{lmdb_txn->open(db::table::kEthTx)};

            int rc{bodies_table->seek_exact(&mdb_key, &mdb_data)};
            while (rc == MDB_SUCCESS) {

                auto key_view{db::from_mdb_val(mdb_key)};
                current_block = boost::endian::load_big_u64(key_view.data());

                if (current_block != expected_block) {
                    // We assume keys in block bodies are properly sorted
                    throw std::runtime_error("Bad block body sequence. Expected " + std::to_string(expected_block) +
                                             " got " + std::to_string(current_block));
                }

                if (memcmp((void*)&key_view[8], (void*)&canonical_headers[header_index], 32) != 0) {
                    // We stumbled into a non canonical block (not matching header)
                    // move next and repeat
                    rc = should_stop_ ? MDB_NOTFOUND : bodies_table->get_next(&mdb_key, &mdb_data);
                    continue;
                }

                auto body_rlp{db::from_mdb_val(mdb_data)};
                auto body{db::detail::decode_stored_block_body(body_rlp)};

                // We get here with a matching block number + header
                // Process it if not empty (ie 0 transactions and 0 ommers)
                if (body.txn_count)
                {

                    // Should we overflow the batch queue dispatch the work
                    // accumulated so far to the recoverer thread
                    if ((batch_size + body.txn_count) > options.batch_size) {
                        // If all workers busy no other option than to wait for
                        // at least one free slot
                        while (workers_in_flight == options.numthreads) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        }

                        // Throw if any error from workers
                        if (workers_thread_error_) {
                            throw std::runtime_error("Error from worker thread");
                        }

                        // Write results to db (if any)
                        bufferize_results(batches_completed, batches_completed_mtx, recoverers_, canonical_headers,
                                          collector, options.block_from);

                        // Dispatch new task to worker
                        total_transactions += recoverPackages.size();

                        SILKWORM_LOG(LogLevels::LogDebug) << "Package size " << recoverPackages.size() << std::endl;

                        recoverers_.at(next_worker_id)->set_work(next_batch_id++, recoverPackages);
                        recoverers_.at(next_worker_id)->kick();
                        workers_in_flight++;
                        batch_size = 0;

                        SILKWORM_LOG(LogLevels::LogInfo)
                            << "Block " << std::right << std::setw(9) << std::setfill(' ') << current_block
                            << " Transactions " << std::right << std::setw(12) << std::setfill(' ')
                            << total_transactions << " Workers " << workers_in_flight << "/" << options.numthreads
                            << std::endl;

                        if (++next_worker_id == options.numthreads) {
                            next_worker_id = 0;
                        }
                    }

                    // Load transactions
                    std::vector<Transaction> transactions{
                        db::read_transactions(transactions_table, body.base_txn_id, body.txn_count)};

                    // Enqueue Txs in current batch
                    process_txs_for_signing(config, current_block, transactions, recoverPackages);
                    batch_size += transactions.size();
                }

                // After processing move to next block number and header
                if (++header_index == headers_count) {
                    // We'd go beyond collected canonical headers
                    break;
                }

                expected_block++;
                rc = should_stop_ ? MDB_NOTFOUND : bodies_table->get_next(&mdb_key, &mdb_data);
            }
            if (rc != MDB_NOTFOUND) {
                lmdb::err_handler(rc);
            }

            // Should we have a partially filled work package deliver it now
            if (batch_size && !should_stop_) {
                // If all workers busy no other option than to wait for
                // at least one free slot
                while (workers_in_flight == options.numthreads) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                // Throw if any error from workers
                if (workers_thread_error_) {
                    throw std::runtime_error("Error from worker thread");
                }

                // Write results to db (if any)
                bufferize_results(batches_completed, batches_completed_mtx, recoverers_, canonical_headers, collector,
                                  options.block_from);

                total_transactions += recoverPackages.size();
                recoverers_.at(next_worker_id)->set_work(next_batch_id, recoverPackages);
                recoverers_.at(next_worker_id)->kick();
                workers_in_flight++;
                batch_size = 0;

                SILKWORM_LOG(LogLevels::LogInfo)
                    << "Block " << std::right << std::setw(9) << std::setfill(' ') << current_block << " Transactions "
                    << std::right << std::setw(12) << std::setfill(' ') << total_transactions << " Workers "
                    << workers_in_flight << "/" << options.numthreads << std::endl;
            }

            // Wait for all workers to complete and write their results
            while (workers_in_flight != 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (!should_stop_) {
                bufferize_results(batches_completed, batches_completed_mtx, recoverers_, canonical_headers, collector,
                                  options.block_from);
            }
        }

        SILKWORM_LOG(LogLevels::LogInfo) << "Bodies scan " << (should_stop_ ? "aborted! " : "completed!") << std::endl;

    } catch (lmdb::exception& ex) {
        // This handles specific lmdb errors
        SILKWORM_LOG(LogLevels::LogCritical) << "Unexpected error : " << ex.err() << " " << ex.what() << std::endl;
        main_thread_error_ = true;
    } catch (std::logic_error& ex) {
        SILKWORM_LOG(LogLevels::LogCritical) << ex.what() << std::endl;
        main_thread_error_ = true;
    } catch (std::runtime_error& ex) {
        // This handles runtime logic errors
        // eg. trying to open two rw txns
        SILKWORM_LOG(LogLevels::LogCritical) << "Unexpected error : " << ex.what() << std::endl;
        main_thread_error_ = true;
    }

    // Stop all recoverers and close all tables
    stop_workers(recoverers_, true);

    // free memory
    if (canonical_headers) {
        std::free(canonical_headers);
    }




    // Should we commit ?
    if (!main_thread_error_ && !workers_thread_error_ && !options.rundry && !should_stop_) {

        SILKWORM_LOG(LogLevels::LogInfo) << "Loading data ..." << std::endl;
        try {

            // Load collected data into Senders' table
            auto senders_table{lmdb_txn->open(db::table::kSenders)};
            collector.load(senders_table.get(), etl::identity_load);

            db::stages::set_stage_progress(lmdb_txn, db::stages::KSenders_key, (options.block_to <= 1 ? 0 : static_cast<uint64_t>(options.block_to)));
            lmdb::err_handler(lmdb_txn->commit());
            lmdb::err_handler(lmdb_env->sync());
        } catch (const std::exception& ex) {
            SILKWORM_LOG(LogLevels::LogCritical) << " Unexpected error : " << ex.what() << std::endl;
            main_thread_error_ = true;
        }
    }

    lmdb_txn.reset();
    lmdb_env.reset();
    collector.~Collector();

    SILKWORM_LOG(LogLevels::LogInfo) << "All done ! " << std::endl;
    return (main_thread_error_ ? -1 : 0);
}

// Prints out info of block's transactions with senders
int do_verify(app_options_t& options) {
    // Adjust params
    if (options.block_to == UINT32_MAX) options.block_to = options.block_from;

    try {
        // Open db and start transaction
        lmdb::DatabaseConfig db_config{options.datadir};
        db_config.map_size = options.mapsize;
        std::shared_ptr<lmdb::Environment> lmdb_env{lmdb::get_env(db_config)};
        std::unique_ptr<lmdb::Transaction> lmdb_txn{lmdb_env->begin_ro_transaction()};
        std::unique_ptr<lmdb::Table> lmdb_headers{lmdb_txn->open(db::table::kBlockHeaders)};
        std::unique_ptr<lmdb::Table> lmdb_bodies{lmdb_txn->open(db::table::kBlockBodies)};
        std::unique_ptr<lmdb::Table> lmdb_senders{lmdb_txn->open(db::table::kSenders)};

        // Verify requested block is not beyond what we already have in chaindb
        size_t count{0};
        lmdb::err_handler(lmdb_senders->get_rcount(&count));
        if (!count) throw std::logic_error("Senders table is empty. Is the sync completed ?");
        lmdb::err_handler(lmdb_bodies->get_rcount(&count));
        if (!count) throw std::logic_error("Block bodies table is empty. Is the sync completed ?");
        lmdb::err_handler(lmdb_headers->get_rcount(&count));
        if (!count) throw std::logic_error("Headers table is empty. Is the sync completed ?");

        MDB_val key, data;
        lmdb::err_handler(lmdb_senders->get_last(&key, &data));
        ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
        uint64_t most_recent_sender{boost::endian::load_big_u64(&v[0])};
        if (options.block_from > most_recent_sender) {
            throw std::logic_error("Selected block beyond collected senders");
        }

        for (uint32_t block_num = options.block_from; block_num <= options.block_to; block_num++) {
            std::cout << "Reading block #" << block_num << std::endl;
            std::optional<BlockWithHash> bh{db::read_block(*lmdb_txn, block_num, /*read_senders=*/true)};
            if (!bh) {
                throw std::logic_error("Could not locate block #" + std::to_string(block_num));
            }

            if (!bh->block.transactions.size()) {
                std::cout << "Block has 0 transactions" << std::endl;
                continue;
            }

            std::cout << std::right << std::setw(4) << std::setfill(' ') << "Tx"
                      << " " << std::left << std::setw(66) << std::setfill(' ') << "Hash"
                      << " " << std::left << std::setw(42) << std::setfill(' ') << "From"
                      << " " << std::left << std::setw(42) << std::setfill(' ') << "To" << std::endl;
            std::cout << std::right << std::setw(4) << std::setfill('-') << ""
                      << " " << std::left << std::setw(66) << std::setfill('-') << ""
                      << " " << std::left << std::setw(42) << std::setfill('-') << ""
                      << " " << std::left << std::setw(42) << std::setfill('-') << "" << std::endl;

            for (size_t i = 0; i < bh->block.transactions.size(); i++) {
                Bytes rlp{};
                rlp::encode(rlp, bh->block.transactions.at(i), /*forsigning*/ false, {});
                ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.length())};
                ByteView bv{hash.bytes, 32};
                std::cout << std::right << std::setw(4) << std::setfill(' ') << i << " 0x" << to_hex(bv) << " 0x"
                          << to_hex(*(bh->block.transactions.at(i).from)) << " 0x"
                          << to_hex(*(bh->block.transactions.at(i).to)) << std::endl;
            }

            std::cout << std::endl;
        }

    } catch (const std::logic_error& ex) {
        std::cout << ex.what() << std::endl;
        return -1;
    } catch (const std::exception& ex) {
        std::cout << "Unexpected error : " << ex.what() << std::endl;
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    // Init command line parser
    CLI::App app("Senders recovery tool.");
    app_options_t options{};
    options.datadir = silkworm::db::default_path();  // Default chain data db path
    options.numthreads = get_host_cpus() - 1;        // 1 thread per core leaving one slot for main thread

    // Command line arguments
    app.add_option("--datadir", options.datadir, "Path to chain db", true)->check(CLI::ExistingDirectory);

    std::string mapSizeStr{"0"};
    app.add_option("--lmdb.mapSize", mapSizeStr, "Lmdb map size", true);
    app.add_option("--threads", options.numthreads, "Number of recovering threads", true)
        ->check(CLI::Range(1u, get_host_cpus() - 1));
    app.add_option("--batch", options.batch_size, "Number of transactions to process per batch", true)
        ->check(CLI::Range((size_t)1'000, (size_t)10'000'000));
    app.add_option("--from", options.block_from, "Initial block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_option("--to", options.block_to, "Final block number to process (inclusive)", true)
        ->check(CLI::Range(1u, UINT32_MAX));
    app.add_flag("--debug", options.debug, "May print some debug/trace info.");
    app.add_flag("--replay", options.replay, "Replay transactions.");
    app.add_flag("--dry", options.rundry, "Runs the full cycle but nothing is persisted");

    app.require_subcommand(1);  // One of the following subcommands is required
    auto& app_recover = *app.add_subcommand("recover", "Recovers senders' addresses");
    auto& app_verify = *app.add_subcommand("verify", "Verifies senders' addresses for given block");

    CLI11_PARSE(app, argc, argv);
    Logger::default_logger().set_local_timezone(true);  // for compatibility with TG logging
    if (options.debug) {
        Logger::default_logger().verbosity = LogLevels::LogTrace;
    }

    auto lmdb_mapSize{parse_size(mapSizeStr)};
    if (!lmdb_mapSize) {
        std::cerr << "Provided --lmdb.mapSize \"" << mapSizeStr << "\" is invalid" << std::endl;
        return -1;
    }
    if (*lmdb_mapSize) {
        // Adjust mapSize to a multiple of page_size
        size_t host_page_size{boost::interprocess::mapped_region::get_page_size()};
        options.mapsize = ((*lmdb_mapSize + host_page_size - 1) / host_page_size) * host_page_size;
    }
    if (!options.block_from) options.block_from = 1u;  // Block 0 (genesis) has no transactions

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    fs::path db_path = fs::path(options.datadir);
    if (!fs::exists(db_path) || !fs::is_directory(db_path) || fs::is_empty(db_path)) {
        std::cerr << "Invalid or empty --datadir \"" << options.datadir << "\"" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    } else {
        fs::path db_file = fs::path(db_path / fs::path("data.mdb"));
        if (!fs::exists(db_file) || !fs::file_size(db_file)) {
            std::cerr << "Invalid or empty data file \"" << db_file.string() << "\"" << std::endl
                      << "Try --help for help" << std::endl;
            return -1;
        }
    }

    // Invoke proper action
    int rc{-1};
    if (app_recover) {
        rc = do_recover(options);
    } else if (app_verify) {
        rc = do_verify(options);
    } else {
        std::cerr << "No command specified" << std::endl;
    }

    return rc;
}
