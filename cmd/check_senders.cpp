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
#include <atomic>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/filesystem.hpp>
#include <condition_variable>
#include <csignal>
#include <ethash/keccak.hpp>
#include <iostream>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/bucket.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>
#include <string>
#include <thread>

namespace bfs = boost::filesystem;
using namespace silkworm;

std::atomic_bool should_stop_{false};           // Request for stop from user or OS
std::atomic_bool main_thread_error_{false};     // Error detected in main thread
std::atomic_bool workers_thread_error_{false};  // Error detected in one of workers threads

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    should_stop_.store(true);
}

unsigned get_host_cpus() {
    unsigned n{std::thread::hardware_concurrency()};
    return n ? n : 2;
}

std::string format_time(boost::posix_time::ptime now = boost::posix_time::microsec_clock::local_time()) {
    char buf[40];
    // Get the time offset in current day
    const boost::posix_time::time_duration td = now.time_of_day();
    const int32_t month = static_cast<int32_t>(now.date().month());
    const int32_t day = static_cast<int32_t>(now.date().day());
    const int32_t hours = static_cast<int32_t>(td.hours());
    const int32_t minutes = static_cast<int32_t>(td.minutes());
    const int32_t seconds = static_cast<int32_t>(td.seconds());
    const int32_t milliseconds = static_cast<int32_t>(
        td.total_milliseconds() -
        ((static_cast<int64_t>(hours) * 3600 + static_cast<int64_t>(minutes) * 60 + seconds) * 1000));
    sprintf(buf, "[%02d-%02d %02d:%02d:%02d.%03d]", month, day, hours, minutes, seconds, milliseconds);
    return std::string{buf};
}

class Recoverer : public silkworm::Worker {
   public:
    Recoverer(uint32_t id, size_t size, bool debug) : id_(id), debug_{debug}, mysize_{size} {};

    struct package {
        uint64_t blockNum;
        ethash::hash256 messageHash;
        uint8_t recoveryId;
        intx::uint256 r;
        intx::uint256 s;
    };

    // Provides a container of packages to process
    void set_work(uint32_t batch_id, std::vector<package>& packages) {
        std::unique_lock l{mywork_};
        std::swap(packages_, packages);
        current_batch_id_ = batch_id;
        // packages_ = std::move(packages);
    }

    // Returns whether or not this worker is busy
    bool is_busy() { return busy_.load(); }

    boost::signals2::signal<void(uint32_t senderId, std::vector<std::pair<uint64_t, MDB_val>>& results,
                                 bool recovery_error)>
        signal_finished;

   private:
    uint32_t id_;                                            // Current worker identifier
    bool debug_;                                             // Whether or not display debug info
    std::atomic_bool busy_{false};                           // Whether the thread is busy processing
    mutable std::mutex mywork_;                              // Work mutex
    std::vector<package> packages_{};                        // Work packages to process
    uint32_t current_batch_id_;                              // Identifier of the batch being processed
    size_t mysize_;                                          // Size of the recovery data
    uint8_t* mydata_{nullptr};                               // Pointer to data where rsults are stored
    std::vector<std::pair<uint64_t, MDB_val>> myresults_{};  // Results per block pointing to data area

    // Basic work loop (overrides Worker::work())
    void work() final {
        bool recovery_error_{false};

        // Try allocate enough memory to store
        // results output
        mydata_ = static_cast<uint8_t*>(std::calloc(1, mysize_));
        if (!mydata_) {
            throw std::runtime_error("Unable to allocate memory");
        }

        while (!should_stop()) {
            bool expectedKick{true};
            if (!kicked_.compare_exchange_strong(expectedKick, false, std::memory_order_relaxed)) {
                std::unique_lock l(xwork_);
                kicked_signal_.wait_for(l, std::chrono::seconds(1));
                continue;
            }

            busy_.store(true);
            if (debug_) {
                std::cout << format_time() << " Recoverer #" << id_ << " starting task with " << packages_.size()
                          << " items " << std::endl;
            }

            {
                // Lock mutex so no other jobs may be set
                std::unique_lock l{mywork_};
                Bytes signature(64, '\0');
                uint64_t current_block{packages_.at(0).blockNum};
                size_t data_offset{0};
                size_t data_length{0};

                // Loop
                for (size_t x{0}; x < packages_.size() && !recovery_error_; x++) {
                    Recoverer::package rp = packages_.at(x);

                    // On block switching store the results
                    if (current_block != rp.blockNum) {
                        MDB_val result{data_length, (void*)&mydata_[data_offset]};
                        myresults_.push_back({current_block, result});
                        data_length = 0;
                        current_block = rp.blockNum;
                    }

                    // Endianess swap for r and s
                    for (int i{0}; i < 2; i++) {
                        std::uint8_t* p = reinterpret_cast<uint8_t*>(i == 0 ? &rp.r.lo : &rp.s.lo);
                        int offset{i ? 32 : 0};
                        for (int j{0}; j < 32; j++) {
                            signature[offset + j] = p[31 - j];
                        }
                    }

                    ByteView message{rp.messageHash.bytes, 32};
                    std::optional<Bytes> key{ecdsa::recover(message, signature, rp.recoveryId)};

                    if (key.has_value() && (int)key->at(0) == 4) {
                        ethash::hash256 keyHash{ethash::keccak256(key->data() + 1, key->length() - 1)};
                        std::memcpy(&mydata_[data_offset], &keyHash.bytes[12], kAddressLength);
                        data_offset += kAddressLength;
                        data_length += kAddressLength;
                    } else {
                        std::cout << format_time() << " Recoverer #" << id_ << " "
                                  << "Public key recovery failed at block #" << rp.blockNum << std::endl;
                        recovery_error_ = true;
                        break;  // No need to process other txns
                    }
                }

                // Store results for last block
                if (data_length) {
                    MDB_val result{data_length, (void*)&mydata_[data_offset]};
                    myresults_.push_back({current_block, result});
                }

                // Raise finished event
                signal_finished(current_batch_id_, myresults_, recovery_error_);
                packages_.clear();
                myresults_.clear();
            }

            busy_.store(false);

            if (debug_) {
                std::cout << format_time() << " Recoverer #" << id_ << " completed task" << std::endl;
            }
        }
    };
};

void process_txs_for_signing(ChainConfig& config, uint64_t block_num, BlockBody& body,
                             std::vector<Recoverer::package>& packages) {
    for (const silkworm::Transaction& txn : body.transactions) {
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

        ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.length())};
        Recoverer::package rp{block_num, hash, x.recovery_id, txn.r, txn.s};
        packages.push_back(rp);
    }
}

bool start_workers(std::vector<std::unique_ptr<Recoverer>>& workers) {
    for (size_t r = 0; r < workers.size(); r++) {
        std::cout << format_time() << " Starting worker thread #" << r << std::endl;
        workers.at(r)->start();
        // Wait for thread to init properly
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (workers.at(r)->get_state() != Worker::WorkerState::kStarted) {
            return false;
        }
    }
    return true;
}

void stop_workers(std::vector<std::unique_ptr<Recoverer>>& workers) {
    for (size_t r = 0; r < workers.size(); r++) {
        if (workers.at(r)->get_state() == Worker::WorkerState::kStarted) {
            std::cout << format_time() << " Stopping worker thread #" << r << std::endl;
            workers.at(r)->stop(true);
        }
    }
}

uint64_t get_highest_canonical_block(std::unique_ptr<db::lmdb::Bkt>& headers) {
    MDB_val key, data;
    uint64_t retvar{0};

    try {
        int rc{headers->get_last(&key, &data)};
        while (rc == MDB_SUCCESS) {
            ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
            if (v[8] != 'n') {
                headers->get_prev(&key, &data);
                continue;
            }
            retvar = boost::endian::load_big_u64(&v[0]);
            break;
        }
    } catch (const std::exception& ex) {
        std::cout << format_time() << "Unexpected error " << ex.what()
                  << " while tryng to locate highest canonical block" << std::endl;
        should_stop_.store(true);
    }

    return retvar;
}

uint64_t load_canonical_headers(std::unique_ptr<db::lmdb::Bkt>& headers, uint64_t from, uint64_t to,
                                evmc::bytes32* out) {
    uint64_t retvar{0};

    // Locate starting canonical block selected
    // and navigate headers
    MDB_val key, data;
    Bytes header_key(9, 'n');
    boost::endian::store_big_u64(&header_key[0], from);
    key.mv_data = (void*)&header_key[0];
    key.mv_size = 9;

    uint32_t percent{0};
    uint32_t percent_step{5};  // 5% increment among batches
    size_t batch_size{(to - from) / (100 / percent_step)};

    std::cout << format_time() << " Locating header at height " << from << std::endl;
    bool eof{false};
    int rc{headers->seek_exact(&key, &data)};
    if (!rc) std::cout << format_time() << " Scanning headers ... " << std::endl;
    while (!should_stop_ && !eof && rc == MDB_SUCCESS) {
        // Canonical header key is 9 bytes (8 blocknumber + 'n')
        if (key.mv_size == 9) {
            ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
            if (v[8] == 'n') {
                uint64_t header_block = boost::endian::load_big_u64(&v[0]);
                if (header_block > to) {
                    eof = true;
                } else {
                    memcpy((void*)&out[header_block - from], data.mv_data, kHashLength);
                    retvar++;
                    batch_size--;
                }
            }

            if (!batch_size) {
                batch_size = (to - from) / (100 / percent_step);
                percent += percent_step;
                std::cout << format_time() << " ... " << percent << "% " << std::endl;
            }
        }
        if (!eof) rc = headers->get_next(&key, &data);
    }

    return (should_stop_ ? 0 : retvar);
}

int main(int argc, char* argv[]) {
    CLI::App app("Walks Ethereum blocks and recovers senders.");

    std::string po_data_dir{silkworm::db::default_path()};  // Default database path
    uint32_t po_num_threads{get_host_cpus() - 1};          // Number of recovery threads to start
    uint32_t po_from_block{1u};                            // Initial block number to start from
    uint32_t po_to_block{UINT32_MAX};                      // Final block number to process
    size_t po_batch_size{10'000};                          // Number of work packages to serve e worker
    bool po_debug{false};                                  // Whether to display some debug info
    bool po_dry{false};                                    // Runs in dry mode (no data is persisted on disk)
    bool po_replay{false};                                 // Replays senders extraction if already present
    CLI::Range range32(1u, UINT32_MAX);

    // Check whether or not default db_path exists and
    // has some files in it
    bfs::path db_path(po_data_dir);
    CLI::Option* db_path_set =
        app.add_option("--datadir", po_data_dir, "Path to chain db", true)->check(CLI::ExistingDirectory);
    if (!bfs::exists(db_path) || !bfs::is_directory(db_path) || db_path.empty()) {
        db_path_set->required();
    }

    app.add_flag("-d,--debug", po_debug, "May be ignored.");
    app.add_flag("--dry", po_dry, "Runs the full cycle but nothing is persisted");
    app.add_flag("--replay", po_replay, "Replays senders extraction if data already present");
    app.add_option("--rthreads", po_num_threads, "Number of recovering threads", true)
        ->check(CLI::Range(1u, get_host_cpus() - 1));
    app.add_option("--from,-f", po_from_block, "Initial block number to process (inclusive)", true)->check(range32);
    app.add_option("--to,-t", po_to_block, "Final block number to process (inclusive)", true)->check(range32);
    app.add_option("--batch", po_batch_size, "Number of transactions to process per batch", true)
        ->check(CLI::Range((size_t)1'000, (size_t)1'000'000));

    CLI11_PARSE(app, argc, argv);

    if (!po_from_block) po_from_block = 1u;  // Block 0 (genesis) has no transactions

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    db_path = bfs::path(po_data_dir);
    if (db_path.empty()) {
        std::cerr << "Provided --datadir [" << po_data_dir << "] is an empty directory" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    }

    std::shared_ptr<db::lmdb::Env> lmdb_env{nullptr};      // Main lmdb environment
    std::unique_ptr<db::lmdb::Txn> lmdb_txn{nullptr};      // Main lmdb transaction
    std::unique_ptr<db::lmdb::Bkt> lmdb_bodies{nullptr};   // Block bodies bucket
    std::unique_ptr<db::lmdb::Bkt> lmdb_senders{nullptr};  // Transaction senders bucket
    ChainConfig config{kEthMainnetConfig};                 // Main net config flags
    evmc::bytes32* canonical_headers{nullptr};             // Storage space for canonical headers
    uint64_t canonical_headers_count{0};                   // Overall number of canonical headers collected
    std::vector<Recoverer::package> recoverPackages{};     // Where to store work packages for recoverers
    uint32_t process_batch_id{0};                          // Batch identifier sent to recoverer thread
    std::atomic<uint32_t> workers_in_flight{0};            // Number of workers in flight
    std::atomic<uint32_t> flush_batch_id{0};               // Holder of queue flushing order
    uint64_t total_transactions{0};                        // Overall number of transactions processed
    uint32_t nextRecovererId{0};                           // Used to serialize the dispatch of works to threads
    size_t batchTxsCount{0};                               // Progressive number of delivered work

    std::condition_variable ready_for_write_cv{};
    std::atomic_bool ready_for_write{false};
    std::mutex write_mtx;

    // Recoverer's signal handlers
    boost::function<void(uint32_t batch_id, std::vector<std::pair<uint64_t, MDB_val>> & results, bool recovery_error)>
        finishedHandler =
            [&](uint32_t batch_id, std::vector<std::pair<uint64_t, MDB_val>>& results, bool recovery_error) {
                // Ensure threads flush in the right order to preserve key sorting
                // Threads waits for its ticket before flushing
                while (flush_batch_id.load(std::memory_order_relaxed) != batch_id) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }

                // Prevent threads from flushing their results while
                // main thread is still fetching blocks
                while (!should_stop_ && !ready_for_write.load(std::memory_order_relaxed)) {
                    std::unique_lock l(write_mtx);
                    ready_for_write_cv.wait_for(l, std::chrono::milliseconds(5));
                    continue;
                }

                // This prevents waiting threads to be stuck forever
                if (should_stop_ || recovery_error) {
                    if (recovery_error) {
                        workers_thread_error_.store(true);
                    }
                } else {
                    // Append results to senders bucket
                    int rc{0};
                    Bytes senders_key(40, '\0');
                    MDB_val key{40, (void*)&senders_key[0]};
                    for (auto& result : results) {
                        boost::endian::store_big_u64(&senders_key[0], result.first);
                        memcpy((void*)&senders_key[8], (void*)&canonical_headers[result.first - po_from_block],
                               kHashLength);
                        rc = lmdb_senders->put_append(&key, &result.second);
                        if (rc != MDB_SUCCESS) {
                            workers_thread_error_.store(true);
                            break;
                        }
                    }
                };

                // Ready to serve next thread
                flush_batch_id.store(++batch_id, std::memory_order_relaxed);
                workers_in_flight--;
            };

    // Each recoverer will allocate enough
    // storage space to hold results for
    // a full batch. Worker object is not copyable
    // thus the need of a unique_ptr.
    std::vector<std::unique_ptr<Recoverer>> recoverers_{};
    for (uint32_t i = 0; i < po_num_threads; i++) {
        try {
            auto r = std::make_unique<Recoverer>(i, (po_batch_size * kAddressLength), po_debug);
            r->signal_finished.connect(boost::bind(finishedHandler, _1, _2, _3));
            recoverers_.push_back(std::move(r));
        } catch (...) {
            std::cerr << "Could not allocate enough memory for Recoverer #" << i << "\n"
                      << "Try lower batch size value or use less rthread" << std::endl;
            return -1;
        }
    }

    // Start recoverers
    if (!start_workers(recoverers_)) {
        std::cout << format_time() << " Unable to start required recoverers" << std::endl;
        stop_workers(recoverers_);
        return -1;
    }

    try {
        // Open db and start transaction
        lmdb_env = db::get_env(po_data_dir.c_str());
        lmdb_txn = lmdb_env->begin_rw_transaction();
        lmdb_senders = lmdb_txn->open(db::bucket::kSenders, MDB_CREATE);  // Throws on error
        auto headers = lmdb_txn->open(db::bucket::kBlockHeaders);         // Throws on error

        /*
         * Senders bucket has only sorted keys from canonical headers
         * By consequence po_from_block is the last block
         * stored in senders + 1.
         * If po_replay flag is set then po_from_block can be anything
         * below that value
         */
        size_t senders_count{0};
        lmdb_senders->get_rcount(&senders_count);
        if (senders_count) {
            MDB_val key, data;
            uint64_t max_sender_block_key{0};
            int rc{lmdb_senders->get_last(&key, &data)};
            if (rc) {
                throw std::runtime_error("Unable to locate highest senders block key");
            }
            ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
            max_sender_block_key = boost::endian::load_big_u64(&v[0]);
            if (po_replay && po_from_block <= max_sender_block_key) {
                // Delete all records of senders bucket from po_from_block
                // up to max_sender_block_key
                std::cout << format_time() << " Deleting previously processed senders from block " << po_from_block
                          << std::endl;
                Bytes block_key(40, '\0');
                boost::endian::store_big_u64(&block_key[0], po_from_block);
                key.mv_data = (void*)&block_key[0];
                key.mv_size = 40;
                rc = lmdb_senders->seek(&key, &data);
                while (!should_stop_ && rc == MDB_SUCCESS) {
                    rc = lmdb_senders->del_current(false);
                    rc = lmdb_senders->get_next(&key, &data);
                }
                po_to_block = po_to_block > max_sender_block_key ? po_to_block : max_sender_block_key;

            } else {
                po_from_block = max_sender_block_key + 1;
            }

        } else {
            po_from_block = 1u;
        }

        // Dirty way to get last block number (from actually stored headers)
        uint64_t highest_block{get_highest_canonical_block(headers)};
        std::cout << format_time() << " Highest canonical block number " << highest_block << std::endl;
        if (!highest_block || highest_block < po_from_block) {
            throw std::logic_error("No blocks to process within the requested range");
        }

        // Checks cli args consistency
        po_to_block = (po_to_block < highest_block) ? po_to_block : highest_block;
        if (po_to_block <= po_from_block) {
        }

        // Try allocate enough memory space to fit all cananonical header hashes
        // which need to be processed
        {
            void* mem{std::calloc(((po_to_block - po_from_block) + 1), kHashLength)};
            if (!mem) {
                // not enough space to store all
                throw std::runtime_error("Can't allocate enough memory for headers");
            }
            canonical_headers = static_cast<evmc::bytes32*>(mem);
        }

        // Scan headers buckets to collect all canonical headers
        canonical_headers_count = load_canonical_headers(headers, po_from_block, po_to_block, canonical_headers);
        headers->close();
        if (!canonical_headers) {
            // Nothing to process
            throw std::runtime_error(" No canonical headers collected.");
        }
        std::cout << format_time() << " Collected " << canonical_headers_count << " canonical headers" << std::endl;
        std::cout << format_time() << " Opening block bodies bucket " << std::endl;

        {
            MDB_val key, data;
            int rc{0};

            // Open bodies bucket and iterate to load transactions (if any in the block)
            lmdb_bodies = lmdb_txn->open(db::bucket::kBlockBodies);  // Throws on error
            size_t bodies_records{0};
            (void)lmdb_bodies->get_rcount(&bodies_records);
            if (!bodies_records) {
                throw std::runtime_error("Bodies bucket is empty");
            }

            uint32_t percent{0};
            uint32_t percent_step{5};  // 5% increment among batches
            size_t batch_size{canonical_headers_count / (100 / percent_step)};

            // Set to first key which is initial block number
            // plus canonical hash
            Bytes block_key(40, '\0');
            boost::endian::store_big_u64(&block_key[0], po_from_block);
            memcpy((void*)&block_key[8], (void*)&canonical_headers[0], kHashLength);
            key.mv_data = (void*)&block_key[0];
            key.mv_size = 40;

            std::cout << format_time() << " Scanning bodies ... " << std::endl;
            rc = lmdb_bodies->seek_exact(&key, &data);
            uint64_t required_block_num{po_from_block};

            for (uint64_t i = 0; !should_stop_ && i <= canonical_headers_count && rc == MDB_SUCCESS;
                 i++, required_block_num++) {
                while (!should_stop_ && rc == MDB_SUCCESS) {
                    ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
                    uint64_t detected_block_num{boost::endian::load_big_u64(&v[0])};

                    if (detected_block_num < required_block_num) {
                        // We're behind with bodies wrt headers
                        rc = lmdb_bodies->get_next(&key, &data);
                        continue;
                    } else if (detected_block_num > required_block_num) {
                        // We're ahead with bodies wrt headers
                        break;
                    }

                    // Check header hash is the same
                    if (memcmp((void*)&v[8], (void*)&canonical_headers[i], 32) == 0) {
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

                            // Should we overflow the batch queue dispatch the work
                            // accumulated so far to the recoverer thread
                            if ((batchTxsCount + body.transactions.size()) > po_batch_size) {
                                // Do any of workers threads returned an error ?
                                if (workers_thread_error_) {
                                    throw std::runtime_error("Error occurred in child worker thread");
                                }

                                if (po_debug) {
                                    std::cout << format_time() << " DBG : dispatching " << batchTxsCount
                                              << " work packages to recoverer #" << nextRecovererId << std::endl;
                                }
                                recoverers_.at(nextRecovererId)->set_work(process_batch_id++, recoverPackages);
                                recoverers_.at(nextRecovererId)->kick();
                                workers_in_flight++;
                                batchTxsCount = 0;
                                if (++nextRecovererId == (uint32_t)recoverers_.size()) {
                                    /*
                                     * All threads in the pool have been fed and are in flight
                                     * Here we have to wait for all of them to complete
                                     * their flushing to avoid overlapping for db reads
                                     * and writes
                                     */
                                    ready_for_write.store(true, std::memory_order_relaxed);
                                    ready_for_write_cv.notify_all();
                                    while (workers_in_flight != 0) {
                                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                                    }
                                    ready_for_write.store(false, std::memory_order_relaxed);
                                    nextRecovererId = 0;
                                }
                            }

                            // Enqueue Txs
                            process_txs_for_signing(config, required_block_num, body, recoverPackages);

                            // Increment number of accumulated transactions
                            total_transactions += body.transactions.size();
                            batchTxsCount += body.transactions.size();
                        }
                    }

                    // Eventually move to next block
                    rc = lmdb_bodies->get_next(&key, &data);
                }

                batch_size--;
                if (!batch_size) {
                    batch_size = canonical_headers_count / (100 / percent_step);
                    percent += percent_step;
                    std::cout << format_time() << " ... " << percent << "%. Current block " << required_block_num
                              << " Detected transactions " << total_transactions << std::endl;
                }
            }

            // Should we have a partially filled work package deliver it now
            if (batchTxsCount) {
                recoverers_.at(nextRecovererId)->set_work(process_batch_id, recoverPackages);
                recoverers_.at(nextRecovererId)->kick();
                workers_in_flight++;
                ready_for_write.store(true, std::memory_order_relaxed);
                while (workers_in_flight != 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }

            lmdb_bodies->close();
        }

        std::cout << format_time() << " Bodies scan " << (should_stop_ ? "aborted. " : "completed.")
                  << " Detected transactions " << total_transactions << std::endl;

    } catch (db::lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << format_time() << " Unexpected error : " << ex.what() << " " << ex.err() << std::endl;
        main_thread_error_ = true;
    } catch (std::runtime_error& ex) {
        // This handles runtime logic errors
        // eg. trying to open two rw txns
        std::cout << format_time() << " Unexpected error : " << ex.what() << std::endl;
        main_thread_error_ = true;
    }

    // Stop all recoverers
    stop_workers(recoverers_);
    lmdb_senders->close();

    int rc{0};
    if (lmdb_txn) {
        if (!main_thread_error_ && !po_dry && !should_stop_) {
            rc = lmdb_txn->commit();
            if (!rc) lmdb_env->sync(true);
        } else {
            lmdb_txn->abort();
        }
        if (rc) {
            std::cout << format_time() << "Unable to commit work " << mdb_strerror(rc) << std::endl;
        }
    }
    if (lmdb_env && lmdb_env->is_opened()) {
        lmdb_env->close();
    }

    return (main_thread_error_ ? -1 : 0);
}
