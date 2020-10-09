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
#include <boost/interprocess/mapped_region.hpp>
#include <condition_variable>
#include <csignal>
#include <ethash/keccak.hpp>
#include <iostream>
#include <queue>
#include <regex>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/block.hpp>
#include <string>
#include <thread>

namespace bfs = boost::filesystem;
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
    std::cout << std::endl << " Request for termination intercepted. Stopping ..." << std::endl << std::endl;
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

std::optional<uint64_t> parse_size(const std::string& strsize) {
    std::regex pattern{"^([0-9]{1,})([\\ ]{0,})?(B|KB|MB|GB|TB|EB)?$"};
    std::smatch matches;
    if (!std::regex_search(strsize, matches, pattern, std::regex_constants::match_default)) {
        return {};
    };

    uint64_t number{std::strtoull(matches[1].str().c_str(), nullptr, 10)};

    if (matches[3].length() == 0) {
        return {number};
    }
    std::string suffix = matches[3].str();
    if (suffix == "B") {
        return {number};
    } else if (suffix == "KB") {
        return {number * (1ull << 10)};
    } else if (suffix == "MB") {
        return {number * (1ull << 20)};
    } else if (suffix == "GB") {
        return {number * (1ull << 30)};
    } else if (suffix == "TB") {
        return {number * (1ull << 40)};
    } else if (suffix == "EB") {
        return {number * (1ull << 50)};
    } else {
        return {};
    }
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
    }

    // Returns whether or not this worker is busy
    bool is_busy() { return busy_.load(); }

    // Pulls results from worker
    std::vector<std::pair<uint64_t, MDB_val>>& get_results(void) { return myresults_; };

    // Signal to connected handlers the task has completed
    boost::signals2::signal<void(uint32_t sender_id, uint32_t batch_id, bool has_error)> signal_completed;

   private:
    uint32_t id_;                                            // Current worker identifier
    bool debug_;                                             // Whether or not display debug info
    std::atomic_bool busy_{false};                           // Whether the thread is busy processing
    mutable std::mutex mywork_;                              // Work mutex
    std::vector<package> packages_{};                        // Work packages to process
    uint32_t current_batch_id_{0};                           // Identifier of the batch being processed
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

            if (debug_) {
                std::cout << format_time() << " DBG : worker #" << id_ << " started batch #" << current_batch_id_
                          << std::endl;
            };

            busy_.store(true);
            {
                // Lock mutex so no other jobs may be set
                std::unique_lock l{mywork_};
                myresults_.clear();

                Bytes signature(64, '\0');
                uint64_t current_block{packages_.at(0).blockNum};
                size_t block_result_offset{0};
                size_t block_result_length{0};

                // Loop
                for (size_t x{0}; x < packages_.size() && !recovery_error_; x++) {
                    Recoverer::package rp = packages_.at(x);

                    // On block switching store the results
                    if (current_block != rp.blockNum) {
                        MDB_val result{block_result_length, (void*)&mydata_[block_result_offset]};
                        myresults_.push_back({current_block, result});
                        block_result_offset += block_result_length;
                        block_result_length = 0;
                        current_block = rp.blockNum;
                        if (should_stop_) break;
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
                        std::memcpy(&mydata_[block_result_offset + block_result_length],
                                    &keyHash.bytes[sizeof(keyHash) - kAddressLength], kAddressLength);
                        block_result_length += kAddressLength;
                    } else {
                        std::cout << format_time() << " Recoverer #" << id_ << " "
                                  << "Public key recovery failed at block #" << rp.blockNum << std::endl;
                        recovery_error_ = true;
                        break;  // No need to process other txns
                    }
                }

                // Store results for last block
                if (block_result_length && !recovery_error_) {
                    MDB_val result{block_result_length, (void*)&mydata_[block_result_offset]};
                    myresults_.push_back({current_block, result});
                }

                // Raise finished event
                signal_completed(id_, current_batch_id_, recovery_error_);
                if (debug_) {
                    std::cout << format_time() << " DBG : worker #" << id_ << " completed batch #" << current_batch_id_
                              << std::endl;
                };
                packages_.clear();  // Clear here. Next set_work will swap the cleaned container to master thread
            }

            busy_.store(false);
        }

        std::free(mydata_);
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

void stop_workers(std::vector<std::unique_ptr<Recoverer>>& workers, bool wait) {
    for (size_t r = 0; r < workers.size(); r++) {
        if (workers.at(r)->get_state() == Worker::WorkerState::kStarted) {
            std::cout << format_time() << " Stopping worker thread #" << r << std::endl;
            workers.at(r)->stop(wait);
        }
    }
}

std::optional<uint64_t> get_highest_canonical_header(std::unique_ptr<lmdb::Table>& headers) {
    size_t count{0};
    lmdb::err_handler(headers->get_rcount(&count));
    if (!count) {
        return {};
    }

    MDB_val key, data;
    int rc{headers->get_last(&key, &data)};
    while (!should_stop_ && rc == MDB_SUCCESS) {
        ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
        if (v[8] != 'n') {
            headers->get_prev(&key, &data);
            continue;
        }
        return {boost::endian::load_big_u64(&v[0])};
    }
    return {};
}

uint64_t load_canonical_headers(std::unique_ptr<lmdb::Table>& headers, uint64_t from, uint64_t to, evmc::bytes32* out) {
    uint64_t retvar{0};

    // Locate starting canonical block selected
    // and navigate headers
    MDB_val key, data;
    Bytes header_key(9, 'n');
    boost::endian::store_big_u64(&header_key[0], from);
    key.mv_data = (void*)&header_key[0];
    key.mv_size = header_key.length();

    uint32_t percent{0};
    uint32_t percent_step{5};  // 5% increment among batches
    size_t batch_size{(to - from + 1) / (100 / percent_step)};

    std::cout << format_time() << " Locating canonical header at height " << from << std::endl;
    bool eof{false};
    int rc{headers->seek_exact(&key, &data)};
    if (!rc) std::cout << format_time() << " Scanning canonical headers ... " << std::endl;
    while (!should_stop_ && !eof && rc == MDB_SUCCESS) {
        // Canonical header key is 9 bytes (8 blocknumber + 'n')
        if (key.mv_size == header_key.length()) {
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
                batch_size = (to - from + 1) / (100 / percent_step);
                percent += percent_step;
                std::cout << format_time() << " ... " << std::right << std::setw(3) << std::setfill(' ') << percent
                          << " %" << std::endl;
            }
        }
        if (!eof) rc = headers->get_next(&key, &data);
    }

    return (should_stop_ ? 0 : retvar);
}

// Writes batch results to db
size_t write_results(std::queue<std::pair<uint32_t, uint32_t>>& batches, std::mutex& batches_mtx,
                     std::vector<std::unique_ptr<Recoverer>>& workers, evmc::bytes32* headers,
                     std::unique_ptr<lmdb::Table>& senders, uint64_t initial_block) {
    size_t ret{0};
    std::vector<std::pair<uint64_t, MDB_val>> results{};

    do {
        // Loop all completed batches until queue
        // empty. Other batches may complete while
        // writing of batch is in progress
        std::unique_lock l{batches_mtx};
        if (batches.empty()) break;
        std::pair<uint32_t, uint32_t> item{batches.front().first, batches.front().second};
        batches.pop();
        l.unlock();

        // Pull result from proper worker
        std::swap(results, workers.at(item.first)->get_results());

        // Append results to senders table
        int rc{0};
        Bytes senders_key(40, '\0');
        MDB_val key{40, (void*)&senders_key[0]};
        for (auto& result : results) {
            boost::endian::store_big_u64(&senders_key[0], result.first);
            memcpy((void*)&senders_key[8], (void*)&headers[result.first - initial_block], kHashLength);
            rc = senders->put_append(&key, &result.second);
            if (rc) {
                throw lmdb::exception(rc, mdb_strerror(rc));
            }
            ret += (key.mv_size + result.second.mv_size);
        }
        results.clear();

    } while (true);

    return ret;
}

// Executes the recovery stage
int do_recover(app_options_t& options) {
    std::shared_ptr<lmdb::Environment> lmdb_env{nullptr};  // Main lmdb environment
    std::unique_ptr<lmdb::Transaction> lmdb_txn{nullptr};  // Main lmdb transaction
    std::unique_ptr<lmdb::Table> lmdb_headers{nullptr};    // Block headers table
    std::unique_ptr<lmdb::Table> lmdb_bodies{nullptr};     // Block bodies table
    std::unique_ptr<lmdb::Table> lmdb_senders{nullptr};    // Transaction senders table
    ChainConfig config{kMainnetConfig};                    // Main net config flags
    evmc::bytes32* canonical_headers{nullptr};             // Storage space for canonical headers
    uint64_t canonical_headers_count{0};                   // Overall number of canonical headers collected
    std::vector<Recoverer::package> recoverPackages{};     // Where to store work packages for recoverers

    uint32_t next_batch_id{0};                   // Batch identifier sent to recoverer thread
    size_t batch_size{0};                        // Progressive number of delivered work
    std::atomic<uint32_t> expected_batch_id{0};  // Holder of queue flushing order
    std::queue<std::pair<uint32_t, uint32_t>>
        batches_completed{};           // Queue of batches completed waiting to be written on disk
    std::mutex batches_completed_mtx;  // Guards the queue
    size_t bytes_written{0};           // Total bytes written

    uint32_t next_worker_id{0};                  // Used to serialize the dispatch of works to threads
    std::atomic<uint32_t> workers_in_flight{0};  // Number of workers in flight
    uint64_t total_transactions{0};              // Overall number of transactions processed

    // Recoverer's signal handlers
    boost::function<void(uint32_t, uint32_t, bool)> finishedHandler =
        [&expected_batch_id, &batches_completed, &batches_completed_mtx, &workers_in_flight](
            uint32_t sender_id, uint32_t batch_id, bool has_error) {
            // Ensure threads flush in the right order to preserve key sorting
            // Threads waits for its ticket before flushing
            while (expected_batch_id.load(std::memory_order_relaxed) != batch_id) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // Store error condition if applicabile
            if (has_error) workers_thread_error_.store(true);

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
        auto worker = std::make_unique<Recoverer>(i, (options.batch_size * kAddressLength), options.debug);
        worker->signal_completed.connect(boost::bind(finishedHandler, _1, _2, _3));
        recoverers_.push_back(std::move(worker));
    }

    // Start recoverers (here occurs allocation)
    if (!start_workers(recoverers_)) {
        std::cout << format_time() << " Unable to start required recoverers" << std::endl;
        stop_workers(recoverers_, true);
        recoverers_.clear();
        return -1;
    }

    try {
        // Open db and start transaction
        lmdb::options opts{};
        opts.map_size = options.mapsize;

        lmdb_env = lmdb::get_env(options.datadir.c_str(), opts, /* forwriting=*/true);
        lmdb_txn = lmdb_env->begin_rw_transaction();
        lmdb_senders = lmdb_txn->open(db::table::kSenders, MDB_CREATE);  // Throws on error
        lmdb_headers = lmdb_txn->open(db::table::kBlockHeaders);         // Throws on error
        lmdb_bodies = lmdb_txn->open(db::table::kBlockBodies);           // Throws on error

        size_t rcount{0};

        // Have canonical block headers ?
        std::cout << format_time() << " Checking canonical headers ..." << std::endl;
        auto mostrecent_header = get_highest_canonical_header(lmdb_headers);
        if (!mostrecent_header.has_value()) {
            throw std::logic_error("Can't locate most recent canonical header. Aborting");
        }
        std::cout << format_time() << " Most recent header number " << *mostrecent_header << std::endl;
        options.block_to =
            (options.block_to > (uint32_t)(*mostrecent_header) ? (uint32_t)(*mostrecent_header) : options.block_to);

        // Have block bodies ?
        std::cout << format_time() << " Checking block bodies ..." << std::endl;
        lmdb::err_handler(lmdb_bodies->get_rcount(&rcount));
        if (!rcount) {
            throw std::logic_error("Block bodies table empty. Aborting");
        }

        /*
         * Senders table has only sorted keys from canonical headers
         * By consequence po_from_block is the last block
         * stored in senders + 1.
         * If po_replay flag is set then po_from_block can be anything
         * below that value
         */
        std::cout << format_time() << " Checking transaction senders ..." << std::endl;
        lmdb::err_handler(lmdb_senders->get_rcount(&rcount));
        if (rcount) {
            MDB_val key, data;
            lmdb::err_handler(lmdb_senders->get_last(&key, &data));
            ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
            auto mostrecent_sender = boost::endian::load_big_u64(&v[0]);
            if (options.block_from <= mostrecent_sender) {
                if (options.replay) {
                    if (options.block_from == 1u) {
                        std::cout << format_time() << " Clearing senders table ... " << std::endl;
                        lmdb::err_handler(lmdb_senders->clear());
                        lmdb_senders.reset();
                        lmdb_senders = lmdb_txn->open(db::table::kSenders, MDB_CREATE);
                    } else {
                        // Delete all senders records with key >= po_from_block
                        std::cout << format_time() << " Deleting senders table from block " << options.block_from
                                  << " ..." << std::endl;
                        Bytes senders_key(40, '\0');
                        boost::endian::store_big_u64(&senders_key[0], options.block_from);
                        key.mv_data = (void*)&senders_key[0];
                        key.mv_size = senders_key.length();
                        int rc{lmdb_senders->seek(&key, &data)};
                        lmdb::err_handler(rc);
                        while (!should_stop_ && rc == MDB_SUCCESS) {
                            lmdb::err_handler(lmdb_senders->del_current(false));
                            rc = lmdb_senders->get_next(&key, &data);
                            if (rc && rc != MDB_NOTFOUND) {
                                lmdb::err_handler(rc);
                            }
                        }
                    }
                } else {
                    std::cout << format_time() << " Overriding requested initial block " << options.block_from
                              << " with " << (mostrecent_sender + 1) << std::endl;
                    options.block_from = (uint32_t)(mostrecent_sender + 1);
                }
            } else {
                std::cout << format_time() << " Overriding requested initial block " << options.block_from << " with "
                          << (mostrecent_sender + 1) << std::endl;
                options.block_from = (uint32_t)(mostrecent_sender + 1);
            }

        } else {
            if (options.block_from > 1u) {
                std::cout << format_time() << " Overriding selected initial block " << options.block_from << " with 1"
                          << std::endl;
                options.block_from = 1u;
            }
        }

        std::cout << format_time() << " Processing transactions from block " << options.block_from << " to block "
                  << options.block_to << std::endl;
        if (options.block_from > options.block_to) {
            // There are no blocks to process
            throw std::logic_error("No valid block range selected. Aborting");
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
        canonical_headers_count =
            load_canonical_headers(lmdb_headers, options.block_from, options.block_to, canonical_headers);
        if (!canonical_headers_count) {
            // Nothing to process
            throw std::logic_error("No canonical headers collected.");
        }
        std::cout << format_time() << " Collected " << canonical_headers_count << " canonical headers" << std::endl;

        {
            MDB_val key, data;

            // Set to first key which is initial block number
            // plus canonical hash

            uint64_t current_block{options.block_from};
            uint64_t detected_block{0};
            size_t header_index{0};

            Bytes block_key(40, '\0');
            boost::endian::store_big_u64(&block_key[0], current_block);
            memcpy((void*)&block_key[8], (void*)&canonical_headers[0], kHashLength);
            key.mv_data = (void*)&block_key[0];
            key.mv_size = block_key.length();

            std::cout << format_time() << " Scanning bodies ... " << std::endl;
            int rc{lmdb_bodies->seek_exact(&key, &data)};
            lmdb::err_handler(rc);

            while (!should_stop_) {
                ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
                detected_block = boost::endian::load_big_u64(&v[0]);
                if (detected_block > current_block) {
                    // We assume keys in block bodies are properly sorted
                    throw std::runtime_error("Bad block body sequence. Expected " + std::to_string(current_block) +
                                             " got " + std::to_string(detected_block));
                }
                if (memcmp((void*)&v[8], (void*)&canonical_headers[header_index], 32) != 0) {
                    // We stumbled into a non canonical block (not matching header)
                    // move next and repeat
                    rc = lmdb_bodies->get_next(&key, &data);
                    if (rc) {
                        if (rc == MDB_NOTFOUND) break;  // Reached the end of records for bodies table
                        lmdb::err_handler(rc);          // Something bad happened
                    }
                }

                // We get here with a matching block number + header
                // Process it if not empty (ie 0 transactions and 0 ommers)
                if (data.mv_size > 3) {
                    // Actually rlp-decoding the whole block adds a
                    // little overhead as transactions are decoded as
                    // well as ommers which actually are not needed
                    // in this scope. Worth optimize it ?
                    ByteView bv{static_cast<uint8_t*>(data.mv_data), data.mv_size};
                    BlockBody body{};
                    rlp::decode(bv, body);

                    // Should we overflow the batch queue dispatch the work
                    // accumulated so far to the recoverer thread
                    if ((batch_size + body.transactions.size()) > options.batch_size) {
                        // If all workers busy no other option than to wait for
                        // at least one free slot
                        while (workers_in_flight == options.numthreads) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        }

                        // Throw if any error from workers
                        if (workers_thread_error_) throw std::runtime_error("Error from worker thread");

                        // Write results to db (if any)
                        bytes_written += write_results(batches_completed, batches_completed_mtx, recoverers_,
                                                       canonical_headers, lmdb_senders, options.block_from);

                        // Dispatch new task to worker
                        total_transactions += recoverPackages.size();
                        recoverers_.at(next_worker_id)->set_work(next_batch_id++, recoverPackages);
                        recoverers_.at(next_worker_id)->kick();
                        workers_in_flight++;
                        batch_size = 0;

                        std::cout << format_time() << " Block " << std::right << std::setw(9) << std::setfill(' ')
                                  << current_block << " Transactions " << std::right << std::setw(12)
                                  << std::setfill(' ') << total_transactions << " Workers " << workers_in_flight << "/"
                                  << options.numthreads << std::endl;

                        if (++next_worker_id == options.numthreads) {
                            next_worker_id = 0;
                        }
                    }

                    // Enqueue Txs in current batch
                    process_txs_for_signing(config, current_block, body, recoverPackages);
                    batch_size += body.transactions.size();
                }

                // After processing move to next block number and header
                if (++header_index == canonical_headers_count) {
                    // We'd go beyond collected canonical headers
                    break;
                }
                rc = lmdb_bodies->get_next(&key, &data);
                if (rc) {
                    if (rc == MDB_NOTFOUND) break;  // Reached the end of records for bodies table
                    lmdb::err_handler(rc);          // Something bad happened
                }
                ++current_block;
            }

            // Should we have a partially filled work package deliver it now
            if (batch_size && !should_stop_) {
                // If all workers busy no other option than to wait for
                // at least one free slot
                while (workers_in_flight == options.numthreads) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                // Throw if any error from workers
                if (workers_thread_error_) throw std::runtime_error("Error from worker thread");

                // Write results to db (if any)
                bytes_written += write_results(batches_completed, batches_completed_mtx, recoverers_, canonical_headers,
                                               lmdb_senders, options.block_from);

                total_transactions += recoverPackages.size();
                recoverers_.at(next_worker_id)->set_work(next_batch_id, recoverPackages);
                recoverers_.at(next_worker_id)->kick();
                workers_in_flight++;
                batch_size = 0;

                std::cout << format_time() << " Block " << std::right << std::setw(9) << std::setfill(' ')
                          << current_block << " Transactions " << std::right << std::setw(12) << std::setfill(' ')
                          << total_transactions << " Workers " << workers_in_flight << "/" << options.numthreads
                          << std::endl;
            }

            // Wait for all workers to complete and write their results
            while (workers_in_flight != 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (!should_stop_) {
                bytes_written += write_results(batches_completed, batches_completed_mtx, recoverers_, canonical_headers,
                                               lmdb_senders, options.block_from);
            }
        }

        std::cout << format_time() << " Bodies scan " << (should_stop_ ? "aborted! " : "completed!") << std::endl;

    } catch (lmdb::exception& ex) {
        // This handles specific lmdb errors
        std::cout << format_time() << " Unexpected error : " << ex.err() << " " << ex.what() << std::endl;
        main_thread_error_ = true;
    } catch (std::logic_error& ex) {
        std::cout << format_time() << " " << ex.what() << std::endl;
        main_thread_error_ = true;
    } catch (std::runtime_error& ex) {
        // This handles runtime logic errors
        // eg. trying to open two rw txns
        std::cout << format_time() << " Unexpected error : " << ex.what() << std::endl;
        main_thread_error_ = true;
    }

    // Stop all recoverers and close all tables
    stop_workers(recoverers_, true);

    lmdb_senders.reset();
    lmdb_headers.reset();
    lmdb_bodies.reset();

    // free memory
    if (canonical_headers) {
        std::free(canonical_headers);
    }

    // Should we commit ?
    if (!main_thread_error_ && !workers_thread_error_ && !options.rundry && !should_stop_) {
        std::cout << format_time() << " Committing work ( " << bytes_written << " bytes )" << std::endl;
        try {
            lmdb::err_handler(lmdb_txn->commit());
            lmdb::err_handler(lmdb_env->sync());
        } catch (const std::exception& ex) {
            std::cout << format_time() << " Unexpected error : " << ex.what() << std::endl;
            main_thread_error_ = true;
        }
    }

    lmdb_txn.reset();
    lmdb_env.reset();
    std::cout << format_time() << " All done ! " << std::endl;
    return (main_thread_error_ ? -1 : 0);
}

// Prints out info of block's transactions with senders
int do_verify(app_options_t& options) {

    // Adjust params
    if (options.block_to == UINT32_MAX) options.block_to = options.block_from;

    try
    {
        // Open db and start transaction
        lmdb::options lmdb_opts{};
        lmdb_opts.map_size = options.mapsize;
        std::shared_ptr<lmdb::Environment> lmdb_env{lmdb::get_env(options.datadir.c_str(), lmdb_opts)};
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

        for (uint32_t block_num = options.block_from; block_num <= options.block_to; block_num++)
        {
            std::cout << "Reading block #" << block_num << std::endl;
            std::optional<BlockWithHash> bh{db::read_block(*lmdb_txn, block_num)};
            if (!bh) {
                throw std::logic_error("Could not locate block #" + std::to_string(block_num));
            }

            if (!bh->block.transactions.size()) {
                std::cout << "Block has 0 transactions" << std::endl;
                continue;
            }

            std::vector<evmc::address> senders{db::read_senders(*lmdb_txn, block_num, bh->hash)};
            if (senders.size() != bh->block.transactions.size()) {
                throw std::runtime_error("Senders count does not match transactions count");
            }

            std::cout << std::right << std::setw(4) << std::setfill(' ') << "Tx"
                      << " " << std::left << std::setw(66) << std::setfill(' ') << "Hash"
                      << " " << std::left << std::setw(42) << std::setfill(' ') << "From"
                      << " " << std::left << std::setw(42) << std::setfill(' ') << "To" << std::endl;
            std::cout << std::right << std::setw(4) << std::setfill('-') << ""
                      << " " << std::left << std::setw(66) << std::setfill('-') << ""
                      << " " << std::left << std::setw(42) << std::setfill('-') << ""
                      << " " << std::left << std::setw(42) << std::setfill('-') << "" << std::endl;

            for (size_t i = 0; i < bh->block.transactions.size(); i++)
            {
                Bytes rlp{};
                rlp::encode(rlp, bh->block.transactions.at(i), /*forsigning*/ false, {});
                ethash::hash256 hash{ ethash::keccak256(rlp.data(), rlp.length()) };
                ByteView bv{ hash.bytes,32 };
                std::cout << std::right << std::setw(4) << std::setfill(' ') << i << " 0x" << to_hex(bv) << " 0x"
                          << to_hex(senders.at(i)) << " 0x" << to_hex(*(bh->block.transactions.at(i).to)) << std::endl;
            }

            std::cout << std::endl;
        }

    }
    catch (const std::logic_error& ex) {
        std::cout << ex.what() << std::endl;
        return -1;
    }
    catch (const std::exception& ex)
    {
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

    std::optional<uint64_t> lmdb_mapSize = parse_size(mapSizeStr);
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
    bfs::path db_path = bfs::path(options.datadir);
    if (!bfs::exists(db_path) || !bfs::is_directory(db_path) || bfs::is_empty(db_path)) {
        std::cerr << "Invalid or empty --datadir \"" << options.datadir << "\"" << std::endl
                  << "Try --help for help" << std::endl;
        return -1;
    } else {
        bfs::path db_file = bfs::path(db_path / bfs::path("data.mdb"));
        if (!bfs::exists(db_file) || !bfs::file_size(db_file)) {
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
