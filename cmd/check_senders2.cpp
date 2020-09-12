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
#include <boost/filesystem.hpp>
#include <boost/endian/conversion.hpp>
#include <ethash/keccak.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/db/bucket.hpp>
#include <silkworm/types/block.hpp>

#include <silkworm/crypto/ecdsa.hpp>

#include <string>
#include <csignal>
#include <iostream>

#if defined(__APPLE__) || defined(__MACOSX)
#error "MACOSX not supported yet"
#elif defined(__linux__)
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* we need sched_setaffinity() */
#endif
#include <error.h>
#include <sched.h>
#include <unistd.h>

#include <thread>
#elif defined(_WINDOWS) || defined(_WIN32)
#include <windows.h>
#else
#error "Unsupported OS configuration"
#endif

namespace bfs = boost::filesystem;
using namespace silkworm;

bool shouldStop{false};
constexpr intx::uint256 uint256_zero{ intx::uint256(0) };
int errorCode{0};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    shouldStop = true;
}

unsigned get_host_cpus() {
#if defined(__linux__)
    long out{ sysconf(_SC_NPROCESSORS_ONLN) };
    if (out == -1L) {
        std::cerr << "Error in func " << __FUNCTION__ << " at sysconf(_SC_NPROCESSORS_ONLN) \"" << strerror(errno)
            << "\"" << std::endl;
        return 0;
    }
    return out;
#else
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#endif
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
    const int32_t milliseconds = static_cast<int32_t>(td.total_milliseconds() - ((static_cast<int64_t>(hours) * 3600 + static_cast<int64_t>(minutes) * 60 + seconds) * 1000));
    sprintf(buf, "[%02d-%02d %02d:%02d:%02d.%03d]", month, day, hours, minutes, seconds, milliseconds);
    return std::string{ buf };
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
        boost::mutex::scoped_lock l{mywork_};
        std::swap(packages_, packages);
        current_batch_id_ = batch_id;
        //packages_ = std::move(packages);
    }

    // Returns whether or not this worker is busy
    bool is_busy() { return busy_.load(); }

    boost::signals2::signal<void(uint32_t senderId, std::vector<std::pair<uint64_t, MDB_val>>& results)>
        signal_finished;

   private:
    uint32_t id_;  // Current worker identifier
    bool debug_;
    std::atomic_bool busy_{false};                           // Whether the thread is busy processing
    mutable boost::mutex mywork_;                            // Work mutex
    std::vector<package> packages_{};                        // Work packages to process
    uint32_t current_batch_id_;                              // Identifier of the batch being processed
    size_t mysize_;                                          // Size of the recovery data
    uint8_t* mydata_{nullptr};                               // Pointer to data where rsults are stored
    std::vector<std::pair<uint64_t, MDB_val>> myresults_{};  // Results per block pointing to data area

    // Basic work loop (overrides Worker::work())
    void work() final {

        const boost::posix_time::time_duration kickWaitDuration{boost::posix_time::seconds(1)};

        // Try allocate enough memory to store
        // results output
        mydata_ = static_cast<uint8_t*>(std::calloc(1, mysize_));
        if (!mydata_) {
            throw std::runtime_error("Unable to allocate memory");
        }

        while (!should_stop()) {
            bool expectedKick{true};
            if (!kicked_.compare_exchange_strong(expectedKick, false, std::memory_order_relaxed)) {
                boost::mutex::scoped_lock l(xwork_);
                kicked_signal_.timed_wait(l, kickWaitDuration);
                continue;
            }

            busy_.store(true);
            if (debug_) {
                std::cout << format_time() << " Recoverer #" << id_ << " starting task with " << packages_.size() << " items " << std::endl;
            }

            {
                // Lock mutex so no other jobs may be set
                boost::mutex::scoped_lock l{mywork_};
                Bytes signature(64, '\0');
                uint64_t current_block{packages_.at(0).blockNum};
                size_t data_offset{0};
                size_t data_length{0};

                // Loop
                for (size_t x{0}; x < packages_.size(); x++) {

                    Recoverer::package rp = packages_.at(x);

                    // On block switching store the results
                    if (current_block != rp.blockNum) {
                        MDB_val result{ data_length, (void*)&mydata_[data_offset] };
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

                    //TODO(Andrea) proper error signalling to master thread

                    if (key.has_value() && (int)key->at(0) == 4) {
                        ethash::hash256 keyHash{ethash::keccak256(key->data() + 1, key->length() - 1)};
                        std::memcpy(&mydata_[data_offset], &keyHash.bytes[12], kAddressLength);
                        data_offset += kAddressLength;
                        data_length += kAddressLength;
                    }
                    else {
                        throw std::runtime_error(" Recoverer #" + std::to_string(id_) + " Pub key recovery failed at block #" + std::to_string(rp.blockNum));
                    }

                }

                // Store results for last block
                if (data_length) {
                    MDB_val result{ data_length, (void*)&mydata_[data_offset] };
                    myresults_.push_back({ current_block, result });
                }

                // Raise finished event
                signal_finished(current_batch_id_, myresults_);

                packages_.clear();
                myresults_.clear();

                busy_.store(false);
            }

            if (debug_) {
                std::cout << format_time() << " Recoverer #" << id_ << " completed task" << std::endl;
            }
        }
    };
};

void encode_tx_for_signing(Bytes& to, const Transaction& txn, const intx::uint256& chainID) {
    using namespace rlp;

    Header h{ true, 0 };
    h.payload_length += length(txn.nonce);
    h.payload_length += length(txn.gas_price);
    h.payload_length += length(txn.gas_limit);
    h.payload_length += txn.to ? (kAddressLength + 1) : 1;
    h.payload_length += length(txn.value);
    h.payload_length += length(txn.data);
    if (chainID) {
        h.payload_length += length(chainID);
        h.payload_length += length(uint256_zero);
        h.payload_length += length(uint256_zero);
    }

    encode_header(to, h);
    encode(to, txn.nonce);
    encode(to, txn.gas_price);
    encode(to, txn.gas_limit);
    if (txn.to) {
        encode(to, txn.to->bytes);
    }
    else {
        to.push_back(kEmptyStringCode);
    }
    encode(to, txn.value);
    encode(to, txn.data);

    if (chainID) {
        encode(to, chainID);
        encode(to, uint256_zero);
        encode(to, uint256_zero);
    }
}

void process_txs_for_signing(ChainConfig& config, uint64_t block_num, BlockBody& body, std::vector<Recoverer::package>& packages) {
    for (const silkworm::Transaction& txn : body.transactions) {

        intx::uint256 txChainID = ecdsa::get_chainid_from_v(txn.v);
        bool is_valid = silkworm::ecdsa::is_valid_signature(txn.v, txn.r, txn.s, txChainID,
            config.has_homestead(block_num));

        // Apply EIP-155 unless protected Tx (i.e. v ∈{27,28} thus chainID == 0)
        if (is_valid && config.has_spurious_dragon(block_num) && txChainID) {
            if (intx::narrow_cast<uint64_t>(txChainID) != config.chain_id) {
                throw std::runtime_error("Got invalid signature in tx for block number " + std::to_string(block_num));
            }
        }

        uint8_t txSigRecoveryId = intx::narrow_cast<uint8_t>(ecdsa::get_signature_recovery_id(txn.v, txChainID));

        // Hash the Tx for signing
        Bytes rlp{};
        encode_tx_for_signing(rlp, txn, txChainID);
        ethash::hash256 txMessageHash{ethash::keccak256(rlp.data(), rlp.length())};
        Recoverer::package rp{ block_num, txMessageHash, txSigRecoveryId, txn.r, txn.s };
        packages.push_back(rp);
    }
}

bool start_workers(std::vector<std::unique_ptr<Recoverer>> &workers) {

    for (size_t r = 0; r < workers.size(); r++) {
        std::cout << format_time() << " Starting worker thread #" << r << std::endl;
        workers.at(r)->start();
        // Wait for thread to init properly
        boost::this_thread::sleep_for(boost::chrono::milliseconds(5));
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

int main(int argc, char* argv[]) {
    CLI::App app("Tests db interfaces.");

    std::string po_db_path{silkworm::db::default_path()};
    uint32_t po_num_threads{ get_host_cpus() - 1 };
    uint32_t po_from_block{ 1u };
    uint32_t po_to_block{ UINT32_MAX };
    size_t po_batch_size{ 50'000 };
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
    app.add_option("--rthreads", po_num_threads, "Number of recovering threads", true)->check(CLI::Range(1u, get_host_cpus() - 1));
    app.add_option("--from,-f", po_from_block, "Initial block number to process (inclusive)", true)->check(range32);
    app.add_option("--to,-t", po_to_block, "Final block number to process (exclusive)", true)->check(range32);
    app.add_option("--batch", po_batch_size, "Number of transactions to process per batch", true)
        ->check(CLI::Range((size_t)1'000, (size_t)100'000'000));

    CLI11_PARSE(app, argc, argv);

    if (!po_from_block) po_from_block = 1u; // Block 0 (genesis) has no transactions

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

    std::shared_ptr<db::lmdb::Env> lmdb_env{nullptr};      // Main lmdb environment
    std::unique_ptr<db::lmdb::Txn> lmdb_txn{nullptr};      // Main lmdb transaction
    std::unique_ptr<db::lmdb::Bkt> lmdb_senders{nullptr};  // Tx Senders bucket
    ChainConfig config{kEtcMainnetChainConfig};            // Main net config flags
    evmc::bytes32* canonical_headers{nullptr};             // Storage space for canonical headers
    uint64_t canonical_headers_count{0};                   // Overall number of canonical headers collected
    std::vector<Recoverer::package> recoverPackages{};     // Where to store work packages for recoverers
    uint32_t process_batch_id{0};                          // Batch identifier sent to recoverer thread
    boost::atomic<uint32_t> flush_batch_id{0};             // Holder of queue flushing order

    uint64_t total_transaction{0};  // Overall number of transactions processed

    // Temporary file number
    uint32_t tmpFileId{ 0 };
    boost::mutex xwrite_;

    // Recoverer's signal handlers
    boost::function<void(uint32_t batch_id, std::vector<std::pair<uint64_t, MDB_val>>& results)>
        finishedHandler = [&](uint32_t batch_id, std::vector<std::pair<uint64_t, MDB_val>>& results) {

        // Ensure threads flush in the right order to preserve key sorting
        // Threads waits for its ticket before flushing
        while (flush_batch_id.load(boost::memory_order::relaxed) != batch_id) {
            boost::this_thread::sleep_for(boost::chrono::milliseconds(1));
        }

        // Prevent other threads from flushing their results
        boost::mutex::scoped_lock l(xwrite_);


        // Accumulate overall size of results data
        void* start_address{ results.at(0).second.mv_data };
        size_t total_size{ 0 };
        for (auto& result : results) {
            total_size += result.second.mv_size;
        }

        // TODO(Andrea)
        // Loop al results and for each block build its key
        // data is already the second member of the tuples returned in results.

        std::stringstream ss;
        ss << "tmprecover-" << std::fixed << std::setw(6) << std::setfill('0') << tmpFileId++ << ".bin";
        std::string tmpFileName{ ss.str() };

        if (po_debug) {
            std::cout << format_time() << " Flushing " << tmpFileName << std::endl;
        }
        std::ofstream file(tmpFileName.c_str(), std::ios::binary);
        file.write(reinterpret_cast<char*>(start_address), total_size);

        // Ready to serve next thread
        flush_batch_id.store(++batch_id, boost::memory_order::relaxed);

    };

    // Each recoverer will allocate enough
    // storage space to hold results for
    // a full batch. Worker object is not copyable
    // thus the need of a unique_ptr.
    std::vector<std::unique_ptr<Recoverer>> recoverers_{};
    for (uint32_t i = 0; i < po_num_threads; i++)
    {
        try {
            auto r = std::make_unique<Recoverer>(i, (po_batch_size * kAddressLength), po_debug);
            r->signal_finished.connect(boost::bind(finishedHandler, _1, _2));
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
        return 0;
    }


    uint32_t nextRecovererId{ 0 };
    size_t batchTxsCount{ 0 };

    // Initialize database
    try {
        lmdb_env = db::get_env(po_db_path.c_str());
        lmdb_txn = lmdb_env->begin_ro_transaction();
    } catch (std::exception& ex) {
        std::cout << format_time() << " Unable to open database. " << ex.what();
        return -1;
    }

    try
    {
        std::cout << format_time() << " Database is " << (lmdb_env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
        {
            MDB_val key, data;
            int rc{0};

            auto headers = lmdb_txn->open(db::bucket::kBlockHeaders);

            size_t headers_records{0};
            (void)headers->get_rcount(&headers_records);

            std::cout << format_time() << " Headers Table has " << headers_records << " records" << std::endl;

            // Dirty way to get last block number (from actually stored headers)
            uint64_t highest_block{0};
            rc = headers->get_last(&key, &data);
            while (!shouldStop && rc == MDB_SUCCESS)
            {
                ByteView v{ static_cast<uint8_t*>(key.mv_data), key.mv_size };
                if (v[8] != 'n') {
                    headers->get_prev(&key, &data);
                    continue;
                }
                highest_block = boost::endian::load_big_u64(&v[0]);
                break;
            }

            std::cout << format_time() << " Highest canonical block number " << highest_block << std::endl;

            // Checks cli args consistency
            if (highest_block < po_from_block)
            {
                // Nothing to process
                headers->close();
                lmdb_txn->abort();
                lmdb_env->close();
                std::cout << format_time() << " Requested initial block " << po_from_block
                          << " greater than highest block available " << highest_block << ". Aborting ..." << std::endl;
                return 0;
            }
            po_to_block = (po_to_block < highest_block) ? po_to_block : highest_block;


            // Try allocate enough memory space to fit all cananonical header hashes
            // which need to be processed
            {
                void* mem{std::calloc(((po_to_block - po_from_block) + 1), kHashLength)};
                if (!mem) {
                    // not enough space to store all
                    throw std::runtime_error("Can't allocate space for canonical hashes");
                }
                canonical_headers = static_cast<evmc::bytes32*>(mem);
            }

            // Locate starting canonical block selected
            // and navigate headers
            Bytes header_key(9, '\0');
            boost::endian::store_big_u64(&header_key[0], po_from_block);
            header_key[8] = 'n';
            key.mv_data = (void*)&header_key[0];
            key.mv_size = 9;

            uint32_t percent{0};
            uint32_t percent_step{5};  // 5% increment among batches
            size_t batch_size{(po_to_block - po_from_block) / (100 / percent_step)};

            std::cout << format_time() << " Locating header at height " << po_from_block << std::endl;
            rc = headers->seek_exact(&key, &data);
            bool headers_eof{false};
            std::cout << format_time() << " Scanning headers ... " << std::endl;
            while (!shouldStop && !headers_eof && rc == MDB_SUCCESS)
            {
                // Canonical header key is 9 bytes (8 blocknumber + 'n')
                if (key.mv_size == 9) {
                    ByteView v{static_cast<uint8_t*>(key.mv_data), key.mv_size};
                    if (v[8] == 'n') {
                        uint64_t header_block = boost::endian::load_big_u64(&v[0]);
                        if (header_block > po_to_block) {
                            headers_eof = true;
                        } else {
                            memcpy((void*)&canonical_headers[header_block - po_from_block], data.mv_data, kHashLength);
                            canonical_headers_count++;
                            batch_size--;
                        }
                    }
                }
                if (!batch_size) {
                    batch_size = (po_to_block - po_from_block) / (100 / percent_step);
                    percent += percent_step;
                    std::cout << format_time() << " ... " << percent << "% " << std::endl;
                }
                rc = headers->get_next(&key, &data);
            }

            std::cout << format_time() << " Collected " << canonical_headers_count << " canonical headers" << std::endl;
            headers->close();
            if (shouldStop || !canonical_headers) {
                // Nothing to process
                lmdb_txn->abort();
                lmdb_env->close();
                return 0;
            }

            // Open bodies bucket and iterate to load transactions (if any in the block)
            auto bodies = lmdb_txn->open(db::bucket::kBlockBodies);
            uint64_t bodies_records{0};
            (void)bodies->get_rcount(&bodies_records);

            batch_size = canonical_headers_count / (100 / percent_step) ;
            percent = 0;
            uint64_t total_transactions{0};

            std::cout << format_time() << " Bodies Table has " << bodies_records << " records." << std::endl;

            // Set to first key which is initial block number
            // plus canonical hash
            Bytes block_key(40, '\0');
            boost::endian::store_big_u64(&block_key[0], po_from_block);
            memcpy((void*)&block_key[8], (void*)&canonical_headers[0], kHashLength);
            key.mv_data = (void*)&block_key[0];
            key.mv_size = 40;

            std::cout << format_time() << " Scanning bodies ... " << std::endl;
            rc = bodies->seek_exact(&key, &data);
            uint64_t block_num{po_from_block};

            for (uint64_t i = 0; !shouldStop && i < canonical_headers_count && rc == MDB_SUCCESS; i++, block_num++)
            {
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
                            if ((batchTxsCount + body.transactions.size()) > po_batch_size)
                            {
                                if (po_debug) {
                                    std::cout << format_time() << " DBG : dispatching " << batchTxsCount
                                              << " work packages to recoverer #" << nextRecovererId << std::endl;
                                }
                                recoverers_.at(nextRecovererId)->set_work(process_batch_id++, recoverPackages);
                                recoverers_.at(nextRecovererId)->kick();
                                batchTxsCount = 0;
                                if (++nextRecovererId == (uint32_t)recoverers_.size()) {
                                    nextRecovererId = 0;
                                }
                            }

                            // Enqueue Txs
                            process_txs_for_signing(config, block_num, body, recoverPackages);

                            // Increment number of accumulated transactions
                            total_transactions += body.transactions.size();
                            batchTxsCount += body.transactions.size();

                        }
                    }

                    // Eventually move to next block
                    rc = bodies->get_next(&key, &data);
                }

                batch_size--;
                if (!batch_size) {
                    batch_size = canonical_headers_count / (100 / percent_step);
                    percent += percent_step;
                    std::cout << format_time() << " ... " << percent << "%. Current block " << block_num << " Detected transactions " << total_transactions << std::endl;
                }

            }

            // Should we have a partially filled work package deliver it now
            if (batchTxsCount) {
                recoverers_.at(nextRecovererId)->set_work(process_batch_id++, recoverPackages);
                recoverers_.at(nextRecovererId)->kick();
            }

            bodies->close();
        }

        std::cout << format_time() << " Bodies scan completed. Detected transactions " << total_transactions
                  << std::endl;

        // Stop all recoverers
        stop_workers(recoverers_);

        lmdb_txn->abort();
        lmdb_env->close();
        std::cout << format_time () << " Database is " << (lmdb_env->is_opened() ? "" : "NOT ") << "opened" << std::endl;
        lmdb_env = nullptr;
    }
    catch (db::lmdb::exception& ex)
    {
        // This handles specific lmdb errors
        std::cout << format_time() << ex.what() << " " << ex.err() << std::endl;
    }
    catch (std::runtime_error& ex)
    {
        // This handles runtime ligic errors
        // eg. trying to open two rw txns
        std::cout << format_time() << ex.what() << std::endl;
    }


    return 0;
}
