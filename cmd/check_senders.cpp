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
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/chrono/chrono.hpp>
#include <boost/filesystem.hpp>
#include <csignal>
#include <ethash/keccak.hpp>
#include <iostream>
#include <silkworm/chain/block_chain.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/common/worker.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/db/lmdb.hpp>
#include <silkworm/db/bucket.hpp>
#include <silkworm/db/util.hpp>
#include <string>

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


namespace bch = boost::chrono;
namespace bfs = boost::filesystem;
using namespace silkworm;

bool shouldStop{false};
int errorCode{0};
constexpr intx::uint256 uint256_zero{intx::uint256(0)};

void sig_handler(int signum) {
    (void)signum;
    std::cout << std::endl << "Request for termination intercepted. Stopping ..." << std::endl << std::endl;
    shouldStop = true;
}

unsigned get_host_cpus() {
#if defined(__linux__)
    long out{sysconf(_SC_NPROCESSORS_ONLN)};
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

bool set_thread_core(unsigned int coreId, unsigned int coresNum) {
#if defined(__linux__)
    cpu_set_t cpuset{};
    CPU_ZERO(&cpuset);
    CPU_SET((coreId % coresNum), &cpuset);

    int err{sched_setaffinity(0, sizeof(cpuset), &cpuset)};
    if (err != 0) {
        std::cerr << "Could not bind thread " << std::this_thread::get_id() << " to cpu " << coreId << std::endl;
    }
#else
    DWORD_PTR dwThreadAffinityMask = 1i64 << (coreId % coresNum);
    DWORD_PTR previous_mask{SetThreadAffinityMask(GetCurrentThread(), dwThreadAffinityMask)};
    if (previous_mask == NULL) {
        std::cerr << "Could not bind thread " << std::this_thread::get_id() << " to cpu " << coreId << std::endl;
        return false;
    }
#endif
    return true;
}

class Recoverer : public silkworm::Worker {
   public:
    Recoverer(uint32_t id, size_t batchSize) : id_(id) {
        // Try allocate enough memory to store
        // results output
        outData_ = static_cast<uint8_t*>(std::calloc(batchSize, kAddressLength));
        if (!outData_) {
            throw std::runtime_error("Unable to allocate memory");
        }
    }

    struct package {
        uint64_t blockNum;
        ethash::hash256 messageHash;
        uint8_t recoveryId;
        intx::uint256 r;
        intx::uint256 s;
    };

    // Provides a container of packages to process
    void set_work(std::vector<package>& packages) {
        boost::mutex::scoped_lock l{mywork_};
        packages_ = std::move(packages);
    }

    // Returns whether or not this worker is busy
    bool is_busy() { return busy_.load(); }

    boost::signals2::signal<void(uint32_t senderId, uint64_t blockFrom, uint64_t blockTo, uint8_t* data, size_t size)>
        signal_finished;

   private:
    uint32_t id_;                      // Current worker identifier
    std::atomic_bool busy_{false};     // Whether the thread is busy processing
    mutable boost::mutex mywork_;      // Work mutex
    std::vector<package> packages_{};  // Work packages to process
    uint8_t* outData_{nullptr};        // Pointer to data where rsults are stored
    uint64_t blockFrom_{0};            // Starting block num of the batch
    uint64_t blockTo_{0};              // End block num of the batch

    // Basic work loop (overrides Worker::work())
    void work() final {

        const boost::posix_time::time_duration kickWaitDuration{boost::posix_time::seconds(1)};

        while (!should_stop()) {

            bool expectedKick{true};
            if (!kicked_.compare_exchange_strong(expectedKick, false, std::memory_order_relaxed)) {
                boost::mutex::scoped_lock l(xwork_);
                kicked_signal_.timed_wait(l, kickWaitDuration);
                continue;
            }

            busy_.store(true);
            {
                // Lock mutex so no other jobs may be set
                boost::mutex::scoped_lock l{mywork_};
                Bytes signature(64, '\0');
                blockFrom_ = blockTo_ = packages_.at(0).blockNum;
                size_t outDataIndex{0};

                // Loop
                for (size_t x{0}; x < packages_.size(); x++) {

                    Recoverer::package rp = packages_.at(x);
                    blockTo_ = rp.blockNum;

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
                    if (!key.has_value() || (int)key->at(0) != 4) {
                        busy_.store(false);
                        throw std::runtime_error("Pub key recover failed at block #" + std::to_string(rp.blockNum));
                    }

                    ethash::hash256 keyHash{ethash::keccak256(key->data() + 1, key->length() - 1)};
                    std::memcpy(&outData_[outDataIndex], &keyHash.bytes[12], kAddressLength);
                    outDataIndex += kAddressLength;
                }
                packages_.clear();

                // Raise finished event
                signal_finished(id_, blockFrom_, blockTo_, outData_, outDataIndex);
            }
            busy_.store(false);
        }
    };


};

void encode_tx_for_signing(Bytes& to, const Transaction& txn, const intx::uint256& chainID) {
    using namespace rlp;

    Header h{true, 0};
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
    } else {
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
    return std::string{buf};
}

std::optional<BlockBody> get_body_from_cursor(uint64_t block_num, std::unique_ptr<db::Cursor>& headers_cursor,
                                              std::unique_ptr<db::Cursor>& bodies_cursor) noexcept {
    BlockBody body{};
    Bytes block_header_key{ db::header_hash_key(block_num) };
    std::optional<db::Entry> block_header_entry{ headers_cursor->seek(block_header_key) };
    if (!block_header_entry) {
        return{};
    }

    Bytes block_body_key{ db::block_key(block_num, block_header_entry->value.substr(0, 32)) };

    // Only interested in block body
    std::optional<db::Entry> block_body_entry{ bodies_cursor->seek(block_body_key) };
    if (!block_body_entry) {
        return{};
    }

    rlp::decode(block_body_entry->value, body);
    return body;

}

std::optional<BlockBody> get_body_from_cursor_next(std::unique_ptr<db::Cursor>& bodies_cursor) {

    // Only interested in block body
    std::optional<db::Entry> block_body_entry{ bodies_cursor->next() };
    if (!block_body_entry) {
        return{};
    }

    BlockBody body{};
    rlp::decode(block_body_entry->value, body);
    return body;


}

int main(int argc, char* argv[]) {
    CLI::App app("Walks Ethereum blocks and recovers senders.");

    std::string po_db_path{silkworm::db::default_path()};
    uint32_t po_num_threads{get_host_cpus() - 1};
    uint32_t po_from_block{1u};
    uint32_t po_to_block{UINT32_MAX};
    size_t po_batch_size{5'000};
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

    // TODO (Andrea) - Stage advance consistency

    // Initialize db
    db::LmdbDatabase db{po_db_path.c_str()};
    BlockChain chain{&db};

    // Get database objects
    auto dbTx{ db.begin_ro_transaction() };
    auto headers_bucket{dbTx->get_bucket(db::bucket::kBlockHeaders)};
    auto bodies_bucket{dbTx->get_bucket(db::bucket::kBlockBodies)};
    auto senders_bucket{dbTx->get_bucket(db::bucket::kSenders)};

    auto headers_cursor{headers_bucket->cursor()};
    auto bodies_cursor{bodies_bucket->cursor()};


    // Temporary file number
    uint32_t tmpFileId{0};
    boost::mutex xwrite_;

    // Recoverer's signal handlers
    boost::function<void(uint32_t senderId, uint64_t blockFrom, uint64_t blockTo, uint8_t * data, size_t size)>
        finishedHandler = [&](uint32_t senderId, uint64_t blockFrom, uint64_t blockTo, uint8_t* data, size_t size) {
        (void)senderId;
        (void)data;
        (void)blockFrom;
        (void)blockTo;

        // Prevent other threads from flushing their results
        boost::mutex::scoped_lock l(xwrite_);

        std::stringstream ss;
        ss << "tmprecover-" << std::fixed << std::setw(6) << std::setfill('0') << tmpFileId++ << ".bin";
        std::string tmpFileName{ss.str()};
        std::ofstream file(tmpFileName.c_str(), std::ios::binary);
        file.write(reinterpret_cast<char*>(data), size);

    };

    // Each recoverer will allocate enough
    // storage space to hold results for
    // a full batch. Worker object is not copyable
    // thus the need of a unique_ptr.
    std::vector<std::unique_ptr<Recoverer>> recoverers_{};
    for (uint32_t i = 0; i < po_num_threads; i++)
    {
        try {
            auto r = std::make_unique<Recoverer>(i, po_batch_size);
            r->signal_finished.connect(boost::bind(finishedHandler, _1, _2, _3, _4, _5));
            recoverers_.push_back(std::move(r));

        } catch (...) {
            std::cerr << "Could not allocate enough memory for Recoverer #" << i << "\n"
                      << "Try lower batch size value or use less rthread" << std::endl;
            return -1;
        }
    }

    // Start recoverers
    for (size_t r = 0; r < recoverers_.size(); r++) {
        std::cout << format_time()  << " Starting recoverer thread #" << r << " ... " << std::endl;
        recoverers_.at(r)->start();
    }

    uint32_t nextRecovererId{0};
    size_t batchTxsCount{0};
    std::vector<Recoverer::package> recoverPackages{};

    bch::time_point start{bch::steady_clock::now()};
    bch::time_point t1{bch::steady_clock::now()};
    uint64_t block_num{po_from_block};
    uint64_t fetched_blocks{0};

    std::optional<BlockBody> bb = get_body_from_cursor(block_num, headers_cursor, bodies_cursor);
    while (!shouldStop && bb && block_num <= po_to_block)
    {
        fetched_blocks++;

        if (bb->transactions.size()) {

            // Should we overflow the batch queue dispatch the work
            // to the recoverer thread
            if (batchTxsCount + bb->transactions.size() >= po_batch_size)
            {
                bch::time_point t2{ bch::steady_clock::now() };
                double elapsedS = (bch::duration_cast<bch::milliseconds>(t2 - t1).count() / 1000.0);
                std::cout << format_time() << " Fetched blocks ≤ " << (fetched_blocks - 1) << " in " << std::fixed
                    << std::setprecision(2) << elapsedS << " s. Dispatching " << batchTxsCount
                    << " tx signatures to thread #" << nextRecovererId << " for address recovery " << std::endl;
                t1 = t2;
                recoverers_.at(nextRecovererId)->set_work(recoverPackages);
                recoverers_.at(nextRecovererId)->kick();
                recoverPackages.clear();
                batchTxsCount = 0;
                if (++nextRecovererId == (uint32_t)recoverers_.size()) {
                    nextRecovererId = 0;
                }
            }

            // TODO - Verify we have to persist returned results

            // Loop block's transactions and enqueue work packages
            for (const silkworm::Transaction& tx : bb->transactions) {

                intx::uint256 txChainID = ecdsa::get_chainid_from_v(tx.v);
                bool txValidSig = silkworm::ecdsa::is_valid_signature(tx.v, tx.r, tx.s, txChainID,
                    chain.config().has_homestead(block_num));

                // Apply EIP-155 unless protected Tx (i.e. v ∈{27,28} thus chainID == 0)
                if (txValidSig && chain.config().has_spurious_dragon(block_num) && txChainID) {
                    if (intx::narrow_cast<uint64_t>(txChainID) != chain.config().chain_id) {
                        txValidSig = false;
                    }
                }

                if (!txValidSig) {
                    std::cerr << "Tx signature validation failed block #" << block_num << "\n"
                        << "r " << intx::hex(tx.r) << "\n"
                        << "s " << intx::hex(tx.s) << "\n"
                        << "v " << intx::hex(tx.v) << "\n"
                        << "Homestead == " << (chain.config().has_homestead(block_num) ? "ON" : "OFF") << "\n"
                        << "Spurious Dragon == " << (chain.config().has_spurious_dragon(block_num) ? "ON" : "OFF")
                        << std::endl;
                    errorCode = -3;
                    break;
                }

                uint8_t txSigRecoveryId = intx::narrow_cast<uint8_t>(ecdsa::get_signature_recovery_id(tx.v, txChainID));

                // Hash the Tx for signing
                Bytes rlp{};
                encode_tx_for_signing(rlp, tx, txChainID);
                ethash::hash256 txMessageHash{ ethash::keccak256(rlp.data(), rlp.length()) };

                Recoverer::package rp{ block_num, txMessageHash, txSigRecoveryId, tx.r, tx.s };

                recoverPackages.push_back(rp);
                batchTxsCount++;

            }

            if (errorCode) {
                break;
            }


        }

        block_num++;
        bb = get_body_from_cursor_next(bodies_cursor);
    }

    //for (; block_num < po_to_block; ++block_num) {

    //    std::optional<BlockBody> bb = get_body_from_cursor(block_num, headers_cursor, bodies_cursor);
    //    if (!bb || shouldStop) {
    //        break;
    //    }

    //    fetched_blocks++;
    //    // If no transactions to process continue
    //    // to next block
    //    if (!bb->transactions.size()) {
    //        continue;
    //    }

    //    //std::vector<evmc::address> senders{ db.get_senders(block_num, bh->hash) };
    //    //if (senders.size() == bh->block.transactions.size()) {
    //    //    // Already processed block ?
    //    //    continue;
    //    //}

    //    // Should we overflow the batch queue dispatch the work
    //    // to the recoverer thread
    //    if (batchTxsCount + bb->transactions.size() >= po_batch_size)
    //    {
    //        bch::time_point t2{ bch::steady_clock::now() };
    //        double elapsedS = (bch::duration_cast<bch::milliseconds>(t2 - t1).count() / 1000.0);
    //        std::cout << format_time() << " Fetched blocks ≤ " << (fetched_blocks - 1) << " in " << std::fixed
    //                  << std::setprecision(2) << elapsedS << " s. Dispatching " << batchTxsCount
    //                  << " tx signatures to thread #" << nextRecovererId << " for address recovery " << std::endl;
    //        t1 = t2;
    //        recoverers_.at(nextRecovererId)->set_work(recoverPackages);
    //        recoverers_.at(nextRecovererId)->kick();
    //        recoverPackages.clear();
    //        batchTxsCount = 0;
    //        if (++nextRecovererId == (uint32_t)recoverers_.size()) {
    //            nextRecovererId = 0;
    //        }
    //    }

    //    // TODO - Verify we have to persist returned results

    //    // Loop block's transactions and enqueue work packages
    //    for (const silkworm::Transaction& tx : bb->transactions) {

    //        intx::uint256 txChainID = ecdsa::get_chainid_from_v(tx.v);
    //        bool txValidSig = silkworm::ecdsa::is_valid_signature(tx.v, tx.r, tx.s, txChainID,
    //                                                              chain.config().has_homestead(block_num));

    //        // Apply EIP-155 unless protected Tx (i.e. v ∈{27,28} thus chainID == 0)
    //        if (txValidSig && chain.config().has_spurious_dragon(block_num) && txChainID) {
    //            if (intx::narrow_cast<uint64_t>(txChainID) != chain.config().chain_id) {
    //                txValidSig = false;
    //            }
    //        }

    //        if (!txValidSig) {
    //            std::cerr << "Tx signature validation failed block #" << block_num << "\n"
    //                      << "r " << intx::hex(tx.r) << "\n"
    //                      << "s " << intx::hex(tx.s) << "\n"
    //                      << "v " << intx::hex(tx.v) << "\n"
    //                      << "Homestead == " << (chain.config().has_homestead(block_num) ? "ON" : "OFF") << "\n"
    //                      << "Spurious Dragon == " << (chain.config().has_spurious_dragon(block_num) ? "ON" : "OFF")
    //                      << std::endl;
    //            errorCode = -3;
    //            break;
    //        }

    //        uint8_t txSigRecoveryId = intx::narrow_cast<uint8_t>(ecdsa::get_signature_recovery_id(tx.v, txChainID));

    //        // Hash the Tx for signing
    //        Bytes rlp{};
    //        encode_tx_for_signing(rlp, tx, txChainID);
    //        ethash::hash256 txMessageHash{ethash::keccak256(rlp.data(), rlp.length())};

    //        Recoverer::package rp{block_num, txMessageHash, txSigRecoveryId, tx.r, tx.s};

    //        recoverPackages.push_back(rp);
    //        batchTxsCount++;

    //    }

    //    if (errorCode) {
    //        break;
    //    }

    //}

    // Should we have any partially filled batch deliver it now
    if (batchTxsCount)
    {
        bch::time_point t2{ bch::steady_clock::now() };
        double elapsedS = (bch::duration_cast<bch::milliseconds>(t2 - t1).count() / 1000.0);
        std::cout << format_time() << " Fetched blocks ≤ " << (fetched_blocks - 1) << " in " << std::fixed
            << std::setprecision(2) << elapsedS << " s. Dispatching " << batchTxsCount
            << " tx signatures to thread #" << nextRecovererId << " for address recovery " << std::endl;

        recoverers_.at(nextRecovererId)->set_work(recoverPackages);
        recoverers_.at(nextRecovererId)->kick();
        recoverPackages.clear();
        batchTxsCount = 0;
    }

    // Stop all recoverers
    for (size_t r = 0; r < recoverers_.size(); r++) {
        std::cout << format_time() << " Waiting for recoverer thread #" << r << " to complete ...";
        recoverers_.at(r)->stop(true);
        std::cout << " Done !" << std::endl;
    }

    std::cout << format_time() << " Blocks (" << po_from_block << " ... " << block_num << "] have been processed 😅\n"
              << "Overall time " << std::fixed << std::setprecision(2)
              << (bch::duration_cast<bch::milliseconds>(bch::steady_clock::now() - start).count() / 1000.0) << " s"
              << std::endl;

    return errorCode;
}
