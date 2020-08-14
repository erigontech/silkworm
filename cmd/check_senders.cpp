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

#include <csignal>

#include <CLI/CLI.hpp>

#include <boost/chrono/chrono.hpp>
#include <boost/filesystem.hpp>

#include <ethash/keccak.hpp>

#include <iostream>
#include <silkworm/db/lmdb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/chain/block_chain.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <string>

namespace bch = boost::chrono;
namespace bfs = boost::filesystem;
using namespace silkworm;

bool shouldStop{ false };

void sigHandler(int signum) {
  (void)signum;
  std::cout << std::endl
            << "Request for termination intercepted. Stopping ..." << std::endl
            << std::endl;
  shouldStop = true;
}

void encodeTxforSigning(Bytes& to, const Transaction& txn, const intx::uint256& chainID) {

    using namespace rlp;

    Header h{ true, 0 };
    h.payload_length += length(txn.nonce);
    h.payload_length += length(txn.gas_price);
    h.payload_length += length(txn.gas_limit);
    h.payload_length += txn.to ? (kAddressLength + 1) : 1;
    h.payload_length += length(txn.value);
    h.payload_length += length(txn.data);
    if (chainID)
    {
        h.payload_length += length(chainID);
        h.payload_length += length(intx::uint256(0));
        h.payload_length += length(intx::uint256(0));
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

    if (chainID)
    {
        encode(to, chainID);
        encode(to, intx::uint256(0));
        encode(to, intx::uint256(0));
    }

}

int main(int argc, char* argv[]) {

    CLI::App app("Walks Ethereum blocks and recovers senders.");

    std::string po_db_path{ silkworm::db::default_path() };
    uint32_t po_from_block{ 1u };
    uint32_t po_to_block{ UINT32_MAX };
    bool po_debug{ false };
    CLI::Range range32(1u, UINT32_MAX);

    // Check whether or not default db_path exists and
    // has some files in it

    bfs::path db_path(po_db_path);
    CLI::Option* db_path_set =
        app.add_option("--db", po_db_path, "Path to chain db", true)->check(CLI::ExistingDirectory);
    if (!bfs::exists(db_path) || !bfs::is_directory(db_path) || db_path.empty()) {
      db_path_set->required();
    }

    app.add_flag("-d,--debug", po_debug, "Stops and show data on first occurence");
    app.add_option("--from,-f", po_from_block, "Initial block number to process (inclusive)", true)
        ->check(range32);
    app.add_option("--to,-t", po_to_block, "Final block number to process (exclusive)", true)
        ->check(range32);

    CLI11_PARSE(app, argc, argv);

    signal(SIGINT, sigHandler);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    db_path = bfs::path(po_db_path);
    if (db_path.empty()) {
      std::cerr << "Provided --db [" << po_db_path << "] is an empty directory" << std::endl
                << "Try --help for help" << std::endl;
      return -1;
    }

    db::LmdbDatabase db{po_db_path.c_str()};
    BlockChain chain{&db};

    bch::time_point start{bch::steady_clock::now()};
    bch::time_point t1{bch::steady_clock::now()};

    uint64_t block_num{po_from_block};
    uint64_t processed_txs{0};
    uint64_t processed_blks{0};

    Bytes message(32, '\0');
    Bytes signature(64, '\0');
    bool validSignature{false};

    for (; block_num < po_to_block; ++block_num, ++processed_blks) {
      std::optional<BlockWithHash> bh = db.get_block(block_num);
      if (!bh || shouldStop) {
        break;
      }

      // Loop block's transactions
      for (silkworm::Transaction tx : bh->block.transactions) {
        auto txChainID = ecdsa::ComputeChainIDfromV(tx.v);
        validSignature = silkworm::ecdsa::ValidateSignatureValues(
            tx.v, tx.r, tx.s, txChainID, chain.config().has_homestead(block_num));

        // Apply EIP-155 unless protected Tx (i.e. v ∈{27,28} thus chainID == 0)
        if (validSignature && chain.config().has_spurious_dragon(block_num) && txChainID) {
          if (intx::narrow_cast<uint64_t>(txChainID) != chain.config().chain_id) {
            validSignature = false;
          }
        }

        if (!validSignature) {
          std::cerr << "Tx signature validation failed block #" << block_num << std::endl;
          std::cerr << "r " << intx::hex(tx.r) << std::endl;
          std::cerr << "s " << intx::hex(tx.s) << std::endl;
          std::cerr << "v " << intx::hex(tx.v) << std::endl;
          std::cerr << "Homestead == " << (chain.config().has_homestead(block_num) ? "ON" : "OFF") << std::endl;
          std::cerr << "Spurious Dragon == " << (chain.config().has_spurious_dragon(block_num) ? "ON" : "OFF") << std::endl;
          return -3;
        }

        auto recoveryID =
            intx::narrow_cast<uint8_t>(ecdsa::GetSignatureRecoveryID(tx.v, txChainID));

        // Hash the Tx for signing
        Bytes rlp{};
        encodeTxforSigning(rlp, tx, txChainID);
        ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.length())};
        std::memcpy(&message[0], hash.bytes, 32);

        // Bytecopy in reverse endianness for r and s
        for (int i{0}; i < 2; i++) {
          std::uint8_t* p = reinterpret_cast<uint8_t*>(i == 0 ? &tx.r.lo : &tx.s.lo);
          int offset{i ? 32 : 0};
          for (int j{0}; j < 32; j++) {
            signature[offset + j] = p[31 - j];
          }
        }

        std::optional<Bytes> key{ecdsa::recover(message, signature, recoveryID)};
        if (!key.has_value() || (int)key->at(0) != 4) {
          std::cout << "Pub key recover failed at block #" << std::dec << block_num << " tx #"
                    << processed_txs << std::endl;
          return -2;
        } else {
          // Ignore the first byte of the public key
          ethash::hash256 hash{ethash::keccak256(key->data() + 1, key->length() - 1)};
          evmc::address out{};
          std::memcpy(out.bytes, &hash.bytes[12], 32 - 12);

          if (po_debug) {
            std::cout << "Block #" << std::dec << block_num << " tx #" << processed_txs
                      << " sender 0x";
            for (size_t i = 0; i < 20; i++) {
              std::cout << std::fixed << std::setw(2) << std::setfill('0') << std::hex
                        << int(out.bytes[i]);
            }
            std::cout << std::endl;
          }
        }

        processed_txs++;
      }

      if (processed_txs && po_debug) {
        return 0;
      }

      if (block_num % 10000 == 0) {
        bch::time_point t2{bch::steady_clock::now()};
        double elapsedS = (bch::duration_cast<bch::milliseconds>(t2 - t1).count() / 1000.0);
        double txperS = processed_txs / elapsedS;
        std::cout << "Processed blocks ≤ " << block_num << " in " << std::fixed
                  << std::setprecision(2) << elapsedS << " s " << processed_txs << " txs ( "
                  << std::fixed << std::setprecision(0) << txperS << " / s )" << std::endl;
        t1 = t2;
        processed_txs = 0;
      }
  }

  std::cout << "Blocks (" << po_from_block << " ... " << block_num << "] have been processed 😅"
            << std::endl;
  std::cout << "Overall time " << std::fixed << std::setprecision(2)
            << (bch::duration_cast<bch::milliseconds>(bch::steady_clock::now() - start).count() /
                1000.0)
            << " s" << std::endl;
  return 0;
}
