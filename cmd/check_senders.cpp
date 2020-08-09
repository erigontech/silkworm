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

#include <boost/chrono/chrono.hpp>
#include <boost/filesystem.hpp>

#include <iostream>
#include <silkworm/db/lmdb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/chain/block_chain.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <string>

namespace bch = boost::chrono;
namespace bfs = boost::filesystem;

int main(int argc, char* argv[]) {

    CLI::App app("Walks Ethereum blocks and recovers senders.");

    std::string po_db_path{ silkworm::db::default_path() };
    uint32_t po_from_block{ 1u };
    uint32_t po_to_block{ UINT32_MAX };
    CLI::Range range32(1u, UINT32_MAX);

    // Check whether or not default db_path exists and
    // has some files in it

    bfs::path db_path(po_db_path);
    CLI::Option* db_path_set{ nullptr };

    if (bfs::exists(db_path) && bfs::is_directory(db_path) && !db_path.empty())
    {
        db_path_set = app.add_option("--db", po_db_path, "Path to chain db", true)->check(CLI::ExistingDirectory);
    }
    else
    {
        db_path_set = app.add_option("--db", po_db_path, "Path to chain db", false)->required()->check(CLI::ExistingDirectory);
    }

    app.add_option("--from,-f", po_from_block, "Initial block number to process (inclusive)", true)->check(range32);
    app.add_option("--to,-t", po_to_block, "Final block number to process (exclusive)", true)->check(range32);
    CLI11_PARSE(app, argc, argv);

    // If database path is provided (and has passed CLI::ExistingDirectory validator
    // check whether it is empty
    if(db_path_set)
    {
        db_path = bfs::path(po_db_path);
        if (db_path.empty())
        {
            std::cerr << "Provided --db [" << po_db_path << "] is an empty directory" << std::endl <<
                "Try --help for help" << std::endl;
            return -1;
        }
    }

  using namespace silkworm;

  db::LmdbDatabase db{po_db_path.c_str()};
  BlockChain chain{&db};

  bch::time_point t1{bch::steady_clock::now()};

  uint64_t block_num{po_from_block};
  uint64_t processed_txs{ 0 };

  for (; block_num < po_to_block; ++block_num) {
    std::optional<BlockWithHash> bh = db.get_block(block_num);
    if (!bh) {
      break;
    }

    // Loop block's transactions
    for (silkworm::Transaction tx : bh->block.transactions)
    {
        if (!silkworm::ecdsa::is_valid_signature(tx.v, tx.r, tx.s, chain.config().has_homestead(block_num), chain.config().chain_id))
        {
            std::cerr << "Tx validation failed block #" << block_num << std::endl;
            std::cerr << "r " << intx::to_string(tx.r) << std::endl;
            std::cerr << "s " << intx::to_string(tx.s) << std::endl;
            std::cerr << "v " << intx::to_string(tx.v) << std::endl;
            return -3;
        }
        processed_txs++;
    }

    if (block_num % 1000 == 0) {
        bch::time_point t2{bch::steady_clock::now()};
        std::cout << "Checked blocks ≤ " << block_num << " in " << std::fixed << std::setprecision(2) << (bch::duration_cast<bch::milliseconds>(t2 -t1).count() / 1000.0)
            << " s " << processed_txs << " txs" << std::endl;
        t1 = t2;
        processed_txs = 0;
    }
  }

  std::cout << "Blocks [" << po_from_block << " ... " << block_num << "] have been examined 😅\n";
  return 0;
}
