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

#include <cstdlib>
#include <iostream>
#include <string>

#include "db/lmdb.hpp"
#include "execution/processor.hpp"
#include "state/intra_block_state.hpp"
#include "state/reader.hpp"

int main() {
  using namespace silkworm;

  std::string db_path{std::getenv("HOME")};
  db_path += "/Library/Ethereum/geth/chaindata";
  db::LmdbDatabase db{db_path.c_str()};

  BlockChain chain{&db};

  uint64_t block_num{0};
  while (std::optional<BlockWithHash> bh = db.get_block(++block_num)) {
    std::vector<evmc::address> senders{db.get_senders(block_num, bh->hash)};
    assert(senders.size() == bh->block.transactions.size());
    for (size_t i{0}; i < senders.size(); ++i) {
      bh->block.transactions[i].from = senders[i];
    }

    state::Reader reader{db, block_num};
    IntraBlockState state{&reader};
    ExecutionProcessor processor{chain, bh->block, state};

    std::vector<Receipt> receipts = processor.execute_block();

    if (processor.gas_used() != bh->block.header.gas_used) {
      std::cerr << "gasUsed mismatch for block " << block_num << ":\n";
      std::cerr << processor.gas_used() << '\n';
      std::cerr << "vs expected\n";
      std::cerr << bh->block.header.gas_used << '\n';
      return -1;
    }

    // TODO[Byzantium] check receipts

    state::Writer writer;
    state.write_block(writer);

    std::optional<db::AccountChanges> db_account_changes{db.get_account_changes(block_num)};
    if (writer.account_changes() != db_account_changes) {
      std::cerr << "Account change mismatch for block " << block_num << " 😲\n";
      if (db_account_changes) {
        for (const auto& e : *db_account_changes) {
          if (writer.account_changes().count(e.first) == 0) {
            std::cerr << to_hex(e.first) << " is missing\n";
          } else if (Bytes val{writer.account_changes().at(e.first)}; val != e.second) {
            std::cerr << "Value mismatch for " << to_hex(e.first) << ":\n";
            std::cerr << to_hex(val) << "\n";
            std::cerr << "vs DB\n";
            std::cerr << to_hex(e.second) << "\n";
          }
        }
        for (const auto& e : writer.account_changes()) {
          if (db_account_changes->count(e.first) == 0) {
            std::cerr << to_hex(e.first) << " is not in DB\n";
          }
        }
      } else {
        std::cerr << "Nil DB account changes\n";
      }
      return -2;
    }

    Bytes db_storage_changes{db.get_storage_changes(block_num)};
    Bytes calculated_storage_changes{};
    if (!writer.storage_changes().empty()) {
      calculated_storage_changes = writer.storage_changes().encode();
    }
    if (calculated_storage_changes != db_storage_changes) {
      std::cerr << "Storage change mismatch for block " << block_num << " 😲\n";
      std::cerr << to_hex(calculated_storage_changes) << "\n";
      std::cerr << "vs DB\n";
      std::cerr << to_hex(db_storage_changes) << "\n";
      return -3;
    }

    if (block_num % 1000 == 0) {
      std::cout << "Checked " << block_num << " blocks\n";
    }
  }
  std::cout << "All " << (block_num - 1) << " available blocks have been checked 😅\n";
  return 0;
}
