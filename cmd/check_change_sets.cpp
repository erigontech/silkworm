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

  uint64_t block_num{1};
  for (std::optional<BlockWithHash> bh = db.get_block(block_num); bh; ++block_num) {
    // TODO[TOP](Andrew) read senders

    state::Reader reader{db, block_num};
    IntraBlockState state{&reader};
    ExecutionProcessor processor{state, bh->block};

    std::vector<Receipt> receipts = processor.execute_block();

    if (processor.gas_used() != bh->block.header.gas_used) {
      std::cerr << "gasUsed is mismatched for block " << block_num << '\n';
      return -1;
    }

    // TODO(Andrew) check receipts post-Byzantium

    state::Writer writer;
    state.write_block(writer);

    std::optional<db::AccountChanges> expected{db.get_account_changes(block_num)};
    if (writer.account_changes() != expected) {
      std::cerr << "Unexpected account changes for block " << block_num << '\n';
      return -2;
    }

    // TODO[TOP](Andrew) storage changes

    if (block_num % 1000 == 0) {
      std::cout << "Checked " << block_num << " blocks\n";
    }
  }
  std::cout << "Checked " << block_num << " blocks\n";
  return 0;
}
