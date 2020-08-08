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

#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/time/time.h>

#include <iostream>
#include <silkworm/db/lmdb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/execution/processor.hpp>
#include <silkworm/state/intra_block_state.hpp>
#include <silkworm/state/reader.hpp>
#include <silkworm/trie/vector_root.hpp>
#include <string>

ABSL_FLAG(std::string, db, silkworm::db::default_path(), "chain DB path");
ABSL_FLAG(uint64_t, from, 1, "start from block number (inclusive)");
ABSL_FLAG(uint64_t, to, UINT64_MAX, "check up to block number (exclusive)");

int main(int argc, char* argv[]) {
  absl::SetProgramUsageMessage(
      "Walks Ethereum blocks and recovers senders.");
  absl::ParseCommandLine(argc, argv);

  using namespace silkworm;

  db::LmdbDatabase db{absl::GetFlag(FLAGS_db).c_str()};
  BlockChain chain{&db};

  const uint64_t from{absl::GetFlag(FLAGS_from)};
  const uint64_t to{absl::GetFlag(FLAGS_to)};

  absl::Time t1{absl::Now()};

  uint64_t block_num{from};
  for (; block_num < to; ++block_num) {
    std::optional<BlockWithHash> bh = db.get_block(block_num);
    if (!bh) {
      break;
    }

  }

  std::cout << "Blocks [" << from << "; " << block_num << ") have been examined 😅\n";
  return 0;
}
