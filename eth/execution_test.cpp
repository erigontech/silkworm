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

#include "execution.hpp"

#include "../tests/catch.hpp"

namespace silkworm::eth {

TEST_CASE("validation", "[execution]") {
  Address miner{eth::HexToAddress("0x829bd824b016326a401d083b33d092293333a830")};
  uint64_t block_number{1};

  eth::Transaction txn{
      .nonce = 12,
      .gas_price = 20000000000,
      .gas_limit = 21000,
      .to = eth::HexToAddress("0x727fc6a68321b754475c668a6abfb6e9e71c169a"),
      .value = 10 * eth::kEther,
  };

  IntraBlockState state;
  ExecutionProcessor processor{state, miner, block_number};

  ExecutionResult res = processor.ExecuteTransaction(txn);
  CHECK(res.error == ValidationError::kMissingSender);

  txn.from = eth::HexToAddress("0x68d7899b6635146a37d01934461d0c9e4b65ddda");
  res = processor.ExecuteTransaction(txn);
  CHECK(res.error == ValidationError::kMissingSender);

  // TODO(Andrew) other validation errors
}

}  // namespace silkworm::eth
