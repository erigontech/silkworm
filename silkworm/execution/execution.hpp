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

#ifndef SILKWORM_EXECUTION_EXECUTION_H_
#define SILKWORM_EXECUTION_EXECUTION_H_

#include <optional>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/types/receipt.hpp>

namespace silkworm {

/** @brief Executes a given block and writes resulting changes into the database.
 *
 * The function assumes that the state in the database is the one that should be at the begining of the block.
 * @return Receipts if the block was executed successfully and std::nullopt if it wasn't found in the database.
 */
std::optional<std::vector<Receipt>> execute_block(db::Buffer& buffer, uint64_t block_number,
                                                  const ChainConfig& config = kMainnetConfig);

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_EXECUTION_H_
