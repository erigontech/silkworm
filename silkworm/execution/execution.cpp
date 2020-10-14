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

#include <cassert>
#include <silkworm/db/access_layer.hpp>
#include <stdexcept>

#include "processor.hpp"

namespace silkworm {

std::optional<std::vector<Receipt>> execute_block(db::Buffer& buffer, uint64_t block_num, const ChainConfig& config) {
    assert(buffer.transaction());
    lmdb::Transaction& txn{*buffer.transaction()};

    std::optional<BlockWithHash> bh{db::read_block(txn, block_num)};
    if (!bh) {
        return std::nullopt;
    }

    std::vector<evmc::address> senders{db::read_senders(txn, block_num, bh->hash)};
    if (senders.size() != bh->block.transactions.size()) {
        throw std::runtime_error("missing or incorrect senders");
    }
    for (size_t i{0}; i < senders.size(); ++i) {
        bh->block.transactions[i].from = senders[i];
    }

    IntraBlockState state{buffer};
    ExecutionProcessor processor{bh->block, state, config};

    return processor.execute_block();
}

}  // namespace silkworm
