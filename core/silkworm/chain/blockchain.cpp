/*
   Copyright 2021 The Silkworm Authors

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

#include "blockchain.hpp"

#include <silkworm/execution/execution.hpp>

namespace silkworm {

Blockchain::Blockchain(StateBuffer& state, const ChainConfig& config, const Block& genesis_block)
    : state_{state}, config_{config} {
    evmc::bytes32 hash{state_.insert_block(genesis_block)};
    state_.canonize_block(genesis_block.header.number, hash);
}

ValidationError Blockchain::insert_block(Block& block, bool check_state_root) {
    if (ValidationError err{pre_validate_block(block, state_, config_)}; err != ValidationError::kOk) {
        return err;
    }

    auto [current_number, current_hash]{state_.current_canonical_block()};
    intx::uint256 current_total_difficult{*state_.total_difficulty(current_number, current_hash)};

    block.recover_senders(config_);

    evmc::bytes32 block_hash{state_.insert_block(block)};
    uint64_t block_number{block.header.number};
    intx::uint256 block_total_difficult{*state_.total_difficulty(block_number, block_hash)};

    if (block_total_difficult > current_total_difficult) {
        // TODO[Issue #23] perform reorg if necessary

        std::pair<std::vector<Receipt>, ValidationError> res{execute_block(block, state_, config_)};
        if (res.second != ValidationError::kOk) {
            // TODO(Andrew) mark the block as invalid and remove it from the state
            return res.second;
        }

        if (check_state_root) {
            evmc::bytes32 state_root{state_.state_root_hash()};
            if (state_root != block.header.state_root) {
                state_.unwind_state_changes(block_number);
                // TODO(Andrew) mark the block as invalid and remove it from the state
                return ValidationError::kWrongStateRoot;
            }
        }

        state_.canonize_block(block_number, block_hash);
    }

    return ValidationError::kOk;
}

}  // namespace silkworm
