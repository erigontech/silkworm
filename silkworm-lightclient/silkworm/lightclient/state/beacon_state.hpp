/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <memory>
#include <vector>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/lightclient/types/types.hpp>
#include <silkworm/lightclient/util/hash32.hpp>

namespace silkworm::cl {

struct BeaconState {
    uint64_t genesis_time{0};
    Hash32 genesis_validators_root;
    uint64_t slot;
    // Fork fork;
    std::shared_ptr<BeaconBlockHeader> latest_block_header;
    Hash32Sequence block_roots;
    Hash32Sequence state_roots;
    Hash32Sequence historical_roots;
    std::shared_ptr<Eth1Data> eth1_data;
    std::vector<std::shared_ptr<Eth1Data>> eth1_data_votes;
    uint64_t eth1_deposit_index{0};
    // std::vector<std::shared_ptr<Validator>> validators;
    std::vector<uint64_t> balances;
    Hash32Sequence randao_mixes;
    std::vector<uint64_t> slashings;
    Bytes previous_epoch_participation;
    Bytes current_epoch_participation;
    Bytes justification_bits;
    std::shared_ptr<Checkpoint> previous_justified_checkpoint;
    std::shared_ptr<Checkpoint> current_justified_checkpoint;
    std::shared_ptr<Checkpoint> finalized_checkpoint;
    std::vector<uint64_t> inactivity_scores;
    std::shared_ptr<SyncCommittee> current_committee;
    std::shared_ptr<SyncCommittee> next_committee;
    // std::shared_ptr<ExecutionHeader> latest_execution_payload_header;
};

}  // namespace silkworm::cl
