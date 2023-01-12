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

#include <silkworm/lightclient/ssz/common/bytes.hpp>
#include <silkworm/lightclient/state/beacon-chain/beacon_block.hpp>
#include <silkworm/lightclient/state/beacon-chain/light_client_bootstrap.hpp>
#include <silkworm/lightclient/state/beacon-chain/light_client_update.hpp>
#include <silkworm/lightclient/state/beacon-chain/sync_committee.hpp>
#include <silkworm/lightclient/types/types.hpp>

namespace silkworm::cl {

//! State storage initialized with a received bootstrap derived from a given trusted block root
class Storage {
  public:
    explicit Storage(const eth::Root& trusted_root, const eth::LightClientBootstrap& bootstrap);

    [[nodiscard]] const auto& finalized_header() const { return finalized_header_; }
    [[nodiscard]] const auto& optimistic_header() const { return optimistic_header_; }
    [[nodiscard]] const auto& current_committee() const { return current_committee_; }

  private:
    //! Most recent finalized Beacon block header
    eth::BeaconBlockHeader finalized_header_;

    //! Most recent available reasonably-safe Beacon block header
    eth::BeaconBlockHeader optimistic_header_;

    //! Current sync committee corresponding to the headers
    eth::SyncCommittee current_committee_;

    //! Next sync committee corresponding to the headers
    eth::SyncCommittee next_committee_;

    //! Best available header to switch finalized head to if we see nothing else
    eth::LightClientUpdate best_valid_update_;

    //! Max number of active participants in previous sync committee (used to calculate safety threshold)
    // uint64_t previous_max_active_participants_{0};

    //! Max number of active participants in current sync committee (used to calculate safety threshold)
    // uint64_t current_max_active_participants_{0};
};

}  // namespace silkworm::cl
