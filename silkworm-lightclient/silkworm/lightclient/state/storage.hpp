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

#include "silkworm/lightclient/types/types.hpp"
#include "silkworm/lightclient/util/hash32.hpp"

namespace silkworm::cl {

//! State storage initialized with a received bootstrap derived from a given trusted block root
class Storage {
  public:
    explicit Storage(const Hash32& trusted_root, const cl::LightClientBootstrap& bootstrap);

    [[nodiscard]] const cl::BeaconBlockHeader* finalized_header() const { return finalized_header_.get(); }

  private:
    //! Most recent finalized Beacon block header
    std::shared_ptr<cl::BeaconBlockHeader> finalized_header_;

    //! Most recent available reasonably-safe Beacon block header
    std::shared_ptr<cl::BeaconBlockHeader> optimistic_header_;

    //! Current sync committee corresponding to the headers
    std::shared_ptr<cl::SyncCommittee> current_committee_;

    //! Next sync committee corresponding to the headers
    std::shared_ptr<cl::SyncCommittee> next_committee_;

    //! Best available header to switch finalized head to if we see nothing else
    std::unique_ptr<cl::LightClientUpdate> best_valid_update_;

    //! Max number of active participants in previous sync committee (used to calculate safety threshold)
    // uint64_t previous_max_active_participants_{0};

    //! Max number of active participants in current sync committee (used to calculate safety threshold)
    // uint64_t current_max_active_participants_{0};
};

}  // namespace silkworm::cl
