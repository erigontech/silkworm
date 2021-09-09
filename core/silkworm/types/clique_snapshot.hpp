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

#ifndef SILKWORM_TYPES_CLIQUE_SNAPSHOT
#define SILKWORM_TYPES_CLIQUE_SNAPSHOT

namespace silkworm {

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
struct CliqueConfig {
	uint64_t   period;   // Number of seconds between blocks to enforce
    uint64_t   epoch;    // Epoch length to reset votes and checkpoint
};

struct SnapshotConfig {
    uint64_t checkpoint_interval;     // Number of blocks after which to save the vote snapshot to the database
    uint64_t inmemory_snapshots;      // Number of recent vote snapshots to keep in memory
	uint64_t inmemory_signatures;     // Number of recent block signatures to keep in memory
};

// Voting Snapshot for Clique
class CliqueSnapshot {
};

constexpr CliqueConfig kDefaultCliqueConfig = {
    15,
    30000,
}; // Ropsten and Görli configuration

constexpr SnapshotConfig kDefaultSnapshotConfig = {
    10,
    1024,
    16384
};

}
#endif // SILKWORM_TYPES_CLIQUE_SNAPSHOT