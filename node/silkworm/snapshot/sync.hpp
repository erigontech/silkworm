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

#include <string>
#include <thread>
#include <vector>

#include <silkworm/bittorrent/client.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/snapshot/repository.hpp>
#include <silkworm/snapshot/settings.hpp>

namespace silkworm {

class SnapshotSync {
  public:
    SnapshotSync(const SnapshotSettings& settings, const ChainConfig& config);
    ~SnapshotSync();

    [[nodiscard]] SnapshotRepository& repository() { return repository_; }

    bool download_and_index_snapshots(db::RWTxn& txn);
    bool download_snapshots(const std::vector<std::string>& snapshot_file_names);
    bool index_snapshots(db::RWTxn& txn, const std::vector<std::string>& snapshot_file_names);
    void stop();

  private:
    SnapshotSettings settings_;
    const ChainConfig& config_;
    SnapshotRepository repository_;
    BitTorrentClient client_;
    std::thread client_thread_;
};

}  // namespace silkworm
