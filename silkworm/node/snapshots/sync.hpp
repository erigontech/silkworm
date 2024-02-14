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

#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/concurrency/stoppable.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/snapshots/bittorrent/client.hpp>
#include <silkworm/node/snapshots/repository.hpp>
#include <silkworm/node/snapshots/settings.hpp>

namespace silkworm::snapshots {

class SnapshotSync : public Stoppable {
  public:
    SnapshotSync(SnapshotRepository* repository, const ChainConfig& config);
    ~SnapshotSync() override;

    bool stop() override;

    bool download_and_index_snapshots(db::RWTxn& txn);
    bool download_snapshots(const std::vector<std::string>& snapshot_file_names);
    void index_snapshots();

  private:
    void reopen();
    void build_missing_indexes();
    void update_database(db::RWTxn& txn, BlockNum max_block_available);
    void update_block_headers(db::RWTxn& txn, BlockNum max_block_available);
    void update_block_bodies(db::RWTxn& txn, BlockNum max_block_available);
    static void update_block_hashes(db::RWTxn& txn, BlockNum max_block_available);
    static void update_block_senders(db::RWTxn& txn, BlockNum max_block_available);

    SnapshotRepository* repository_;
    const SnapshotSettings& settings_;
    const ChainConfig& config_;
    bittorrent::BitTorrentClient client_;
    std::thread client_thread_;
};

}  // namespace silkworm::snapshots
