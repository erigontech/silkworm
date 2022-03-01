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

#ifndef SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_HPP_
#define SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_HPP_

#include <silkworm/stagedsync/common.hpp>
#include <silkworm/trie/prefix_set.hpp>

namespace silkworm::stagedsync {

class InterHashes final : public IStage {
  public:
    explicit InterHashes(NodeSettings* node_settings) : IStage(db::stages::kHashStateKey, node_settings){};
    ~InterHashes() override = default;
    StageResult forward(db::RWTxn& txn) final;
    StageResult unwind(db::RWTxn& txn, BlockNum to) final;
    StageResult prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    //! \brief Resets all fields related to log progress tracking
    void reset_log_progress();

    //! \brief See Erigon (p *HashPromoter) Promote
    trie::PrefixSet gather_account_changes(mdbx::txn& txn, BlockNum from, BlockNum to);
    //! \brief See Erigon (p *HashPromoter) Promote
    trie::PrefixSet gather_storage_changes(mdbx::txn& txn, BlockNum from, BlockNum to);

    // Logger info
    std::mutex log_mtx_{};        // Guards async logging
    std::string current_source_;  // Current source of data
    std::string current_key_;     // Actual processing key
};

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_HPP_
