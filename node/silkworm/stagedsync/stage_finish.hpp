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

#include <silkworm/stagedsync/common.hpp>

namespace silkworm::stagedsync {

class Finish : public IStage {
  public:
    explicit Finish(NodeSettings* node_settings, SyncContext* sync_context)
        : IStage(sync_context, db::stages::kFinishKey, node_settings){};
    ~Finish() override = default;

    StageResult forward(db::RWTxn& txn) final;
    StageResult unwind(db::RWTxn& txn) final;

    // Finish does not prune.
    StageResult prune(db::RWTxn&) final { return StageResult::kSuccess; };
};
}  // namespace silkworm::stagedsync
