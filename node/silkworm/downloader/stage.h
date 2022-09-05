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

#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/common/settings.hpp>

namespace silkworm {

// todo: replace this class with IStage as soon as it will support the shared status
class Stage : public Stoppable {
  public:
    enum Result { Unspecified, Done, DoneAndUpdated, UnwindNeeded, SkipTx, Error };

    struct Status {
        bool first_sync{false};
        std::optional<BlockNum> current_point;
        std::optional<BlockNum> unwind_point;
        std::optional<Hash> bad_block;
    };

    Stage([[maybe_unused]] const char* stage_name, Status& s, NodeSettings*): shared_status_(s) {};
    Stage(const Stage& s): shared_status_(s.shared_status_) {}
    
    virtual ~Stage() = default;
    
    virtual Result forward(db::RWTxn&) = 0;
    virtual Result unwind(db::RWTxn&, BlockNum new_height) = 0;
    virtual Result prune(db::RWTxn&) = 0;

    // for progress log
    enum class OperationType { None, Forward, Unwind, Prune };
    std::atomic<OperationType> operation_{OperationType::None};  // actual operation being carried out
    virtual std::vector<std::string> get_log_progress() = 0; // implementation MUST be thread safe

  protected:
    Status& shared_status_;
};

}  // namespace silkworm
