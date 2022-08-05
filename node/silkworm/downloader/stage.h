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

namespace silkworm {

// todo: use IStage from stagedsync module when it will have support for returning unwind_point and bad_block
class Stage {
  public:
    struct Result {
        enum Status { Unspecified, Done, DoneAndUpdated, UnwindNeeded, SkipTx, Error } status;
        std::optional<BlockNum> current_point;
        std::optional<BlockNum> unwind_point;
        std::optional<Hash> bad_block;
    };

    virtual ~Stage() = default;

    virtual Result forward(bool first_sync) = 0;
    virtual Result unwind_to(BlockNum new_height, Hash bad_block) = 0;
};

}  // namespace silkworm
