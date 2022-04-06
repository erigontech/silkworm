/*
Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_BODY_DOWNLOADER_H
#define SILKWORM_BODY_DOWNLOADER_H

#include <silkworm/concurrency/containers.hpp>
#include <silkworm/downloader/internals/db_tx.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/messages/internal_message.hpp>

#include "block_downloader.hpp"
#include "stage.h"

namespace silkworm {

class BodyStage : public Stage {
  public:
    BodyStage(const Db::ReadWriteAccess&, BlockDownloader&);
    BodyStage(const BodyStage&) = delete;  // not copyable
    BodyStage(BodyStage&&) = delete;       // nor movable
    ~BodyStage();

    Stage::Result forward(bool first_sync) override;  // go forward, downloading headers
    Stage::Result unwind_to(BlockNum new_height,
                            Hash bad_block) override;  // go backward, unwinding headers to new_height

  private:
    void send_body_requests();  // send requests for more bodies
    auto withdraw_ready_bodies() -> std::shared_ptr<InternalMessage<std::vector<BlockBody>>>;

    Db::ReadWriteAccess db_access_;
    BlockDownloader& block_downloader_;
};

}  // namespace silkworm

#endif  // SILKWORM_BODY_DOWNLOADER_H
