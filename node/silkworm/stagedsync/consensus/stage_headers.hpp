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

#include <atomic>

#include <silkworm/common/measure.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/block_exchange.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/messages/internal_message.hpp>
#include <silkworm/stagedsync/execution_engine.hpp>

#include "stage.hpp"

namespace silkworm::stagedsync::consensus {

class HeadersStage : public Stage {
  public:
    HeadersStage(BlockExchange&, ExecutionEngine&);
    HeadersStage(const HeadersStage&) = delete;  // not copyable
    HeadersStage(HeadersStage&&) = delete;       // nor movable
    ~HeadersStage();

    Stage::Result forward(std::optional<NewHeight>) override;  // go forward, downloading headers
    Stage::Result unwind(UnwindPoint) override;   // go backward, unwinding headers to new_height

  private:
    void send_header_requests();  // send requests for more headers
    void send_announcements();
    auto sync_header_chain(BlockNum highest_in_db) -> std::shared_ptr<InternalMessage<void>>;
    auto withdraw_stable_headers() -> std::shared_ptr<InternalMessage<std::tuple<Headers, bool>>>;
    auto update_bad_headers(std::set<Hash>) -> std::shared_ptr<InternalMessage<void>>;

    std::vector<std::string> get_log_progress() override;  // thread safe
    std::atomic<BlockNum> current_height_{0};

    std::optional<BlockNum> target_block_;
    BlockExchange& block_downloader_;
    ExecutionEngine& exec_engine_;
    std::string log_prefix_;
    bool is_first_cycle_{true};
};

}  // namespace silkworm::stagedsync
