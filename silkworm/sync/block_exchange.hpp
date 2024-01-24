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
#include <variant>

#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/infra/concurrency/containers.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/sentry/api/common/message_from_peer.hpp>
#include <silkworm/sync/internals/body_sequence.hpp>
#include <silkworm/sync/internals/header_chain.hpp>
#include <silkworm/sync/messages/inbound_message.hpp>

namespace silkworm {

class SentryClient;

//! \brief Implement the logic needed to download headers and bodies
class BlockExchange : public ActiveComponent {
  public:
    BlockExchange(SentryClient&, db::ROAccess, const ChainConfig&);
    ~BlockExchange() override;

    // public interface for block downloading

    void initial_state(std::vector<BlockHeader> last_headers);  // set the initial state of the sync

    enum class Target_Tracking : uint8_t {
        kByAnnouncements,
        kByNewPayloads
    };
    void download_blocks(BlockNum current_height, Target_Tracking);  // start downloading blocks from current_height

    void new_target_block(std::shared_ptr<Block> block);  // set a new target block to download, to use with Target_Tracking::kByNewPayloads

    void stop_downloading();  // stop downloading blocks

    using ResultQueue = ConcurrentQueue<Blocks>;
    ResultQueue& result_queue();  // get the queue where to receive downloaded blocks

    bool in_sync() const;             // true if the sync is in sync with the network
    BlockNum current_height() const;  // the current height of the sync

    // public generic interface

    void accept(std::shared_ptr<Message>); /*[[thread_safe]]*/
    void execution_loop() override;        /*[[long_running]]*/

    const ChainConfig& chain_config() const;
    SentryClient& sentry() const;

  private:
    using MessageQueue = ConcurrentQueue<std::shared_ptr<Message>>;  // used internally to store new messages

    void receive_message(std::shared_ptr<InboundMessage> message);
    size_t request_headers(time_point_t tp, size_t max_requests);
    size_t request_bodies(time_point_t tp, size_t max_requests);
    void collect_headers();
    void collect_bodies();
    void log_status();

    db::ROAccess db_access_;  // only to reply remote peer's requests
    SentryClient& sentry_;
    const ChainConfig& chain_config_;
    HeaderChain header_chain_;
    BodySequence body_sequence_;
    Network_Statistics statistics_;

    ResultQueue results_{};
    MessageQueue messages_{};  // thread safe queue where to receive messages from sentry
    std::atomic_bool in_sync_{false};
    std::atomic_bool downloading_active_{false};
    std::atomic<BlockNum> current_height_{0};
};

}  // namespace silkworm
