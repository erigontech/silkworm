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
#ifndef SILKWORM_BLOCK_PROVIDER_HPP
#define SILKWORM_BLOCK_PROVIDER_HPP

#include <silkworm/chain/identity.hpp>
#include <silkworm/concurrency/active_component.hpp>
#include <silkworm/concurrency/containers.hpp>
#include <silkworm/downloader/internals/db_tx.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/messages/InboundMessage.hpp>
#include <silkworm/downloader/sentry_client.hpp>

namespace silkworm {

/*
 * BlockProvider
 * This component processes inbound request from other peers that ask for block headers or block bodies.
 * This component should always be running; to do so provide a thread to run the execution_loop().
 * BlockProvider depends upon a SentryClient to connect to the remote sentry to receive requests and send responses.
 */
class BlockProvider : public ActiveComponent {  // an active component that must run always
  public:
    BlockProvider(SentryClient& sentry, const Db::ReadOnlyAccess& db_access);
    BlockProvider(const BlockProvider&) = delete;  // not copyable
    BlockProvider(BlockProvider&&) = delete;       // nor movable
    ~BlockProvider();

    /*[[long_running]]*/ void execution_loop() override;  // main loop, receive messages from sentry and process them

  private:
    using MessageQueue = ConcurrentQueue<std::shared_ptr<InboundMessage>>;  // used internally to store new messages

    void receive_message(const sentry::InboundMessage&);

    Db::ReadOnlyAccess db_access_;
    SentryClient& sentry_;
    MessageQueue messages_{};  // thread safe queue where to receive messages from sentry
};

}  // namespace silkworm

#endif  // SILKWORM_BLOCK_PROVIDER_HPP
