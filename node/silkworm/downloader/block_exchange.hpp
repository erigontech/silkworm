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

#ifndef SILKWORM_BLOCK_EXCHANGE_H
#define SILKWORM_BLOCK_EXCHANGE_H

#include <silkworm/chain/identity.hpp>
#include <silkworm/concurrency/active_component.hpp>
#include <silkworm/concurrency/containers.hpp>
#include <silkworm/downloader/internals/db_tx.hpp>
#include <silkworm/downloader/internals/header_chain.hpp>
#include <silkworm/downloader/internals/body_sequence.hpp>
#include <silkworm/downloader/messages/message.hpp>
#include <silkworm/downloader/sentry_client.hpp>

namespace silkworm {

//! \brief Implement the logic needed to download headers and bodies
class BlockExchange : public ActiveComponent {
  public:
    BlockExchange(SentryClient&, const Db::ReadOnlyAccess&, const ChainIdentity&);
    ~BlockExchange();

    void accept(std::shared_ptr<Message>); /*[[thread_safe]]*/
    void execution_loop() override;        /*[[long_running]]*/

    const ChainIdentity& chain_identity();

  private:
    using MessageQueue = ConcurrentQueue<std::shared_ptr<Message>>;  // used internally to store new messages

    void receive_message(const sentry::InboundMessage& raw_message);
    void log_status();

    Db::ReadOnlyAccess db_access_;
    SentryClient& sentry_;
    const ChainIdentity& chain_identity_;
    HeaderChain header_chain_;
    BodySequence body_sequence_;
    MessageQueue messages_{};  // thread safe queue where to receive messages from sentry
};

}  // namespace silkworm

#endif  // SILKWORM_BLOCK_EXCHANGE_H
