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

#include "messages/InboundMessage.hpp"
#include "internals/DbTx.hpp"
#include "internals/types.hpp"
#include "sentry_client.hpp"

namespace silkworm {

class BlockProviderException: public std::runtime_error {
  public:
    explicit BlockProviderException(std::string cause): std::runtime_error(cause) {}
};


class BlockProvider : public ActiveComponent {  // but also an active component that must run always

    ChainIdentity chain_identity_;
    DbTx& db_;
    SentryClient& sentry_;

  public:
    BlockProvider(SentryClient& sentry, DbTx& db, ChainIdentity chain_identity);
    BlockProvider(const BlockProvider&) = delete;  // not copyable
    BlockProvider(BlockProvider&&) = delete;       // nor movable
    ~BlockProvider();

    DbTx& db_tx() { return db_; }
    SentryClient& sentry() { return sentry_; }

    void execution_loop() override;

  private:
    void send_status();
    void process_message(std::shared_ptr<InboundMessage> message);

};

}  // namespace silkworm

#endif  // SILKWORM_BLOCK_PROVIDER_HPP
