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

#include <silkworm/chain/identity.hpp>
#include <silkworm/concurrency/active_component.hpp>
#include <silkworm/concurrency/containers.hpp>
#include <silkworm/downloader/internals/db_tx.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/messages/message.hpp>
#include <silkworm/downloader/sentry_client.hpp>
#include "stage.h"

namespace silkworm {

class BodyDownloader : public Stage, public ActiveComponent {
    Db::ReadWriteAccess db_access_;
    SentryClient& sentry_;

  public:
    BodyDownloader(SentryClient& sentry, const Db::ReadWriteAccess& db_access, const ChainIdentity& chain_identity);
    BodyDownloader(const BodyDownloader&) = delete;  // not copyable
    BodyDownloader(BodyDownloader&&) = delete;       // nor movable
    ~BodyDownloader();

    Stage::Result forward(bool first_sync) override;  // go forward, downloading headers
    Stage::Result unwind_to(BlockNum new_height,
                            Hash bad_block) override;  // go backward, unwinding headers to new_height

    /*[[long_running]]*/ void execution_loop() override;  // process messages popping them from the queue

  private:
    using MessageQueue = ConcurrentQueue<std::shared_ptr<Message>>;  // used internally to store new messages

};

}

#endif  // SILKWORM_BODY_DOWNLOADER_H
