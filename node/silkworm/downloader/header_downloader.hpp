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
#ifndef SILKWORM_HEADER_DOWNLOADER_HPP
#define SILKWORM_HEADER_DOWNLOADER_HPP

#include <atomic>

#include <silkworm/chain/identity.hpp>

#include <silkworm/concurrency/containers.hpp>

#include "messages/Message.hpp"
#include "internals/DbTx.hpp"
#include "internals/types.hpp"
#include "internals/working_chain.hpp"
#include "sentry_client.hpp"

namespace silkworm {

// (proposed) abstract interface for all stages
class Stage {
  public:
    enum StageResult { kOk, kError };

    virtual StageResult wind(BlockNum new_height) = 0;
    virtual StageResult unwind(BlockNum new_height) = 0;
};

// custom exception
class HeaderDownloaderException: public std::runtime_error {
  public:
    explicit HeaderDownloaderException(std::string cause): std::runtime_error(cause) {}
};

// header downloader stage
class HeaderDownloader : public Stage {

    ChainIdentity chain_identity_;
    DbTx& db_;
    SentryClient& sentry_;
    WorkingChain working_chain_;

  public:
    HeaderDownloader(SentryClient& sentry, DbTx& db, ChainIdentity chain_identity);
    HeaderDownloader(const HeaderDownloader&) = delete; // not copyable
    HeaderDownloader(HeaderDownloader&&) = delete; // nor movable
    ~HeaderDownloader();

    StageResult wind(BlockNum new_height) override;
    StageResult unwind(BlockNum new_height) override;

  private:
    using MessageQueue = ConcurrentQueue<std::shared_ptr<Message>>;

    void send_status();
    [[long_running]] void receive_messages(MessageQueue& messages, std::atomic<bool>& stopping);

    void process_one_message(MessageQueue& messages);
};


}  // namespace silkworm

#endif  // SILKWORM_HEADER_DOWNLOADER_HPP
