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
#include <silkworm/concurrency/active_component.hpp>

#include "internals/db_tx.hpp"
#include "internals/types.hpp"
#include "internals/working_chain.hpp"
#include "messages/InternalMessage.hpp"
#include "sentry_client.hpp"

namespace silkworm {

// (proposed) abstract interface for all stages
class Stage {
  public:
    struct Result {
        enum Status { Unknown, Done, UnwindNeeded, Error } status;
        std::optional<BlockNum> unwind_point;
    };

    virtual Result forward(bool first_sync) = 0;
    virtual Result unwind_to(BlockNum new_height, Hash bad_block) = 0;
};

// custom exception
class HeaderDownloaderException: public std::runtime_error {
  public:
    explicit HeaderDownloaderException(std::string cause): std::runtime_error(cause) {}
};

/*
 * Header downloading stage
 * Like the other stages it has two methods, one to go forward and one to go backwards in the chain.
 * It doesn't require a thread, but it uses one internally to separate message receiving and message handling
 */
class HeaderDownloader : public Stage, public ActiveComponent {

    ChainIdentity chain_identity_;
    Db::ReadWriteAccess db_access_;
    SentryClient& sentry_;

  public:
    HeaderDownloader(SentryClient& sentry, Db::ReadWriteAccess db_access, ChainIdentity chain_identity);
    HeaderDownloader(const HeaderDownloader&) = delete; // not copyable
    HeaderDownloader(HeaderDownloader&&) = delete; // nor movable
    ~HeaderDownloader();

    Stage::Result forward(bool first_sync) override; // go forward, downloading headers
    Stage::Result unwind_to(BlockNum new_height, Hash bad_block = {}) override;  // go backward, unwinding headers to new_height

    /*[[long_running]]*/ void receive_messages(); // subscribe with sentry to receive messages
                                                   // and do a long-running loop to wait for messages

    /*[[long_running]]*/ void execution_loop() override; // process messages popping them from the queue

  private:
    using MessageQueue = ConcurrentQueue<std::shared_ptr<Message>>; // used internally to store new messages

    void send_status();          // send chain identity to sentry
    void send_header_requests(); // send requests for more headers
    void send_announcements();
    auto sync_working_chain(BlockNum highest_in_db) -> std::shared_ptr<InternalMessage<void>>;
    auto withdraw_stable_headers() -> std::shared_ptr<InternalMessage<std::tuple<Headers,bool>>>;
    auto update_bad_headers(std::set<Hash>) -> std::shared_ptr<InternalMessage<void>>;

    WorkingChain working_chain_;
    MessageQueue messages_{}; // thread safe queue where to receive messages from sentry

    /* todo: to better enforce mono-thread usage of WorkingChain, put WorkingChain and MessageQueue here, add here the message-execution loop and use messages with a execute(working_chain) method
    class Background_Processing {
        MessageQueue messages;
        WorkingChain working_chain_;
      public:
        void receive_message(shared_ptr<Message>); // put message in the queue; call it from sentry (pub/sub) and from the downloader

        [[long_running]] void process_messages(); // wait for a message, pop and process it; provide a thread from the outside
    };
    */
};

}  // namespace silkworm

#endif  // SILKWORM_HEADER_DOWNLOADER_HPP
