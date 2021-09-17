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
#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>

#include "header_downloader.hpp"
#include "messages/InboundGetBlockHeaders.hpp"
#include "messages/OutboundGetBlockHeaders.hpp"
#include "rpc/ReceiveMessages.hpp"
#include "rpc/SetStatus.hpp"
#include "internals/header_retrieval.hpp"

namespace silkworm {

HeaderDownloader::HeaderDownloader(SentryClient& sentry, Db::ReadWriteAccess db_access, ChainIdentity chain_identity):
    chain_identity_(std::move(chain_identity)),
    db_access_{db_access},
    sentry_{sentry}
{
}

HeaderDownloader::~HeaderDownloader() {
    SILKWORM_LOG(LogLevel::Error) << "HeaderDownloader destroyed\n";
}

void HeaderDownloader::send_status() {
    HeaderRetrieval headers(db_access_);
    auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();

    rpc::SetStatus set_status(chain_identity_, head_hash, head_td);
    sentry_.exec_remotely(set_status);

    SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader, set_status sent\n";
    sentry::SetStatusReply reply = set_status.reply();

    sentry::Protocol supported_protocol = reply.protocol();
    if (supported_protocol != sentry::Protocol::ETH66) {
        SILKWORM_LOG(LogLevel::Critical) << "HeaderDownloader: sentry do not support eth/66 protocol, is_stopping...\n";
        sentry_.need_close();
        throw HeaderDownloaderException("HeaderDownloader exception, cause: sentry do not support eth/66 protocol");
    }
}

void HeaderDownloader::receive_messages(MessageQueue& messages, std::atomic<bool>& stopping) {

    rpc::ReceiveMessages message_subscription(rpc::ReceiveMessages::Scope::BlockAnnouncements);
    sentry_.exec_remotely(message_subscription);

    while (!stopping && !sentry_.closing() && message_subscription.receive_one_reply()) {

        auto message = InboundBlockAnnouncementMessage::make(message_subscription.reply(), working_chain_, sentry_);

        messages.push(message);
    }

    SILKWORM_LOG(LogLevel::Warn) << "HeaderDownloader execution_loop is_stopping...\n";

}

void HeaderDownloader::process_one_message(MessageQueue& messages) {
    using namespace std::chrono_literals;

    // pop a message from the queue
    std::shared_ptr<Message> message;
    bool present = messages.timed_wait_and_pop(message, 1000ms);
    if (!present) return;   // timeout, needed to check exiting_

    SILKWORM_LOG(LogLevel::Trace) << "HeaderDownloader processing message " << message->name() << "\n";

    // process the message (command pattern)
    message->execute();
}

auto HeaderDownloader::forward_to(BlockNum new_height) -> StageResult {

    using std::shared_ptr;
    using namespace std::chrono_literals;

    bool new_height_reached = false;

    MessageQueue messages{}; // thread safe queue where receive messages from sentry thread
    std::atomic<bool> stopping{false};
    std::thread message_receiving;

    try {

        // read last chain
        working_chain_.recover_from_db(db_access_); // todo: this use the same db connection, it is ok?

        // set a goal
        working_chain_.target_height(new_height);

        // send status to sentry
        send_status(); // todo: avoid if already sent by BlockProvider?

        // start message receiving (headers & blocks requests)
        message_receiving = std::thread([this, &messages, &stopping]() {
            receive_messages(messages, stopping);
        });

        // message processing
        time_point_t last_request;
        while (!new_height_reached && !sentry_.closing()) {

            // make an outbound headers request at every minute
            if (std::chrono::system_clock::now() - last_request > 60s) {
                shared_ptr<Message> message = std::make_shared<OutboundGetBlockHeaders>(working_chain_, sentry_);
                messages.push(message);
                last_request = std::chrono::system_clock::now();
            }

            // process outbound & inbound messages
            process_one_message(messages);  // pop a message from the queue and process it

            // check if finished
            new_height_reached = working_chain_.height_reached() >= new_height;
            SILKWORM_LOG(LogLevel::Debug) << "WorkingChain status: " << working_chain_.human_readable_status() << "\n";
        }

        stopping = true; // todo: it is better to try to cancel the grpc call
    }
    catch(const std::exception& e) {
        SILKWORM_LOG(LogLevel::Error) << "HeaderDownloader wind operation is_stopping due to exception: " << e.what() << "\n";
        return StageResult::kError;
    }

    message_receiving.join();

    SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader wind operation completed\n";

    return new_height_reached ? StageResult::kOk : StageResult::kError;
}

auto HeaderDownloader::unwind_to([[maybe_unused]] BlockNum new_height) -> StageResult {
    // todo: to implement
    return StageResult::kOk;
}


}  // namespace silkworm

