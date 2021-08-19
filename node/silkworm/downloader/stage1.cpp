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
#include "stage1.hpp"

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>

#include "HeaderLogic.hpp"
#include "messages/InboundMessage.hpp"
#include "rpc/ReceiveMessages.hpp"
#include "rpc/SetStatus.hpp"
#include "rpc/SendMessageById.hpp"
#include "rpc/SendMessageByMinBlock.hpp"
#include "rpc/PeerMinBlock.hpp"

namespace silkworm {

// logs
std::string result(std::shared_ptr<SentryRpc> rpc);

// impl
BlockProvider::BlockProvider(SentryClient& sentry, ChainIdentity chain_identity, std::string db_path):
    chain_identity_(std::move(chain_identity)),
    db_{db_path},
    sentry_{sentry}
{
}

BlockProvider::~BlockProvider() {
    SILKWORM_LOG(LogLevel::Error) << "BlockProvider destroyed\n";
}

void BlockProvider::send_status() {
    HeaderRetrieval headers(db_);
    auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();
    auto set_status = rpc::SetStatus::make(chain_identity_.chain, chain_identity_.genesis_hash,
                                           chain_identity_.distinct_fork_numbers(), head_hash, head_td);
    set_status->on_receive_reply([&, set_status](auto& call) {
      if (!call.status().ok()) {
          exiting_ = true;
          SILKWORM_LOG(LogLevel::Critical)
              << "BlockProvider failed to set status to the remote sentry, cause:'" << call.status().error_message() << "', exiting...\n";
          return;
      }
      SILKWORM_LOG(LogLevel::Trace) << "set-status reply arrived\n";
      sentry::SetStatusReply& reply = set_status->reply();
      sentry::Protocol supported_protocol = reply.protocol();
      if (supported_protocol != sentry::Protocol::ETH66) {
          exiting_ = true;
          SILKWORM_LOG(LogLevel::Critical) << "BlockProvider: sentry do not support eth/66 protocol, exiting...\n";
      }
    });
    sentry_.exec_remotely(set_status);
}

void BlockProvider::send_message_subscription(MessageQueue& messages) {
    // create a message subscription rpc
    auto receive_messages = rpc::ReceiveMessages::make();
    receive_messages->on_receive_reply([&, receive_messages](auto& call) {
      // warning: this code will be executed in a foreign thread
      SILKWORM_LOG(LogLevel::Trace) << "BlockProvider, receive-messages reply arrived\n";
      if (!call.terminated()) {
          // receiving a message... copy it in the message queue for later processing
          sentry::InboundMessage& reply = receive_messages->reply();

          auto message = InboundBlockRequestMessage::make_from_raw_message(reply, db_);
          if (message) {
              SILKWORM_LOG(LogLevel::Info) << "BlockProvider, message received from remote peer " << identify(*message) << "\n";
              messages.push(message);
          }
      }
      else {
          // this call is a long running call, if it terminates there was an error on the link with the sentry
          exiting_ = true;
          SILKWORM_LOG(LogLevel::Critical)
              << "BlockProvider receiving messages stream interrupted, cause:'" << call.status().error_message() << "', exiting...\n";
      }
    });

    // send the subscription rpc
    sentry_.exec_remotely(receive_messages);
}

void BlockProvider::process_one_message(MessageQueue& messages) {
    using namespace std::chrono_literals;

    // pop a message from the queue
    std::shared_ptr<Message> message;
    bool present = messages.timed_wait_and_pop(message, 1000ms);
    if (!present) return;   // timeout, needed to check exiting_

    if (std::dynamic_pointer_cast<InboundMessage>(message)) {
        SILKWORM_LOG(LogLevel::Info) << "Processing message " << *message << "\n";
    }

    // process the message (command pattern)
    auto rpc_bundle = message->execute();

    // send remote rpcs if the message need them as result of processing
    for(auto& rpc: rpc_bundle) {
        SILKWORM_LOG(LogLevel::Info) << "Replying to " << identify(*message) << " with " << rpc->name() << "\n";

        rpc->on_receive_reply([message, rpc](auto&) { // copy message and rpc to retain their lifetime (shared_ptr) [avoid rpc passing using make_shared_from_this in AsyncCall]
            SILKWORM_LOG(LogLevel::Info) << "Received rpc result of " << identify(*message) << ": " << result(rpc) << "\n";
        });

        sentry_.exec_remotely(rpc);
    }
}

void BlockProvider::execution_loop() {
    using std::shared_ptr;
    using namespace std::chrono_literals;

    // set status
    send_status();
    std::this_thread::sleep_for(3s); // wait for connection setup before submit other requests

    // thread safe queue where receive messages from sentry thread
    MessageQueue messages{};

    // start message receiving (headers & blocks requests)
    send_message_subscription(messages); // messages will be copied in the message queue

    // message processing
    try {
        while (!exiting_) {
            process_one_message(messages);  // pop a message from the queue and process it
        }
    }
    catch(const std::exception& e) {
        SILKWORM_LOG(LogLevel::Error) << "BlockProvider execution_loop exiting due to exception: " << e.what() << "\n";
        exiting_ = true;
    }

    SILKWORM_LOG(LogLevel::Info) << "BlockProvider execution_loop exiting...\n";
}

std::string result(std::shared_ptr<SentryRpc> rpc) {
    auto sendMessageById = std::dynamic_pointer_cast<rpc::SendMessageById>(rpc);
    if (sendMessageById) {
        const sentry::SentPeers& peers = sendMessageById->reply();
        return std::to_string(peers.peers_size()) + " peer(s)";
    }

    auto sendMessageByMinBlock = std::dynamic_pointer_cast<rpc::SendMessageByMinBlock>(rpc);
    if (sendMessageByMinBlock) {
        const sentry::SentPeers& peers = sendMessageByMinBlock->reply();
        return std::to_string(peers.peers_size()) + " peer(s)";
    }

    auto peerMinBlock = std::dynamic_pointer_cast<rpc::PeerMinBlock>(rpc);
    if (peerMinBlock) {
        return "ok";  // no result
    }

    return "-todo-";
}

}  // namespace silkworm

