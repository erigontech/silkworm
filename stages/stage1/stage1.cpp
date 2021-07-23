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
Stage1::Stage1(ChainIdentity chain_identity, std::string db_path, std::string sentry_addr):
    chain_identity_(std::move(chain_identity)),
    db_{db_path},
    sentry_{sentry_addr}
{
}

Stage1::~Stage1() {
    SILKWORM_LOG(LogLevel::Error) << "stage1 destroyed\n";
}

auto Stage1::wind([[maybe_unused]] BlockNum new_height) -> StageResult {
    // todo: to implement in the next PR, this is only the code of the "reponder"
    return StageResult::OK;
}

auto Stage1::unwind([[maybe_unused]] BlockNum new_height) -> StageResult {
    // todo: to implement in the next PR, this is only the code of the "reponder"
    return StageResult::OK;
}

void Stage1::receive_one_message() {
    // check the gRPC queue, and trigger gRPC processing (gRPC will create a message)
    auto executed_rpc = sentry_.receive_one_result();

    // log gRPC termination
    if (executed_rpc && executed_rpc->terminated()) {
        auto status = executed_rpc->status();
        if (status.ok())
            SILKWORM_LOG(LogLevel::Trace) << "RPC ok, " << executed_rpc->name() << "\n";
        else
        SILKWORM_LOG(LogLevel::Warn)
            << "RPC failed, " << executed_rpc->name() << ", error: '" << status.error_message()
            << "', code: " << status.error_code() << ", details: " << status.error_details() << std::endl;
    }
}

void Stage1::process_one_message(MessageQueue& messages) {
    using namespace std::chrono_literals;

    std::shared_ptr<Message> message;
    bool present = messages.timed_wait_and_pop(message, 1000ms);
    if (!present) return;   // timeout, needed to check exiting_

    if (std::dynamic_pointer_cast<InboundMessage>(message)) {
        SILKWORM_LOG(LogLevel::Info) << "Processing message " << *message << "\n";
    }

    auto rpc_bundle = message->execute();
    if (rpc_bundle.empty()) return;

    for(auto& rpc: rpc_bundle) {
        SILKWORM_LOG(LogLevel::Info) << "Replying to " << identify(*message) << " with " << rpc->name() << "\n";

        rpc->on_receive_reply([message, rpc, &messages](auto&) { // copy message and rpc to retain their lifetime (shared_ptr) [avoid rpc passing using make_shared_from_this in AsyncCall]
          SILKWORM_LOG(LogLevel::Info) << "Received rpc result of " << identify(*message) << ": " << result(rpc) << "\n";
        });

        sentry_.exec_remotely(rpc);
    }
}

void Stage1::send_status() {
    auto [head_hash, head_td] = HeaderLogic::head_hash_and_total_difficulty(db_);
    auto set_status = rpc::SetStatus::make(chain_identity_.chain, chain_identity_.genesis_hash,
                                           chain_identity_.distinct_fork_numbers(), head_hash, head_td);
    set_status->on_receive_reply([&, set_status](auto& call) {
      if (!call.status().ok()) {
          exiting_ = true;
          SILKWORM_LOG(LogLevel::Critical)
              << "failed to set status to the remote sentry, cause:'" << call.status().error_message() << "', exiting...\n";
          return;
      }
      SILKWORM_LOG(LogLevel::Trace) << "set-status reply arrived\n";
      sentry::SetStatusReply& reply = set_status->reply();
      sentry::Protocol supported_protocol = reply.protocol();
      if (supported_protocol != sentry::Protocol::ETH66) {
          exiting_ = true;
          SILKWORM_LOG(LogLevel::Critical) << "sentry do not support eth/66 protocol, exiting...\n";
      }
    });
    sentry_.exec_remotely(set_status);
}

void Stage1::send_message_subscription(MessageQueue& messages) {
    auto receive_messages = rpc::ReceiveMessages::make();
    receive_messages->on_receive_reply([&, receive_messages](auto& call) {
      SILKWORM_LOG(LogLevel::Trace) << "receive-messages reply arrived\n";
      if (!call.terminated()) {
          sentry::InboundMessage& reply = receive_messages->reply();
          auto message = InboundMessage::make(reply);
          if (message) {
              SILKWORM_LOG(LogLevel::Info) << "Message received from remote peer " << identify(*message) << "\n";
              messages.push(message);
          }
      }
      else {
          exiting_ = true;
          SILKWORM_LOG(LogLevel::Critical)
              << "receiving messages stream interrupted, cause:'" << call.status().error_message() << "', exiting...\n";
      }
    });
    sentry_.exec_remotely(receive_messages);
}

void Stage1::execution_loop() { // no-thread version
    using std::shared_ptr;
    using namespace std::chrono_literals;

    MessageQueue messages{};

    // set chain limits
    //BlockNum head_height = HeaderLogic::head_height(db_);
    //working_chain_.highest_block_in_db(head_height); // the second limit will be set at the each block announcements

    // handling async rpc
    std::thread rpc_handling{[&]() {
        try {
            while (!exiting_) {
                receive_one_message();
            }
        }
        catch(const std::exception& e) {
            SILKWORM_LOG(LogLevel::Error) << "rpc_handling exception: " << e.what() << "\n";
            exiting_ = true;
        }
      SILKWORM_LOG(LogLevel::Info) << "rpc_handling thread exiting...\n";
    }};

    // set status
    send_status();
    std::this_thread::sleep_for(3s); // wait for connection setup before submit other requests

    // start message receiving (headers & blocks announcements & requests)
    send_message_subscription(messages);

    // message processing
    std::thread message_processing{[&]() {
      try {
        while (!exiting_) {
            process_one_message(messages);
        }
      }
      catch(const std::exception& e) {
          SILKWORM_LOG(LogLevel::Error) << "message_processing exception: " << e.what() << "\n";
          exiting_ = true;
      }
      SILKWORM_LOG(LogLevel::Info) << "message_processing thread exiting...\n";
    }};

    // wait exiting ---------------------------------------------------------------------------------------------------
    rpc_handling.join();
    message_processing.join();
    SILKWORM_LOG(LogLevel::Info) << "Stage1 execution_loop exiting...\n";
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

