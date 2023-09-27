/*
   Copyright 2023 The Silkworm Authors

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

#include <chrono>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/udp.hpp>
#include <boost/signals2.hpp>

#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/discovery/node_db/node_db.hpp>

#include "message_sender.hpp"
#include "pong_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::ping {

struct PingCheckResult {
    EccPublicKey node_id;

    std::optional<std::chrono::time_point<std::chrono::system_clock>> pong_time;
    std::optional<size_t> ping_fails_count;
    std::optional<std::chrono::time_point<std::chrono::system_clock>> next_ping_time;
    std::optional<uint64_t> enr_seq_num;

    Task<void> save(node_db::NodeDb& db) const;

    [[nodiscard]] bool is_skipped() const {
        return !next_ping_time.has_value();
    }

    [[nodiscard]] bool is_success() const {
        return pong_time.has_value();
    }
};

Task<PingCheckResult> ping_check(
    EccPublicKey node_id,
    EnodeUrl local_node_url,
    uint64_t local_enr_seq_num,
    MessageSender& message_sender,
    boost::signals2::signal<void(PongMessage, EccPublicKey)>& on_pong_signal,
    node_db::NodeDb& db);

Task<PingCheckResult> ping_check(
    EccPublicKey node_id,
    boost::asio::ip::udp::endpoint endpoint,
    EnodeUrl local_node_url,
    uint64_t local_enr_seq_num,
    MessageSender& message_sender,
    boost::signals2::signal<void(PongMessage, EccPublicKey)>& on_pong_signal,
    std::optional<std::chrono::time_point<std::chrono::system_clock>> last_pong_time,
    size_t prev_ping_fails_count);

std::chrono::time_point<std::chrono::system_clock> min_valid_pong_time(
    std::chrono::time_point<std::chrono::system_clock> now);

}  // namespace silkworm::sentry::discovery::disc_v4::ping
