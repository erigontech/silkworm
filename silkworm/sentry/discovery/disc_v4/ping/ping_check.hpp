// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

    bool is_skipped() const {
        return !next_ping_time.has_value();
    }

    bool is_success() const {
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
