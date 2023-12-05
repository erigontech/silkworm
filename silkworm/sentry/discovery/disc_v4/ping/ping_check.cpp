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

#include "ping_check.hpp"

#include <cassert>
#include <stdexcept>

#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/ipv6_unsupported_error.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_distance.hpp>

namespace silkworm::sentry::discovery::disc_v4::ping {

static const std::chrono::hours kPongValidityPeriod{24};

static std::chrono::time_point<std::chrono::system_clock> pong_expiration(std::chrono::time_point<std::chrono::system_clock> last_pong_time) {
    return last_pong_time + kPongValidityPeriod;
}

std::chrono::time_point<std::chrono::system_clock> min_valid_pong_time(std::chrono::time_point<std::chrono::system_clock> now) {
    return now - kPongValidityPeriod;
}

static std::chrono::minutes next_ping_delay(size_t ping_fails) {
    using namespace std::chrono_literals;
    if (ping_fails < 3)
        return 10min;

    // back off: double for each next retry
    return std::chrono::hours(1 << (ping_fails - 3));
}

static std::chrono::time_point<std::chrono::system_clock> next_ping_time(std::chrono::time_point<std::chrono::system_clock> now, size_t ping_fails) {
    return now + next_ping_delay(ping_fails);
}

Task<PingCheckResult> ping_check(
    EccPublicKey node_id,
    EnodeUrl local_node_url,
    uint64_t local_enr_seq_num,
    MessageSender& message_sender,
    boost::signals2::signal<void(PongMessage, EccPublicKey)>& on_pong_signal,
    node_db::NodeDb& db) {
    auto address = co_await db.find_node_address(node_id);
    if (!address) {
        throw std::runtime_error("ping_check: node address not found");
    }
    auto endpoint = address->to_common_address().endpoint;

    auto last_pong_time = co_await db.find_last_pong_time(node_id);
    auto ping_fails_count = co_await db.find_ping_fails(node_id);

    auto result = co_await ping_check(
        std::move(node_id),
        std::move(endpoint),
        std::move(local_node_url),
        local_enr_seq_num,
        message_sender,
        on_pong_signal,
        std::move(last_pong_time),
        ping_fails_count.value_or(0));

    co_return result;
}

Task<void> PingCheckResult::save(node_db::NodeDb& db) const {
    auto& result = *this;
    if (result.ping_fails_count)
        co_await db.update_ping_fails(node_id, *result.ping_fails_count);
    if (result.next_ping_time)
        co_await db.update_next_ping_time(node_id, *result.next_ping_time);
    if (result.pong_time)
        co_await db.update_last_pong_time(node_id, *result.pong_time);
}

Task<PingCheckResult> ping_check(
    EccPublicKey node_id,
    boost::asio::ip::udp::endpoint endpoint,
    EnodeUrl local_node_url,
    uint64_t local_enr_seq_num,
    MessageSender& message_sender,
    boost::signals2::signal<void(PongMessage, EccPublicKey)>& on_pong_signal,
    std::optional<std::chrono::time_point<std::chrono::system_clock>> last_pong_time,
    size_t prev_ping_fails_count) {
    using namespace std::chrono_literals;
    using namespace concurrency::awaitable_wait_for_one;

    if (node_id == local_node_url.public_key()) {
        assert(false);
        co_return PingCheckResult{std::move(node_id)};
    }

    if (last_pong_time && !is_time_in_past(pong_expiration(*last_pong_time))) {
        co_return PingCheckResult{std::move(node_id)};
    }

    auto executor = co_await boost::asio::this_coro::executor;
    concurrency::EventNotifier pong_received_notifier{executor};
    std::optional<uint64_t> enr_seq_num;
    auto on_pong_handler = [&](PongMessage message, EccPublicKey sender_node_id) {
        if ((sender_node_id == node_id) && !is_expired_message_expiration(message.expiration)) {
            enr_seq_num = message.enr_seq_num;
            pong_received_notifier.notify();
        }
    };

    [[maybe_unused]] boost::signals2::scoped_connection pong_subscription(on_pong_signal.connect(on_pong_handler));

    PingMessage ping_message{
        boost::asio::ip::udp::endpoint{local_node_url.ip(), local_node_url.port_disc()},
        local_node_url.port_rlpx(),
        endpoint,
        make_message_expiration(),
        local_enr_seq_num,
    };

    try {
        co_await message_sender.send_ping(std::move(ping_message), endpoint);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
        log::Debug("disc_v4") << "ping_check failed to send_ping"
                              << " to " << endpoint
                              << " due to exception: " << ex.what();
    } catch (const IPV6UnsupportedError& ex) {
        log::Debug("disc_v4") << "ping_check failed to send_ping"
                              << " to " << endpoint
                              << " due to exception: " << ex.what();
    }

    bool is_pong_received = false;
    try {
        co_await (pong_received_notifier.wait() || concurrency::timeout(500ms));
        is_pong_received = true;
    } catch (const concurrency::TimeoutExpiredError&) {
    }

    auto now = std::chrono::system_clock::now();
    auto pong_time = is_pong_received ? std::optional{now} : std::nullopt;
    size_t ping_fails_count = is_pong_received ? 0 : prev_ping_fails_count + 1;
    auto next_ping_time1 = next_ping_time(now, ping_fails_count);

    co_return PingCheckResult{
        std::move(node_id),
        std::move(pong_time),
        ping_fails_count,
        std::move(next_ping_time1),
        std::move(enr_seq_num),
    };
}

}  // namespace silkworm::sentry::discovery::disc_v4::ping
