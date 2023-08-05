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

Task<bool> ping_check(
    EccPublicKey node_id,
    std::optional<boost::asio::ip::udp::endpoint> endpoint_opt,
    EnodeUrl local_node_url,
    MessageSender& message_sender,
    boost::signals2::signal<void(PongMessage, EccPublicKey)>& on_pong_signal,
    node_db::NodeDb& db) {
    using namespace std::chrono_literals;
    using namespace concurrency::awaitable_wait_for_one;

    if (node_id == local_node_url.public_key()) {
        assert(false);
        co_return false;
    }

    auto last_pong_time = co_await db.find_last_pong_time(node_id);
    if (last_pong_time && !is_time_in_past(pong_expiration(*last_pong_time))) {
        co_return true;
    }

    boost::asio::ip::udp::endpoint endpoint;
    if (endpoint_opt) {
        endpoint = *endpoint_opt;
    } else {
        auto address = co_await db.find_node_address_v4(node_id);
        if (!address) {
            throw std::runtime_error("ping_check: node address not found");
        }
        endpoint = boost::asio::ip::udp::endpoint(address->ip, address->port_disc);
    }

    auto executor = co_await boost::asio::this_coro::executor;
    concurrency::EventNotifier pong_received_notifier{executor};
    auto on_pong_handler = [&](PongMessage message, EccPublicKey sender_node_id) {
        if ((sender_node_id == node_id) && !is_expired_message_expiration(message.expiration)) {
            pong_received_notifier.notify();
        }
    };

    boost::signals2::scoped_connection pong_subscription(on_pong_signal.connect(on_pong_handler));

    PingMessage ping_message{
        boost::asio::ip::udp::endpoint{local_node_url.ip(), local_node_url.port_disc()},
        local_node_url.port_rlpx(),
        endpoint,
        make_message_expiration(),
    };

    try {
        co_await message_sender.send_ping(std::move(ping_message), endpoint);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
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

    if (endpoint_opt) {
        if (!co_await db.find_node_address_v4(node_id)) {
            node_db::NodeAddress address{
                endpoint.address(),
                endpoint.port(),
                /* port_rlpx = */ 0,
            };
            auto distance = node_distance(node_id, local_node_url.public_key());

            co_await db.upsert_node_address(node_id, std::move(address));
            co_await db.update_distance(node_id, distance);
        }
    }

    auto now = std::chrono::system_clock::now();
    if (is_pong_received) {
        co_await db.update_last_pong_time(node_id, now);
    }

    size_t ping_fails_count = is_pong_received ? 0 : (co_await db.find_ping_fails(node_id)).value_or(0) + 1;
    co_await db.update_ping_fails(node_id, ping_fails_count);
    co_await db.update_next_ping_time(node_id, next_ping_time(now, ping_fails_count));

    co_return is_pong_received;
}

}  // namespace silkworm::sentry::discovery::disc_v4::ping
