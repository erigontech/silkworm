// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "find_neighbors.hpp"

#include <chrono>
#include <map>
#include <stdexcept>
#include <variant>

#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/ip_classify.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_distance.hpp>

namespace silkworm::sentry::discovery::disc_v4::find {

Task<size_t> find_neighbors(
    EccPublicKey node_id,
    EccPublicKey local_node_id,
    MessageSender& message_sender,
    boost::signals2::signal<void(NeighborsMessage, EccPublicKey)>& on_neighbors_signal,
    node_db::NodeDb& db) {
    using namespace std::chrono_literals;
    using namespace concurrency::awaitable_wait_for_one;

    auto address = co_await db.find_node_address(node_id);
    if (!address) {
        throw std::runtime_error("find_neighbors: node address not found");
    }
    auto endpoint = address->to_common_address().endpoint;

    auto executor = co_await boost::asio::this_coro::executor;
    concurrency::Channel<std::map<EccPublicKey, NodeAddress>> neighbors_channel{executor, 2};
    auto on_neighbors_handler = [&](NeighborsMessage message, const EccPublicKey& sender_node_id) {
        if ((sender_node_id == node_id) && !is_expired_message_expiration(message.expiration)) {
            neighbors_channel.try_send(std::move(message.node_addresses));
        }
    };

    boost::signals2::scoped_connection neighbors_subscription(on_neighbors_signal.connect(on_neighbors_handler));

    FindNodeMessage find_node_message{
        local_node_id,
        make_message_expiration(),
    };

    try {
        co_await message_sender.send_find_node(std::move(find_node_message), endpoint);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
        SILK_DEBUG_M("disc_v4")
            << "find_neighbors failed to send_find_node"
            << " to " << endpoint
            << " due to exception: " << ex.what();
        co_return 0;
    }

    std::map<EccPublicKey, NodeAddress> neighbors_node_addresses;
    try {
        neighbors_node_addresses = std::get<0>(co_await (neighbors_channel.receive() || concurrency::timeout(500ms)));
    } catch (const concurrency::TimeoutExpiredError&) {
        co_return 0;
    }

    for (auto& [neighbor_id, neighbor_node_address] : neighbors_node_addresses) {
        auto ip = neighbor_node_address.endpoint.address();
        if (ip_classify(ip) != IpAddressType::kRegular) {
            continue;
        }
        if (neighbor_id == local_node_id) {
            continue;
        }

        auto distance = node_distance(neighbor_id, local_node_id);

        co_await db.upsert_node_address(neighbor_id, neighbor_node_address);
        co_await db.update_distance(neighbor_id, distance);
    }

    co_return neighbors_node_addresses.size();
}

}  // namespace silkworm::sentry::discovery::disc_v4::find
