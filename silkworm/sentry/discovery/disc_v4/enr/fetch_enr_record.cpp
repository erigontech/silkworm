// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "fetch_enr_record.hpp"

#include <chrono>
#include <variant>

#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>

#include "enr_request_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::enr {

Task<std::optional<discovery::enr::EnrRecord>> fetch_enr_record(
    EccPublicKey node_id,
    boost::asio::ip::udp::endpoint endpoint,
    MessageSender& message_sender,
    boost::signals2::signal<void(EnrResponseMessage)>& on_enr_response_signal) {
    using namespace std::chrono_literals;
    using namespace concurrency::awaitable_wait_for_one;

    auto executor = co_await boost::asio::this_coro::executor;
    concurrency::Channel<std::optional<discovery::enr::EnrRecord>> response_channel{executor, 1};
    auto on_enr_response_handler = [&](EnrResponseMessage message) {
        if (message.record.public_key == node_id) {
            response_channel.try_send(std::move(message.record));
        }
    };

    [[maybe_unused]] boost::signals2::scoped_connection subscription(on_enr_response_signal.connect(on_enr_response_handler));

    EnrRequestMessage request_message{
        make_message_expiration(),
    };

    try {
        co_await message_sender.send_enr_request(request_message, endpoint);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
        SILK_DEBUG_M("disc_v4")
            << "fetch_enr_record failed to send_enr_request"
            << " to " << endpoint
            << " due to exception: " << ex.what();
        co_return std::nullopt;
    }

    try {
        auto record = std::get<0>(co_await (response_channel.receive() || concurrency::timeout(500ms)));
        co_return record;
    } catch (const concurrency::TimeoutExpiredError&) {
        co_return std::nullopt;
    }
}

}  // namespace silkworm::sentry::discovery::disc_v4::enr
