// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stun_ip_resolver.hpp"

#include <chrono>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string_view>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/this_coro.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/common/random.hpp>

#include "address_util.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-qualifiers"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <stun++/message.h>
#pragma GCC diagnostic pop

namespace silkworm::sentry::nat {

using namespace boost::asio;

static constexpr std::string_view kStunDefaultServerHost = "stun.l.google.com";
static constexpr uint16_t kStunDefaultServerPort = 19302;

Task<ip::address> stun_ip_resolver() {
    using namespace std::chrono_literals;
    using namespace concurrency::awaitable_wait_for_one;

    auto executor = co_await this_coro::executor;

    ip::udp::endpoint endpoint;
    ip::udp::resolver resolver{executor};
    try {
        auto endpoints = co_await resolver.async_resolve(
            kStunDefaultServerHost,
            std::to_string(kStunDefaultServerPort),
            use_awaitable);
        endpoint = *endpoints.cbegin();
    } catch (const boost::system::system_error& ex) {
        std::ostringstream message;
        message << "stun_ip_resolver: failed to resolve host '" << kStunDefaultServerHost << "': ";
        message << ex.what() << ". ";
        message << "Does your internet connection work?";
        throw std::runtime_error(message.str());
    }

    ip::udp::socket socket{executor};
    co_await socket.async_connect(endpoint, use_awaitable);

    Bytes response_data(2048, 0);

    int retry_count = 3;
    while (retry_count > 0) {
        try {
            Bytes transaction_id = random_bytes(12);
            stun::message binding_request{stun::message::binding_request, transaction_id.data()};
            ByteView request_data(binding_request.data(), binding_request.size());

            co_await (socket.async_send(buffer(request_data), use_awaitable) || concurrency::timeout(1s));
            co_await (socket.async_receive(buffer(response_data), use_awaitable) || concurrency::timeout(1s));
            break;
        } catch (const concurrency::TimeoutExpiredError&) {
            --retry_count;
        }
    }

    if (retry_count == 0) {
        throw std::runtime_error("stun_ip_resolver: no response from the STUN server");
    }

    stun::message binding_response{response_data.begin(), response_data.end()};
    if (!binding_response.verify()) {
        throw std::runtime_error("stun_ip_resolver: invalid response message");
    }
    if (binding_response.type() != stun::message::binding_response) {
        throw std::runtime_error("stun_ip_resolver: unexpected response type");
    }

    std::optional<stun::attribute::decoding_bits::xor_socket_address> address_attribute;
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wambiguous-reversed-operator"
#endif
    for (auto& attribute : binding_response) {
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
        if (attribute.type() == stun::attribute::type::xor_mapped_address) {
            address_attribute = attribute.to<stun::attribute::type::xor_mapped_address>();
        }
    }

    if (!address_attribute) {
        throw std::runtime_error("stun_ip_resolver: address attribute not found in response");
    }

    sockaddr_storage address_storage{};
    auto address = reinterpret_cast<sockaddr*>(&address_storage);
    bool ok = address_attribute->to_sockaddr(address);
    if (!ok) {
        throw std::runtime_error("stun_ip_resolver: failed to parse the address attribute");
    }

    co_return make_address_from_sockaddr(address);
}

}  // namespace silkworm::sentry::nat
