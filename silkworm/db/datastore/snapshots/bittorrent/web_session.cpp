// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "web_session.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/url/parse.hpp>

#include <silkworm/infra/common/log.hpp>

#include "root_certificates.hpp"

namespace silkworm::snapshots::bittorrent {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
namespace urls = boost::urls;

//! The timeout for HTTP asynchronous operations
static constexpr std::chrono::seconds kHttpTimeoutSecs{30};

WebSession::WebSession(std::optional<std::string> server_certificate)
    : server_certificate_(std::move(server_certificate)) {}

Task<WebSession::StringResponse> WebSession::https_get(const urls::url& web_url,
                                                       std::string_view target_file,
                                                       const HeaderFields& custom_fields) const {
    // The SSL context which holds root certificate used for verification ()
    ssl::context ssl_ctx{ssl::context::tlsv13_client};
    load_root_certificates(ssl_ctx, server_certificate_);
    ssl_ctx.set_verify_mode(ssl::verify_peer);  // Ask to verify the remote server certificate

    // These objects perform our I/O
    net::ip::tcp::resolver resolver{co_await net::this_coro::executor};
    beast::ssl_stream<beast::tcp_stream> ssl_stream{co_await net::this_coro::executor, ssl_ctx};
    beast::tcp_stream& tcp_stream = beast::get_lowest_layer(ssl_stream);

    // Set SNI Hostname (many hosts need this to handshake successfully)
    const std::string host{web_url.host()};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"  // SSL_set_tlsext_host_name casts to (void*)
    if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(), host.c_str())) {
        beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
        throw beast::system_error{ec, "error setting SNI hostname"};
    }
#pragma GCC diagnostic pop

    const std::string port{web_url.has_port() ? web_url.port() : "443"};

    // Look up the domain name
    const auto resolve_results = co_await resolver.async_resolve(host, port, net::use_awaitable);

    // Make the connection on the IP address we get from a lookup
    tcp_stream.expires_after(kHttpTimeoutSecs);
    co_await tcp_stream.async_connect(resolve_results, net::use_awaitable);

    // Perform the SSL handshake
    tcp_stream.expires_after(kHttpTimeoutSecs);
    co_await ssl_stream.async_handshake(ssl::stream_base::client, net::use_awaitable);

    // Setup the HTTP GET request message
    http::request<http::empty_body> req{http::verb::get, target_file, kHttpVersion};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    include_custom_headers(req, custom_fields);
    SILK_TRACE << "WebSeedClient::http_session HTTP request: " << req;

    // Send the HTTP request to the remote host
    tcp_stream.expires_after(kHttpTimeoutSecs);
    const auto written_bytes = co_await http::async_write(ssl_stream, req, net::use_awaitable);
    SILK_TRACE << "WebSeedClient::http_session HTTP request written_bytes: " << written_bytes;

    // This buffer is used for reading
    beast::flat_buffer data;

    // Declare a container to hold the response
    http::response<http::string_body> response;

    // Receive the HTTP response
    tcp_stream.expires_after(kHttpTimeoutSecs);
    const auto read_bytes = co_await http::async_read(ssl_stream, data, response, net::use_awaitable);
    SILK_TRACE << "WebSeedClient::http_session HTTP read_bytes: " << read_bytes << " response: " << response;

    // Gracefully close the stream
    try {
        tcp_stream.expires_after(kHttpTimeoutSecs);
        co_await ssl_stream.async_shutdown(net::use_awaitable);
    } catch (const beast::system_error& se) {
        // Swallow shutdown errors due to misbehaviour of some web servers:
        // https://github.com/boostorg/beast/issues/38, https://github.com/boostorg/beast/issues/824
        if (se.code() != net::error::eof && se.code() != net::ssl::error::stream_truncated) {
            throw;
        }
    }

    co_return response;
}

void WebSession::include_custom_headers(EmptyRequest& request, const HeaderFields& custom_fields) {
    for (const auto [field_name, field_value] : custom_fields) {
        request.set(field_name, field_value);
    }
}

}  // namespace silkworm::snapshots::bittorrent
