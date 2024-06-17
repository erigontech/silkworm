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

#include "connection.hpp"

#include <array>
#include <chrono>
#include <exception>
#include <string_view>

#include <boost/asio/buffer.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/http/chunk_encode.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::http {

using namespace std::chrono_literals;

static constexpr std::string_view kMaxAge{"600"};
static constexpr auto kMaxPayloadSize{30 * kMebi};  // 30MiB
static constexpr std::array kAcceptedContentTypes{"application/json", "application/jsonrequest", "application/json-rpc"};
static constexpr auto kGzipEncoding{"gzip"};
static constexpr auto kBearerTokenPrefix{"Bearer "sv};  // space matters: format is `Bearer <token>`

Task<void> Connection::run_read_loop(std::shared_ptr<Connection> connection) {
    co_await connection->read_loop();
}

Connection::Connection(boost::asio::ip::tcp::socket socket,
                       RequestHandlerFactory& handler_factory,
                       const std::vector<std::string>& allowed_origins,
                       std::optional<std::string> jwt_secret,
                       bool ws_upgrade_enabled,
                       bool ws_compression,
                       bool http_compression,
                       WorkerPool& workers)
    : socket_{std::move(socket)},
      handler_factory_{handler_factory},
      handler_{handler_factory_(this)},
      allowed_origins_{allowed_origins},
      jwt_secret_{std ::move(jwt_secret)},
      ws_upgrade_enabled_{ws_upgrade_enabled},
      ws_compression_{ws_compression},
      http_compression_{http_compression},
      workers_{workers} {
    socket_.set_option(boost::asio::ip::tcp::socket::keep_alive(true));
    SILK_TRACE << "Connection::Connection created for " << socket_.remote_endpoint();
}

Connection::~Connection() {
    socket_.close();
    SILK_TRACE << "Connection::~Connection socket " << &socket_ << " deleted";
}

Task<void> Connection::read_loop() {
    try {
        bool continue_processing{true};
        while (continue_processing) {
            continue_processing = co_await do_read();
        }
    } catch (const boost::system::system_error& se) {
        if (se.code() == boost::beast::http::error::end_of_stream) {
            SILK_TRACE << "Connection::read_loop received graceful close from " << socket_.remote_endpoint();
        } else {
            SILK_TRACE << "Connection::read_loop system_error: " << se.code();
        }
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::read_loop exception: " << e.what();
    }
}

Task<bool> Connection::do_read() {
    SILK_TRACE << "Connection::do_read going to read...";

    boost::beast::http::request_parser<boost::beast::http::string_body> parser;
    parser.body_limit(kMaxPayloadSize);

    const auto bytes_transferred = co_await boost::beast::http::async_read(socket_, data_, parser, boost::asio::use_awaitable);
    SILK_TRACE << "Connection::do_read bytes_read: " << bytes_transferred << " message: " << parser.get();

    if (!parser.is_done()) {
        co_return true;
    }
    request_keep_alive_ = parser.get().keep_alive();
    request_http_version_ = parser.get().version();

    if (boost::beast::websocket::is_upgrade(parser.get())) {
        if (const auto auth_result = is_request_authorized(parser.get()); !auth_result) {
            co_await do_write(auth_result.error() + "\n", boost::beast::http::status::forbidden);
            co_return false;
        }

        if (ws_upgrade_enabled_) {
            co_await do_upgrade(parser.release());
            co_return false;
        } else {
            // If it does not (or cannot) upgrade the connection, it ignores the Upgrade header and sends back a regular response (OK)
            co_await do_write("", boost::beast::http::status::ok);
        }
        co_return true;
    }

    co_await handle_request(parser.release());
    co_return true;
}

Task<void> Connection::do_upgrade(const RequestWithStringBody& req) {
    // Now that talking to the socket is successful, we tie the socket object to a WebSocket stream
    boost::beast::websocket::stream<boost::beast::tcp_stream> stream(std::move(socket_));

    auto ws_connection = std::make_shared<ws::Connection>(std::move(stream), handler_factory_, ws_compression_);
    co_await ws_connection->accept(req);

    auto connection_loop = [](auto websocket_connection) -> Task<void> { co_await websocket_connection->read_loop(); };

    boost::asio::co_spawn(socket_.get_executor(), connection_loop(ws_connection), boost::asio::detached);
}

Task<void> Connection::handle_request(const RequestWithStringBody& req) {
    if (req.method() == boost::beast::http::verb::options &&
        !req[boost::beast::http::field::access_control_request_method].empty()) {
        co_await handle_preflight(req);
    } else {
        co_await handle_actual_request(req);
    }
}

Task<void> Connection::handle_preflight(const RequestWithStringBody& req) {
    boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::no_content, request_http_version_};
    std::string vary = req[boost::beast::http::field::vary];

    if (vary.empty()) {
        res.set(boost::beast::http::field::vary, "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
    } else {
        vary.append(" Origin");
        res.set(boost::beast::http::field::vary, vary);
    }

    std::string origin = req[boost::beast::http::field::origin];
    if (!origin.empty() && is_origin_allowed(allowed_origins_, origin) && is_method_allowed(req.method())) {
        if (allowed_origins_.at(0) == "*") {
            res.set(boost::beast::http::field::access_control_allow_origin, "*");
        } else {
            res.set(boost::beast::http::field::access_control_allow_origin, origin);
        }

        res.set(boost::beast::http::field::access_control_request_method, req[boost::beast::http::field::access_control_request_method]);
        res.set(boost::beast::http::field::access_control_allow_headers, "*");
        res.set(boost::beast::http::field::access_control_max_age, kMaxAge);
    }

    res.prepare_payload();
    co_await boost::beast::http::async_write(socket_, res, boost::asio::use_awaitable);
}

Task<void> Connection::handle_actual_request(const RequestWithStringBody& req) {
    if (req.body().empty()) {
        co_await do_write(std::string{}, boost::beast::http::status::ok);  // just like Erigon
        co_return;
    }

    const auto accept_encoding = req[boost::beast::http::field::accept_encoding];
    if (!http_compression_ && !accept_encoding.empty()) {
        co_await do_write("unsupported compression\n", boost::beast::http::status::unsupported_media_type, "identity");
        co_return;
    }

    const bool gzip_encoding_requested{accept_encoding.contains(kGzipEncoding)};
    if (http_compression_ && !accept_encoding.empty() && !gzip_encoding_requested) {
        co_await do_write("unsupported requested compression\n", boost::beast::http::status::unsupported_media_type, kGzipEncoding);
        co_return;
    }

    // Check HTTP method and content type [max body size is limited using beast::http::request_parser::body_limit in do_read]
    if (!is_method_allowed(req.method())) {
        co_await do_write("method not allowed\n", boost::beast::http::status::method_not_allowed);
        co_return;
    }
    if (req.method() != boost::beast::http::verb::options && req.method() != boost::beast::http::verb::get) {
        if (!is_accepted_content_type(req[boost::beast::http::field::content_type])) {
            co_await do_write("invalid content type\n, only application/json is supported\n", boost::beast::http::status::bad_request);
            co_return;
        }
    }

    SILK_TRACE << "Connection::handle_request body size: " << req.body().size() << " data: " << req.body();

    if (const auto auth_result = is_request_authorized(req); !auth_result) {
        co_await do_write(auth_result.error() + "\n", boost::beast::http::status::forbidden);
        co_return;
    }

    // Save few fields of the request to be used in set_cors
    vary_ = req[boost::beast::http::field::vary];
    origin_ = req[boost::beast::http::field::origin];
    method_ = req.method();

    auto rsp_content = co_await handler_->handle(req.body());
    if (rsp_content) {
        co_await do_write(rsp_content->append("\n"), boost::beast::http::status::ok, gzip_encoding_requested ? kGzipEncoding : "");
    }
}

//! Write chunked response headers
Task<void> Connection::open_stream() {
    try {
        boost::beast::http::response<boost::beast::http::empty_body> rsp{boost::beast::http::status::ok, request_http_version_};
        rsp.set(boost::beast::http::field::content_type, "application/json");
        rsp.set(boost::beast::http::field::date, get_date_time());
        rsp.chunked(true);

        set_cors(rsp);

        boost::beast::http::response_serializer<boost::beast::http::empty_body> serializer{rsp};

        co_await async_write_header(socket_, serializer, boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::open_stream system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::open_stream exception: " << e.what();
        throw;
    }
    co_return;
}

Task<void> Connection::close_stream() {
    try {
        co_await boost::asio::async_write(socket_, boost::beast::http::make_chunk_last(), boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::close system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::close exception: " << e.what();
        throw;
    }
    co_return;
}

//! Write chunked response content to the underlying socket
Task<std::size_t> Connection::write(std::string_view content, bool /*last*/) {
    unsigned long bytes_transferred{0};
    try {
        boost::asio::const_buffer buffer{content.data(), content.size()};
        bytes_transferred = co_await boost::asio::async_write(socket_, boost::beast::http::chunk_body(buffer), boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::write exception: " << e.what();
        throw;
    }

    SILK_TRACE << "Connection::write bytes_transferred: " << bytes_transferred;
    co_return bytes_transferred;
}

Task<void> Connection::do_write(const std::string& content, boost::beast::http::status http_status, const std::string& content_encoding) {
    try {
        SILK_TRACE << "Connection::do_write response: " << http_status << " content: " << content;
        boost::beast::http::response<boost::beast::http::string_body> res{http_status, request_http_version_};

        if (http_status != boost::beast::http::status::ok) {
            res.set(boost::beast::http::field::content_type, "text/plain");
        } else {
            res.set(boost::beast::http::field::content_type, "application/json");
        }

        res.set(boost::beast::http::field::date, get_date_time());
        res.erase(boost::beast::http::field::host);
        res.keep_alive(request_keep_alive_);
        if (http_status == boost::beast::http::status::ok && !content_encoding.empty()) {
            // Positive response w/ compression required
            res.set(boost::beast::http::field::content_encoding, content_encoding);
            std::string compressed_content;

            co_await compress(content, compressed_content);

            res.content_length(compressed_content.length());
            res.body() = std::move(compressed_content);
        } else {
            // Any negative response or positive response w/o compression
            if (!content_encoding.empty()) {
                res.set(boost::beast::http::field::accept_encoding, content_encoding);  // Indicate the supported encoding
            }
            res.content_length(content.size());
            res.body() = content;
        }

        set_cors<boost::beast::http::string_body>(res);

        res.prepare_payload();
        const auto bytes_transferred = co_await boost::beast::http::async_write(socket_, res, boost::asio::use_awaitable);

        SILK_TRACE << "Connection::do_write bytes_transferred: " << bytes_transferred;
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::do_write system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::do_write exception: " << e.what();
        throw;
    }
    co_return;
}

Connection::AuthorizationResult Connection::is_request_authorized(const RequestWithStringBody& req) {
    if (!jwt_secret_.has_value() || (*jwt_secret_).empty()) {
        return {};
    }

    // Bearer authentication system: HTTP Authorization header with expected value `Bearer <token>`
    const auto authorization_it = req.find("Authorization");
    if (authorization_it == req.end()) {
        SILK_ERROR << "HTTP request without Authorization header received from " << socket_.remote_endpoint();
        return tl::make_unexpected("missing token");
    }

    std::string client_token;
    const auto authorization_value{authorization_it->value()};
    if (authorization_value.starts_with(kBearerTokenPrefix)) {
        client_token = authorization_value.substr(kBearerTokenPrefix.size());
    } else {
        SILK_ERROR << "HTTP request without Bearer token in Authorization header received from " << socket_.remote_endpoint();
        return tl::make_unexpected("missing token");
    }
    try {
        // Parse JWT token payload
        const auto decoded_client_token = jwt::decode(client_token);
        if (decoded_client_token.has_issued_at() == 0) {
            SILK_ERROR << "JWT iat (issued-at) claim not present in token received from " << socket_.remote_endpoint();
            return tl::make_unexpected("missing issued-at claim");
        }
        // Ensure JWT iat timestamp is within +-60 seconds from the current time
        // https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md#jwt-claims
        const auto issued_at_timestamp{decoded_client_token.get_issued_at()};
        const auto current_timestamp{std::chrono::system_clock::now()};
        if (std::chrono::abs(std::chrono::duration_cast<std::chrono::seconds>(current_timestamp - issued_at_timestamp)) > 60s) {
            SILK_ERROR << "JWT iat (issued-at) claim not present in token received from " << socket_.remote_endpoint();
            return tl::make_unexpected("invalid issued-at claim");
        }
        // Validate received JWT token
        const auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{*jwt_secret_});
        SILK_TRACE << "JWT client token: " << client_token << " secret: " << *jwt_secret_;
        verifier.verify(decoded_client_token);
    } catch (const std::system_error& se) {
        SILK_ERROR << "JWT invalid token: " << se.what();
        return tl::make_unexpected(se.what());
    } catch (const std::exception& se) {
        SILK_ERROR << "JWT invalid token: " << se.what();
        return tl::make_unexpected("invalid token");
    }
    return {};
}

template <class Body>
void Connection::set_cors(boost::beast::http::response<Body>& res) {
    if (vary_.empty()) {
        res.set(boost::beast::http::field::vary, "Origin");
    } else {
        vary_.append(" Origin");
        res.set(boost::beast::http::field::vary, vary_);
    }

    if (origin_.empty()) {
        return;
    }

    if (!is_origin_allowed(allowed_origins_, origin_)) {
        return;
    }

    if (!is_method_allowed(method_)) {
        return;
    }

    if (allowed_origins_.at(0) == "*") {
        res.set(boost::beast::http::field::access_control_allow_origin, "*");
    } else {
        res.set(boost::beast::http::field::access_control_allow_origin, origin_);
    }
}

bool Connection::is_origin_allowed(const std::vector<std::string>& allowed_origins, const std::string& origin) {
    if (allowed_origins.size() == 1 && allowed_origins[0] == "*") {
        return true;
    }

    if (std::ranges::any_of(allowed_origins, [&](const auto& allowed) { return origin == allowed; })) {
        return true;
    }
    return false;
}

bool Connection::is_accepted_content_type(const std::string& req_content_type) {
    return std::ranges::any_of(kAcceptedContentTypes, [&](const auto& content_type) { return req_content_type == content_type; });
}

bool Connection::is_method_allowed(boost::beast::http::verb method) {
    return (method == boost::beast::http::verb::options ||
            method == boost::beast::http::verb::post ||
            method == boost::beast::http::verb::get);
}

std::string Connection::get_date_time() {
    static const absl::TimeZone tz{absl::LocalTimeZone()};
    const absl::Time now{absl::Now()};

    std::stringstream ss;
    ss << absl::FormatTime("%a, %d %b %E4Y %H:%M:%S ", now, tz) << tz.name();
    return ss.str();
}

Task<void> Connection::compress(const std::string& clear_data, std::string& compressed_data) {
    boost::iostreams::filtering_ostream out;
    co_await async_task(workers_.executor(), [&]() -> void {
#ifndef SILKWORM_SANITIZE
        out.push(boost::iostreams::gzip_compressor());
#endif
        out.push(boost::iostreams::back_inserter(compressed_data));
        boost::iostreams::copy(boost::make_iterator_range(clear_data), out);
    });
}

}  // namespace silkworm::rpc::http
