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

#include <zlib.h>

#include <array>
#include <exception>
#include <string_view>

#include <boost/asio/buffer.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/http/chunk_encode.hpp>
#include <boost/beast/http/write.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::http {

static constexpr std::string_view kMaxAge{"600"};
static constexpr auto kMaxPayloadSize{30 * kMebi};  // 30MiB
static constexpr std::array kAcceptedContentTypes{"application/json", "application/jsonrequest", "application/json-rpc"};

Connection::Connection(boost::asio::io_context& io_context,
                       commands::RpcApi& api,
                       commands::RpcApiTable& handler_table,
                       const std::vector<std::string>& allowed_origins,
                       std::optional<std::string> jwt_secret,
                       bool ws_upgrade_enabled,
                       bool ws_compression,
                       InterfaceLogSettings ifc_log_settings)
    : socket_{io_context},
      api_{api},
      handler_table_{handler_table},
      request_handler_{this, api, handler_table, std::move(ifc_log_settings)},
      allowed_origins_{allowed_origins},
      jwt_secret_{std ::move(jwt_secret)},
      ws_upgrade_enabled_{ws_upgrade_enabled},
      ws_compression_{ws_compression} {
    SILK_TRACE << "Connection::Connection socket " << &socket_ << " created";
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
        SILK_TRACE << "Connection::read_loop system-error: " << se.code();
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::read_loop exception: " << e.what();
    }
}

Task<bool> Connection::do_read() {
    SILK_TRACE << "Connection::do_read going to read...";

    boost::beast::http::request_parser<boost::beast::http::string_body> parser;
    auto bytes_transferred = co_await boost::beast::http::async_read(socket_, data_, parser, boost::asio::use_awaitable);

    SILK_TRACE << "Connection::do_read bytes_read: " << bytes_transferred << " [" << parser.get() << "]";

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

Task<void> Connection::do_upgrade(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    // Now that talking to the socket is successful, we tie the socket object to a WebSocket stream
    boost::beast::websocket::stream<boost::beast::tcp_stream> stream(std::move(socket_));

    auto ws_connection = std::make_shared<ws::Connection>(std::move(stream), api_, std::move(handler_table_), ws_compression_);
    co_await ws_connection->accept(req);

    auto connection_loop = [](auto websocket_connection) -> Task<void> { co_await websocket_connection->read_loop(); };

    boost::asio::co_spawn(socket_.get_executor(), connection_loop(ws_connection), boost::asio::detached);
}

Task<void> Connection::handle_request(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    if (req.method() == boost::beast::http::verb::options &&
        !req[boost::beast::http::field::access_control_request_method].empty()) {
        co_await handle_preflight(req);
    } else {
        co_await handle_actual_request(req);
    }
}

Task<void> Connection::handle_preflight(const boost::beast::http::request<boost::beast::http::string_body>& req) {
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

Task<void> Connection::handle_actual_request(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    if (req.body().empty()) {
        co_await do_write(std::string{}, boost::beast::http::status::ok);  // just like Erigon
        co_return;
    }

    if (!is_method_allowed(req.method())) {
        co_await do_write("method not allowed\n", boost::beast::http::status::method_not_allowed);
        co_return;
    }
    if (req.has_content_length() && req.body().length() > kMaxPayloadSize) {
        co_await do_write("content length too large\n", boost::beast::http::status::payload_too_large);
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
    auto encoding = req[boost::beast::http::field::accept_encoding];

    auto rsp_content = co_await request_handler_.handle(req.body());
    if (rsp_content) {
        co_await do_write(rsp_content->append("\n"), boost::beast::http::status::ok, !encoding.empty());
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

Task<void> Connection::do_write(const std::string& content, boost::beast::http::status http_status, bool compress) {
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
        if (compress) {
            const std::string compression_type = "gzip";
            res.set(boost::beast::http::field::content_encoding, compression_type);
            std::string compressed_data;
            try {
                compress_data(content, compressed_data);
            } catch (const std::exception& e) {
                SILK_ERROR << "Connection::compress_data exception: " << e.what();
                throw;
            }
            res.content_length(compressed_data.length());
            res.body() = std::move(compressed_data);
        } else {
            res.content_length(content.size());
            res.body() = std::move(content);
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

void Connection::compress_data(const std::string& clear_data, std::string& compressed_data) {
    z_stream strm;

    memset(&strm, 0, sizeof(strm));
    int ret = Z_OK;
    ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        throw std::runtime_error("deflateInit2 fail");
    }
    strm.avail_in = static_cast<unsigned int>(clear_data.size());
    auto ptr_clear = const_cast<char*>(clear_data.c_str());
    strm.next_in = reinterpret_cast<Bytef*>(ptr_clear);

    do {
        strm.next_out = reinterpret_cast<Bytef*>(temp_compressed_buffer_);
        strm.avail_out = sizeof(temp_compressed_buffer_);

        ret = deflate(&strm, Z_FINISH);
        if (ret < 0) {
            deflateEnd(&strm);
            throw std::runtime_error("deflate fail");
        }
        if (compressed_data.size() < strm.total_out) {
            // append the block to the output string
            compressed_data.append(temp_compressed_buffer_, strm.total_out - compressed_data.size());
        }
    } while (ret != Z_STREAM_END);

    deflateEnd(&strm);
}

Connection::AuthorizationResult Connection::is_request_authorized(const boost::beast::http::request<boost::beast::http::string_body>& req) {
    if (!jwt_secret_.has_value() || (*jwt_secret_).empty()) {
        return {};
    }

    auto it = req.find("Authorization");
    if (it == req.end()) {
        SILK_ERROR << "JWT request without Authorization Header: " << req.body();
        return tl::make_unexpected("missing token");
    }

    std::string client_token;
    if (it->value().substr(0, 7) == "Bearer ") {
        client_token = it->value().substr(7);
    } else {
        SILK_ERROR << "JWT client request without token";
        return tl::make_unexpected("missing token");
    }
    try {
        // Parse token
        auto decoded_client_token = jwt::decode(client_token);
        if (decoded_client_token.has_issued_at() == 0) {
            SILK_ERROR << "JWT iat (Issued At) not defined";
            return tl::make_unexpected("missing issued-at");
        }
        // Validate token
        auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::hs256{*jwt_secret_});

        SILK_TRACE << "JWT client token: " << client_token << " secret: " << *jwt_secret_;
        verifier.verify(decoded_client_token);
    } catch (const boost::system::system_error& se) {
        SILK_ERROR << "JWT invalid token: " << se.what();
        return tl::make_unexpected("invalid token");
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

}  // namespace silkworm::rpc::http
