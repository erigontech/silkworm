// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "connection.hpp"

#include <array>
#include <chrono>
#include <exception>
#include <shared_mutex>
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
#include <silkworm/rpc/http/deflater.hpp>

namespace silkworm::rpc::http {

using namespace std::chrono_literals;

static constexpr std::string_view kMaxAge{"600"};
static constexpr uint64_t kMaxPayloadSize = 30 * kMebi;  // 30MiB
static constexpr std::array kAcceptedContentTypes{"application/json", "application/jsonrequest", "application/json-rpc"};
static constexpr std::string_view kGzipEncoding{"gzip"};
static constexpr std::string_view kIdentity{"Identity"};
static constexpr std::string_view kBearerTokenPrefix{"Bearer "};  // space matters: format is `Bearer <token>`

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
                       WorkerPool& workers,
                       bool erigon_json_rpc_compatibility)
    : socket_{std::move(socket)},
      handler_factory_{handler_factory},
      handler_{handler_factory_(this)},
      allowed_origins_{allowed_origins},
      jwt_secret_{std ::move(jwt_secret)},
      ws_upgrade_enabled_{ws_upgrade_enabled},
      ws_compression_{ws_compression},
      http_compression_{http_compression},
      workers_{workers},
      erigon_json_rpc_compatibility_{erigon_json_rpc_compatibility} {
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

    auto req = parser.release();
    const auto accept_encoding = req[boost::beast::http::field::accept_encoding];
    auto gzip_encoding_requested = accept_encoding.contains(kGzipEncoding) && http_compression_;

    RequestData request_data{
        .request_keep_alive = parser.get().keep_alive(),
        .request_http_version = parser.get().version(),
        .gzip_encoding_requested = gzip_encoding_requested,
        .vary = req[boost::beast::http::field::vary],
        .origin = req[boost::beast::http::field::origin],
        .method = req.method(),
    };

    if (boost::beast::websocket::is_upgrade(parser.get())) {
        if (const auto auth_result = is_request_authorized(parser.get()); !auth_result) {
            co_await do_write(auth_result.error() + "\n", boost::beast::http::status::forbidden, request_data);
            co_return false;
        }

        if (ws_upgrade_enabled_) {
            co_await do_upgrade(parser.release());
            co_return false;
        } else {
            // If it does not (or cannot) upgrade the connection, it ignores the Upgrade header and sends back a regular response (OK)
            co_await do_write("", boost::beast::http::status::ok, request_data);
        }
        co_return true;
    }

    co_await handle_request(req, request_data);
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

Task<void> Connection::handle_request(const RequestWithStringBody& req, RequestData& request_data) {
    if (req.method() == boost::beast::http::verb::options &&
        !req[boost::beast::http::field::access_control_request_method].empty()) {
        co_await handle_preflight(req, request_data);
    } else {
        co_await handle_actual_request(req, request_data);
    }
}

Task<void> Connection::handle_preflight(const RequestWithStringBody& req, RequestData& request_data) {
    boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::no_content, request_data.request_http_version};
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

Task<void> Connection::handle_actual_request(const RequestWithStringBody& req, RequestData& request_data) {
    const auto accept_encoding = req[boost::beast::http::field::accept_encoding];

    if (req.body().empty()) {
        co_await do_write(std::string{}, boost::beast::http::status::ok, request_data);  // just like Erigon
        co_return;
    }

    if (!http_compression_ && !accept_encoding.empty() && !erigon_json_rpc_compatibility_) {
        co_await do_write("unsupported compression\n", boost::beast::http::status::unsupported_media_type, request_data, "identity");
        co_return;
    }

    if (http_compression_ && !accept_encoding.empty() && !accept_encoding.contains(kIdentity) && !request_data.gzip_encoding_requested) {
        co_await do_write("unsupported requested compression\n", boost::beast::http::status::unsupported_media_type, request_data, kGzipEncoding);
        co_return;
    }

    // Check HTTP method and content type [max body size is limited using beast::http::request_parser::body_limit in do_read]
    if (!is_method_allowed(req.method())) {
        co_await do_write("method not allowed\n", boost::beast::http::status::method_not_allowed, request_data);
        co_return;
    }
    if (req.method() != boost::beast::http::verb::options && req.method() != boost::beast::http::verb::get) {
        if (!is_accepted_content_type(req[boost::beast::http::field::content_type])) {
            co_await do_write("invalid content type\n, only application/json is supported\n", boost::beast::http::status::bad_request, request_data);
            co_return;
        }
    }

    SILK_TRACE << "Connection::handle_request body size: " << req.body().size() << " data: " << req.body();

    if (const auto auth_result = is_request_authorized(req); !auth_result) {
        co_await do_write(auth_result.error() + "\n", boost::beast::http::status::forbidden, request_data);
        co_return;
    }

    request_map_.emplace(request_id_, std::move(request_data));
    auto rsp_content = co_await handler_->handle(req.body(), request_id_);
    if (rsp_content) {
        // no streaming
        const auto& req_data = request_map_.at(request_id_);
        co_await do_write(rsp_content->append("\n"), boost::beast::http::status::ok, req_data, req_data.gzip_encoding_requested ? kGzipEncoding : "", req_data.gzip_encoding_requested);
        const auto it = request_map_.find(request_id_);
        if (it != request_map_.end()) {
            request_map_.erase(it);
        }
    }
    request_id_++;
}

//! Write chunked response headers
Task<void> Connection::create_chunk_header(RequestData& request_data) {
    try {
        boost::beast::http::response<boost::beast::http::empty_body> rsp{boost::beast::http::status::ok, request_data.request_http_version};
        rsp.set(boost::beast::http::field::content_type, "application/json");
        rsp.set(boost::beast::http::field::date, get_date_time());
        rsp.chunked(true);

        if (request_data.gzip_encoding_requested) {
            rsp.set(boost::beast::http::field::content_encoding, kGzipEncoding);
        }

        set_cors(rsp, request_data);

        boost::beast::http::response_serializer<boost::beast::http::empty_body> serializer{rsp};

        co_await async_write_header(socket_, serializer, boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        SILK_TRACE << "Connection::create_chunk_header system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        SILK_ERROR << "Connection::create_chunk_header exception: " << e.what();
        throw;
    }
    co_return;
}

Task<void> Connection::open_stream(uint64_t request_id) {
    const auto request_data_it = request_map_.find(request_id);
    if (request_data_it == request_map_.end()) {
        SILK_ERROR << "Connection::open_stream request_id not found: " << request_id;
        SILKWORM_ASSERT(false);
    }
    auto& request_data = request_data_it->second;

    // add chunking supports
    request_data.chunk_ = std::make_unique<Chunker>();
    if (request_data.gzip_encoding_requested_) {
        request_data.zlib_compressor_ = std::make_unique<ZlibCompressor>();
    }
    request_data.chunk = std::make_unique<Chunker>();

    co_return;
}

Task<void> Connection::close_stream(uint64_t request_id) {
    const auto request_data_it = request_map_.find(request_id);
    if (request_data_it == request_map_.end()) {
        SILK_ERROR << "Connection::close_stream request_id not found: " << request_id;
        SILKWORM_ASSERT(false);
    }
    auto& request_data = request_data_it->second;

    try {
        // Get remaining chunk and flush it
        auto [chunk, first_chunk] = request_data.chunk->get_remainder();
        if (first_chunk) {
            if (!chunk.empty()) {
                // If it is the first chunk, send without chunking
                co_await do_write(chunk, boost::beast::http::status::ok, request_data, request_data.gzip_encoding_requested ? kGzipEncoding : "", /* to_be_compressed */ false);  // data already compressed if nec
            }
        } else {
            // A previous chunk was already generated
            if (!chunk.empty()) {
                // Send the new one
                co_await send_chunk(chunk);
            }
            co_await boost::asio::async_write(socket_, boost::beast::http::make_chunk_last(), boost::asio::use_awaitable);
        }
    } catch (const boost::system::system_error& se) {
        request_map_.erase(request_data_it);
        SILK_TRACE << "Connection::close system_error: " << se.what();
        throw;
    } catch (const std::exception& e) {
        request_map_.erase(request_data_it);
        SILK_ERROR << "Connection::close exception: " << e.what();
        throw;
    }
    request_map_.erase(request_data_it);

    co_return;
}

//! Write chunked response content to the underlying socket
Task<size_t> Connection::write(uint64_t request_id, std::string_view content, bool last) {
    const auto request_data_it = request_map_.find(request_id);
    if (request_data_it == request_map_.end()) {
        SILK_ERROR << "Connection::write request_id not found: " << request_id;
        SILKWORM_ASSERT(false);
    }
    auto& request_data = request_data_it->second;

    std::string response(std::move(content));
    if (last) {
        response.append("\n");
    }

    if (request_data.gzip_encoding_requested) {
        std::string compressed_content;
        co_await compress(response, compressed_content);
        // queued compressed buffer
        request_data.chunk->queue_data(compressed_content);
    } else {
        // queued clear buffer
        request_data.chunk->queue_data(response);
    }

    // until completed chunk are present
    while (request_data.chunk->has_chunks()) {
        auto [complete_chunk, first_chunk] = request_data.chunk->get_complete_chunk();

        if (first_chunk) {
            co_await create_chunk_header(request_data);
        }
        co_await send_chunk(complete_chunk);
    }
    co_return 0;
}

Task<size_t> Connection::send_chunk(const std::string& content) {
    size_t bytes_transferred{0};
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

Task<void> Connection::do_write(const std::string& content, boost::beast::http::status http_status, const RequestData& request_data, std::string_view content_encoding, bool to_be_compressed) {
    try {
        SILK_TRACE << "Connection::do_write response: " << http_status << " content: " << content;
        boost::beast::http::response<boost::beast::http::string_body> res{http_status, request_data.request_http_version};

        if (http_status != boost::beast::http::status::ok) {
            res.set(boost::beast::http::field::content_type, "text/plain");
        } else {
            res.set(boost::beast::http::field::content_type, "application/json");
        }

        res.set(boost::beast::http::field::date, get_date_time());
        res.erase(boost::beast::http::field::host);
        res.keep_alive(request_data.request_keep_alive);
        if (http_status == boost::beast::http::status::ok && !content_encoding.empty()) {
            // Positive response w/ compression required
            res.set(boost::beast::http::field::content_encoding, content_encoding);
            if (to_be_compressed) {
                std::string compressed_content;
                co_await compress(content, compressed_content);

                res.content_length(compressed_content.size());
                res.body() = std::move(compressed_content);
            } else {
                res.content_length(content.size());
                res.body() = content;
            }

        } else {
            // Any negative response or positive response w/o compression
            if (!content_encoding.empty()) {
                res.set(boost::beast::http::field::accept_encoding, content_encoding);  // Indicate the supported encoding
            }
            res.content_length(content.size());
            res.body() = std::move(content);
        }

        set_cors<boost::beast::http::string_body>(res, request_data);

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
    if (!jwt_secret_ || jwt_secret_->empty()) {
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
void Connection::set_cors(boost::beast::http::response<Body>& res, const RequestData& request_data) {
    if (request_data.vary.empty()) {
        res.set(boost::beast::http::field::vary, "Origin");
    } else {
        auto vary{request_data.vary};
        res.set(boost::beast::http::field::vary, vary.append(" Origin"));
    }

    if (request_data.origin.empty()) {
        return;
    }

    if (!is_origin_allowed(allowed_origins_, request_data.origin)) {
        return;
    }

    if (!is_method_allowed(request_data.method)) {
        return;
    }

    if (allowed_origins_.at(0) == "*") {
        res.set(boost::beast::http::field::access_control_allow_origin, "*");
    } else {
        res.set(boost::beast::http::field::access_control_allow_origin, request_data.origin);
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
    static const absl::TimeZone kTz{absl::LocalTimeZone()};
    static std::pair<int64_t, std::string> cache;
    static std::shared_mutex cache_mutex;

    // read cache
    std::pair<int64_t, std::string> result;
    {
        std::shared_lock lock{cache_mutex};
        result = cache;
    }

    const int64_t ts = absl::ToUnixSeconds(absl::Now());

    // if timestamp matches - return the cached result
    if (ts == result.first) {
        return std::move(result.second);
    }

    // otherwise - format
    const absl::Time now = absl::FromUnixSeconds(ts);
    std::stringstream ss;
    ss << absl::FormatTime("%a, %d %b %E4Y %H:%M:%S ", now, kTz) << kTz.name();
    result = {ts, ss.str()};

    // update cache if timestamp increased
    {
        std::unique_lock lock{cache_mutex};
        if (ts > cache.first) {
            cache = result;
        }
    }

    return std::move(result.second);
}

Task<void> Connection::compress(const std::string& clear_data, std::string& compressed_data) {
    co_await async_task(workers_.executor(), [&]() -> void {
        Deflater deflater;
        deflater.compress(clear_data, compressed_data);
    });
}

Task<void> Connection::compress_stream(const std::string& clear_data, std::string& compressed_data, const RequestData& req_data, bool last) {
    co_await async_task(workers_.executor(), [&]() -> void {
        req_data.zlib_compressor_->compress_chunk(clear_data, compressed_data, last);
    });
}

}  // namespace silkworm::rpc::http
