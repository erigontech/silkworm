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

#include <boost/asio/thread_pool.hpp>
#include <catch2/catch_test_macros.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc::http {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
// SUMMARY: ThreadSanitizer: data race /usr/include/c++/11/bits/stl_algobase.h:431
// - write of size 1 thread T8 'grpc_global_tim' created by main thread
// - previous write of size 1 by main thread
#ifndef SILKWORM_SANITIZE

class Connection_ForTest : public Connection {
  public:
    using Connection::Connection;
    using Connection::is_request_authorized;
};

TEST_CASE("connection creation", "[rpc][http][connection]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    SECTION("field initialization") {
        boost::asio::io_context ioc;
        boost::asio::ip::tcp::socket socket{ioc};
        socket.open(boost::asio::ip::tcp::v4());
        RequestHandlerFactory handler_factory = [](auto*) -> RequestHandlerPtr { return nullptr; };
        std::vector<std::string> allowed_origins;
        std::optional<std::string> jwt_secret;
        WorkerPool workers;
        CHECK_NOTHROW(Connection_ForTest{std::move(socket),
                                         handler_factory,
                                         allowed_origins,
                                         std::move(jwt_secret),
                                         false,
                                         false,
                                         false,
                                         workers});
    }
}

static constexpr auto kSampleJWTKey{
    "NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXO"
    "PsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c="sv};
static constexpr auto kSampleJWTBearer{
    "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUs"
    "ImlhdCI6MTcxMzUxNDQ3MCwiZXhwIjoxNzEzNTE4MDcwfQ.IBKIdE8Bcto9cwGSkr6mqylBLvfcPZZyDOyZMWYtEaQ"sv};

static std::string create_and_sign_jwt_token(auto&& jwt_secret, bool include_issued_at = true) {
    auto token_builder{jwt::create()};
    if (include_issued_at) {
        token_builder.set_issued_at(jwt::date::clock::now());
    }
    return token_builder.sign(jwt::algorithm::hs256{std::forward<decltype(jwt_secret)>(jwt_secret)});
}

static RequestWithStringBody create_request_with_authorization(std::string_view auth_value) {
    RequestWithStringBody req;
    req.insert(boost::beast::http::field::authorization, auth_value);
    return req;
}

static RequestWithStringBody create_request_with_bearer_token(const std::string& jwt_token) {
    return create_request_with_authorization("Bearer " + jwt_token);
}

TEST_CASE("is_request_authorized", "[rpc][http][connection]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    boost::asio::io_context ioc;
    RequestHandlerFactory handler_factory = [](auto*) -> RequestHandlerPtr { return nullptr; };
    std::vector<std::string> allowed_origins;
    WorkerPool workers;
    auto make_connection = [&](auto&& j) -> Connection_ForTest {
        boost::asio::ip::tcp::socket socket{ioc};
        socket.open(boost::asio::ip::tcp::v4());
        return {std::move(socket), handler_factory, allowed_origins, std::forward<decltype(j)>(j), false, false, false, workers};
    };
    std::optional<std::string> jwt_secret{kSampleJWTKey};
    // Pass the expected JWT secret to the HTTP connection
    Connection_ForTest connection{make_connection(*jwt_secret)};

    SECTION("no HTTP Authorization header") {
        const auto auth_result{connection.is_request_authorized(RequestWithStringBody{})};
        CHECK(!auth_result);
        CHECK(auth_result.error() == "missing token");
    }

    SECTION("empty HTTP Authorization header") {
        RequestWithStringBody req;
        req.insert(boost::beast::http::field::authorization, "");
        const auto auth_result{connection.is_request_authorized(req)};
        CHECK(!auth_result);
        CHECK(auth_result.error() == "missing token");
    }

    SECTION("invalid Bearer token") {
        RequestWithStringBody req{create_request_with_authorization("Bear")};
        const auto auth_result{connection.is_request_authorized(req)};
        CHECK(!auth_result);
        CHECK(auth_result.error() == "missing token");
    }

    SECTION("invalid JWT token") {
        RequestWithStringBody req = create_request_with_bearer_token("INVALID_TOKEN");
        const auto auth_result{connection.is_request_authorized(req)};
        CHECK(!auth_result);
        CHECK(auth_result.error() == "invalid token");
    }

    SECTION("invalid JWT issued-at claim") {
        // Create the HTTP request using a valid-but-too-old Bearer token
        RequestWithStringBody req = create_request_with_authorization(kSampleJWTBearer);

        const auto auth_result{connection.is_request_authorized(req)};
        CHECK(!auth_result);
        CHECK(auth_result.error() == "invalid issued-at claim");
    }

    SECTION("invalid JWT signature") {
        // Create *now* a new JWT token and sign it using `another_jwt_secret`
        std::optional<std::string> another_jwt_secret{"00112233"};
        const auto jwt_token{create_and_sign_jwt_token(*another_jwt_secret)};
        // Create the HTTP request using the JWT token
        RequestWithStringBody req = create_request_with_bearer_token(jwt_token);

        const auto auth_result{connection.is_request_authorized(req)};
        CHECK(!auth_result);
        CHECK(auth_result.error() == "invalid signature");
    }

    SECTION("missing JWT issued-at claim") {
        // Create *now* a new JWT token w/o issued-at claim and sign it using the same `jwt_secret`
        const auto jwt_token{create_and_sign_jwt_token(*jwt_secret, /*include_issued_at=*/false)};
        // Create the HTTP request using the JWT token
        RequestWithStringBody req = create_request_with_bearer_token(jwt_token);

        const auto auth_result{connection.is_request_authorized(req)};
        CHECK(!auth_result);
        CHECK(auth_result.error() == "missing issued-at claim");
    }

    SECTION("valid JWT token") {
        // Create *now* a new JWT token and sign it using the same `jwt_secret`
        const auto jwt_token{create_and_sign_jwt_token(*jwt_secret)};
        // Create the HTTP request using the JWT token
        RequestWithStringBody req = create_request_with_bearer_token(jwt_token);

        CHECK(connection.is_request_authorized(req));
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::http
