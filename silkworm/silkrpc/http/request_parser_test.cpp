/*
   Copyright 2021 The Silkrpc Authors

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

#include "request_parser.hpp"

#include <array>
#include <string>
#include <vector>

#include <catch2/catch.hpp>

namespace silkrpc::http {

using Catch::Matchers::Message;

TEST_CASE("parse", "[silkrpc][http][request_parser]") {
    SECTION("invalid request with non-character") {
        std::array<char, 2> non_chars{static_cast<char>(-1), static_cast<char>(128)};
        for (auto c : non_chars) {
            silkrpc::http::RequestParser parser;
            silkrpc::http::Request req;
            std::array<char, 1> buffer{c};
            std::size_t bytes_read{1};
            const auto result{parser.parse(req, buffer.data(), buffer.data() + bytes_read)};
            CHECK(result == RequestParser::bad);
        }
    }

    SECTION("invalid request with control character") {
        std::array<char, 33> ctrl_chars{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127};
        for (auto c : ctrl_chars) {
            silkrpc::http::RequestParser parser;
            silkrpc::http::Request req;
            std::array<char, 1> buffer{c};
            std::size_t bytes_read{1};
            const auto result{parser.parse(req, buffer.data(), buffer.data() + bytes_read)};
            CHECK(result == RequestParser::bad);
        }
    }

    SECTION("empty request") {
        silkrpc::http::RequestParser parser;
        silkrpc::http::Request req;
        std::array<char, 0> buffer;
        std::size_t bytes_read{0};
        const auto result{parser.parse(req, buffer.data(), buffer.data() + bytes_read)};
        CHECK(result == RequestParser::indeterminate);
    }

    SECTION("continue requests") {
        std::vector<std::string> continue_requests{
            "POST / HTTP/1.1\r\nContent-Length: 15\r\nExpect: 100-continue\r\n\r\n{\"json\": \"2.0\"}",
            "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 15\r\n\r\n{\"json\": \"2.0\"}",
        };
        for (const auto& s : continue_requests) {
            silkrpc::http::RequestParser parser;
            silkrpc::http::Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::processing_continue);
        }
    }

    SECTION("bad requests") {
        std::vector<std::string> bad_requests{
            "(", ")", "<", ">", "@", ",", ";", ":", "\\", "\"", "/", "[", "]", "?", "=", "{", "}", " ", "\t", // special character strings
            "P@",
            "POST \t",
            "POST / *",
            "POST / H*",
            "POST / HT*",
            "POST / HTT*",
            "POST / HTTP*",
            "POST / HTTP/*",
            "POST / HTTP/1*",
            "POST / HTTP/1.*",
            "POST / HTTP/1.1*",
            "POST / HTTP/1.1\r*",
            "POST / HTTP/1.1\r\n\r\n",
            "POST / HTTP/1.1\r\nHost:*",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r*",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\t", // invalid char instead of \n
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0\r\n{", // missing \r\n
            "POST / HTTP/1.1\r\nExpect: 100-continue\r\n\r\n",
        };
        for (const auto& s : bad_requests) {
            silkrpc::http::RequestParser parser;
            silkrpc::http::Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::bad);
        }
    }

    SECTION("indeterminate requests") {
        std::vector<std::string> incomplete_requests{
            "POST / HTTP/1.1\r\nHost: localhost:8545",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json"
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0",
            "POST / HTTP/11.1\r\nHost: localhost:8545",
            "POST / HTTP/1.10\r\nHost: localhost:8545",
            "POST / HTTP/1.1\r\nHost: localhost:8545 \r\nUser-Agent: curl/7.68.0",
            "POST / HTTP/1.1\r\nHost: localhost:8545  \r\nUser-Agent: curl/7.68.0",
        };
        for (const auto& s : incomplete_requests) {
            silkrpc::http::RequestParser parser;
            silkrpc::http::Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::indeterminate);
        }
    }

    SECTION("good requests") {
        std::vector<std::string> good_requests{
            "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: localhost:8545 \r\nUser-Agent: curl/7.68.0 \r\nAccept: */* \r\nContent-Type: application/json \r\nContent-Length: 0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\n User-Agent: curl/7.68.0\r\n Accept: */*\r\n Content-Type: application/json\r\nContent-Length: 0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\n User-Agent: curl/7.68.0\r\n Accept: */*\r\n Content-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"json\": \"2.0\"}",
        };
        for (const auto& s : good_requests) {
            silkrpc::http::RequestParser parser;
            silkrpc::http::Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::good);
        }
    }
}

TEST_CASE("reset", "[silkrpc][http][request_parser]") {
    silkrpc::http::RequestParser parser;

    SECTION("empty parser") {
        CHECK_NOTHROW(parser.reset());
    }

    SECTION("idempotent") {
        CHECK_NOTHROW(parser.reset());
        CHECK_NOTHROW(parser.reset());
    }
}

} // namespace silkrpc::http

