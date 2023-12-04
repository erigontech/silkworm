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

#include "request_parser.hpp"

#include <array>
#include <iostream>
#include <string>
#include <vector>

#include <catch2/catch.hpp>

namespace silkworm::rpc::http {

using Catch::Matchers::Message;

TEST_CASE("parse", "[rpc][http][request_parser]") {
    SECTION("invalid request with non-character") {
        std::array<char, 2> non_chars{static_cast<char>(-1), static_cast<char>(128)};
        for (auto c : non_chars) {
            RequestParser parser;
            Request req;
            std::array<char, 1> buffer{c};
            std::size_t bytes_read{1};
            const auto result{parser.parse(req, buffer.data(), buffer.data() + bytes_read)};
            CHECK(result == RequestParser::ResultType::bad);
        }
    }

    SECTION("invalid request with control character") {
        std::array<char, 33> ctrl_chars{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127};
        for (auto c : ctrl_chars) {
            RequestParser parser;
            Request req;
            std::array<char, 1> buffer{c};
            std::size_t bytes_read{1};
            const auto result{parser.parse(req, buffer.data(), buffer.data() + bytes_read)};
            CHECK(result == RequestParser::ResultType::bad);
        }
    }

    SECTION("empty request") {
        RequestParser parser;
        Request req;
        // Non-empty buffer is required to avoid runtime error: applying zero offset to null pointer
        // UndefinedBehaviorSanitizer: undefined-behavior in picohttpparser.c:404:55
        std::array<char, 1> buffer{};
        std::size_t bytes_read{0};
        const auto result{parser.parse(req, buffer.data(), buffer.data() + bytes_read)};
        CHECK(result == RequestParser::ResultType::indeterminate);
    }

    SECTION("continue requests") {
        std::vector<std::string> continue_requests{
            "POST / HTTP/1.1\r\nContent-Length: 15\r\nExpect: 100-continue\r\n\r\n{\"json\": \"2.0\"}",
            "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 15\r\n\r\n{\"json\": \"2.0\"}",
        };
        for (const auto& s : continue_requests) {
            RequestParser parser;
            Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::ResultType::processing_continue);
        }
    }

    SECTION("bad requests") {
        std::vector<std::string> bad_requests{
            "(",
            ")",
            "<",
            ">",
            "@",
            ",",
            ";",
            ":",
            "\\",
            "\"",
            "/",
            "[",
            "]",
            "?",
            "=",
            "{",
            "}",
            "\t",  // special character strings
            "P@",
            "POST \t",
            "POST / HTTP/1.10\r\nHost: localhost:8545",
            "POST / HTTP/11.1\r\nHost: localhost:8545",
            "POST / HTTP/1.1*",
            "POST / HTTP/1.1\r*",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r*",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\t",  // invalid char instead of \n
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0\r\n{",     // missing \r\n
        };
        for (const auto& s : bad_requests) {
            RequestParser parser;
            Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::ResultType::bad);
        }
    }

    SECTION("bad requests with segments") {
        std::string seg1{"POST / HT**/1.1\r\nHost: localhost:8545\r\n User-Agent: curl/7.68.0\r\n Accept: */*\r\n"};
        RequestParser parser;
        Request req;
        const auto result1{parser.parse(req, seg1.data(), seg1.data() + seg1.size())};
        CHECK(result1 == RequestParser::ResultType::bad);
    }

    SECTION("indeterminate requests") {
        std::vector<std::string> incomplete_requests{
            "POST / HTTP/1.1\r\nHost: localhost:8545",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json",
            "POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0",
            "POST / HTTP/1.1\r\nHost: localhost:8545 \r\nUser-Agent: curl/7.68.0",
            "POST / HTTP/1.1\r\nHost: localhost:8545  \r\nUser-Agent: curl/7.68.0",
        };
        for (const auto& s : incomplete_requests) {
            RequestParser parser;
            Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::ResultType::indeterminate);
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
            "POST / HTTP/1.1\r\nExpect: 100-continue\r\n\r\n",
            "POST / HTTP/1.1\r\n\r\n",
        };
        for (const auto& s : good_requests) {
            RequestParser parser;
            Request req;
            const auto result{parser.parse(req, s.data(), s.data() + s.size())};
            CHECK(result == RequestParser::ResultType::good);
        }
    }

    SECTION("segemented http request 2 segs") {
        std::string seg1{"POST / HTTP/1.9\r\nHost: localhost:8545\r\n User-Agent: curl/7.68.0\r\n Accept: */*\r\n"};
        std::string seg2{"Content-Type: application/json\r\nContent-Length: 0\r\n\r\n}"};
        RequestParser parser;
        Request req;
        const auto result1{parser.parse(req, seg1.data(), seg1.data() + seg1.size())};
        CHECK(result1 == RequestParser::ResultType::indeterminate);
        const auto result2{parser.parse(req, seg2.data(), seg2.data() + seg2.length())};
        CHECK(result2 == RequestParser::ResultType::good);
        CHECK(req.http_version_major == 1);
        CHECK(req.http_version_minor == 9);
        CHECK(req.headers.size() == 0);
        CHECK(req.content_length == 0);
        CHECK(req.content.length() == 0);
    }

    SECTION("segemented http request 3 segs") {
        std::string seg1{"POST / HTTP/1.1\r\nHost: localhost:8545\r\n User-Agent: curl/7.68.0\r\n Accept: */*\r\n"};
        std::string seg2{"Content-Type: application/json\r\nContent-Length: 15\r\n\r\n"};
        std::string seg3{"{\"json\": \"2.0\"}"};
        RequestParser parser;
        Request req;
        const auto result1{parser.parse(req, seg1.data(), seg1.data() + seg1.size())};
        CHECK(result1 == RequestParser::ResultType::indeterminate);
        const auto result2{parser.parse(req, seg2.data(), seg2.data() + seg2.length())};
        CHECK(result2 == RequestParser::ResultType::indeterminate);
        const auto result3{parser.parse(req, seg3.data(), seg3.data() + seg3.length())};
        CHECK(result3 == RequestParser::ResultType::good);
        CHECK(req.http_version_major == 1);
        CHECK(req.http_version_minor == 1);
        CHECK(req.headers.size() == 0);
        CHECK(req.content_length == 15);
        CHECK(req.content.length() == 15);
    }

    SECTION("segemented http request 4 segs") {
        std::string seg1{"POST / HTTP/1.1\r\nHost: localhost:8545\r\n User-Agent: curl/7.68.0\r\n Accept: */*\r\n"};
        std::string seg2{"Content-Type: application/json\r\nContent-Length: 15\r\n\r\n"};
        std::string seg3{"{\"json\""};
        std::string seg4{": \"2.0\"}"};
        RequestParser parser;
        Request req;
        const auto result1{parser.parse(req, seg1.data(), seg1.data() + seg1.size())};
        CHECK(result1 == RequestParser::ResultType::indeterminate);
        const auto result2{parser.parse(req, seg2.data(), seg2.data() + seg2.length())};
        CHECK(result2 == RequestParser::ResultType::indeterminate);
        const auto result3{parser.parse(req, seg3.data(), seg3.data() + seg3.length())};
        CHECK(result3 == RequestParser::ResultType::indeterminate);
        const auto result4{parser.parse(req, seg4.data(), seg4.data() + seg4.length())};
        CHECK(result4 == RequestParser::ResultType::good);
        CHECK(req.http_version_major == 1);
        CHECK(req.http_version_minor == 1);
        CHECK(req.headers.size() == 0);
        CHECK(req.content_length == 15);
        CHECK(req.content.length() == 15);
    }
}

TEST_CASE("reset", "[rpc][http][request_parser]") {
    RequestParser parser;

    SECTION("empty parser") {
        CHECK_NOTHROW(parser.reset());
    }

    SECTION("idempotent") {
        CHECK_NOTHROW(parser.reset());
        CHECK_NOTHROW(parser.reset());
    }
}

}  // namespace silkworm::rpc::http
