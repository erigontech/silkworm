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

#include "reply.hpp"

#include <iostream>

#include <catch2/catch.hpp>

namespace silkworm::rpc::http {

TEST_CASE("header", "[rpc][http][reply]") {
    Header header{"Accept", "*/*"};

    CHECK(header.name == "Accept");
    CHECK(header.value == "*/*");
}

TEST_CASE("headers to_buffers", "[rpc][http][reply]") {
    std::vector<Header> headers{{"Accept", "*/*"}};

    auto buffers = to_buffers(headers);
    CHECK(buffers.size() == 4);

    std::string result;
    for (const auto& buffer : buffers) {
        std::string buf(static_cast<const char*>(buffer.data()), buffer.size());
        result += buf;
    }
    CHECK(result == "Accept: */*\r\n");
}

TEST_CASE("status & headers to_buffers", "[rpc][http][reply]") {
    std::vector<Header> headers{{"Accept", "*/*"}};

    auto buffers = to_buffers(StatusType::ok, headers);
    CHECK(buffers.size() == 6);

    std::string result;
    for (const auto& buffer : buffers) {
        std::string buf(static_cast<const char*>(buffer.data()), buffer.size());
        result += buf;
    }
    CHECK(result == "HTTP/1.1 200 OK\r\nAccept: */*\r\n\r\n");
}

TEST_CASE("StatusType to_buffer", "[rpc][http][reply]") {
    SECTION("ok") {
        auto buffer = to_buffer(StatusType::ok);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 200 OK\r\n");
    }
    SECTION("created") {
        auto buffer = to_buffer(StatusType::created);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 201 Created\r\n");
    }
    SECTION("accepted") {
        auto buffer = to_buffer(StatusType::accepted);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 202 Accepted\r\n");
    }
    SECTION("no_content") {
        auto buffer = to_buffer(StatusType::no_content);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 204 No Content\r\n");
    }
    SECTION("multiple_choices") {
        auto buffer = to_buffer(StatusType::multiple_choices);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 300 Multiple Choices\r\n");
    }
    SECTION("moved_permanently") {
        auto buffer = to_buffer(StatusType::moved_permanently);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 301 Moved Permanently\r\n");
    }
    SECTION("moved_temporarily") {
        auto buffer = to_buffer(StatusType::moved_temporarily);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 302 Moved Temporarily\r\n");
    }
    SECTION("not_modified") {
        auto buffer = to_buffer(StatusType::not_modified);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 304 Not Modified\r\n");
    }
    SECTION("bad_request") {
        auto buffer = to_buffer(StatusType::bad_request);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 400 Bad Request\r\n");
    }
    SECTION("unauthorized") {
        auto buffer = to_buffer(StatusType::unauthorized);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 401 Unauthorized\r\n");
    }
    SECTION("forbidden") {
        auto buffer = to_buffer(StatusType::forbidden);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 403 Forbidden\r\n");
    }
    SECTION("not_found") {
        auto buffer = to_buffer(StatusType::not_found);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 404 Not Found\r\n");
    }
    SECTION("internal_server_error") {
        auto buffer = to_buffer(StatusType::internal_server_error);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 500 Internal Server Error\r\n");
    }
    SECTION("not_implemented") {
        auto buffer = to_buffer(StatusType::not_implemented);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 501 Not Implemented\r\n");
    }
    SECTION("bad_gateway") {
        auto buffer = to_buffer(StatusType::bad_gateway);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 502 Bad Gateway\r\n");
    }
    SECTION("service_unavailable") {
        auto buffer = to_buffer(StatusType::service_unavailable);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 503 Service Unavailable\r\n");
    }
    SECTION("processing_continue") {
        auto buffer = to_buffer(StatusType::processing_continue);
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 100 Continue\r\n");
    }
    SECTION("unexpected values") {
        auto buffer = to_buffer(static_cast<StatusType>(100));
        std::string result(static_cast<const char*>(buffer.data()), buffer.size());
        CHECK(result == "HTTP/1.1 100 Continue\r\n");
    }
}

TEST_CASE("Reply", "[rpc][http][reply]") {
    Reply reply{
        StatusType::ok,
        std::vector<Header>{{"Accept", "*/*"}},
        R"({"json": "2.0"})"};

    SECTION("check reset method") {
        CHECK(reply.status == StatusType::ok);
        CHECK(reply.headers == std::vector<Header>{{"Accept", "*/*"}});
        CHECK(reply.content == "{\"json\": \"2.0\"}");
        reply.reset();
        CHECK(reply.headers.empty());
        CHECK(reply.content.empty());
    }
    SECTION("check to_buffers") {
        auto buffers = reply.to_buffers();

        std::string result;
        for (const auto buffer : buffers) {
            result += std::string(static_cast<const char*>(buffer.data()), buffer.size());
        }

        CHECK(buffers.size() == 7);
        CHECK(result == "HTTP/1.1 200 OK\r\nAccept: */*\r\n\r\n{\"json\": \"2.0\"}");
    }
}

TEST_CASE("Reply stock_reply", "[rpc][http][reply]") {
    SECTION("ok") {
        auto result = Reply::stock_reply(StatusType::ok);
        CHECK(result.status == StatusType::ok);
        CHECK(result.content.empty());
    }
    SECTION("created") {
        auto result = Reply::stock_reply(StatusType::created);
        CHECK(result.status == StatusType::created);
        CHECK(result.content == "<html><head><title>Created</title></head><body><h1>201 Created</h1></body></html>");
    }
    SECTION("accepted") {
        auto result = Reply::stock_reply(StatusType::accepted);
        CHECK(result.status == StatusType::accepted);
        CHECK(result.content == "<html><head><title>Accepted</title></head><body><h1>202 Accepted</h1></body></html>");
    }
    SECTION("no_content") {
        auto result = Reply::stock_reply(StatusType::no_content);
        CHECK(result.status == StatusType::no_content);
        CHECK(result.content == "<html><head><title>No Content</title></head><body><h1>204 Content</h1></body></html>");
    }
    SECTION("multiple_choices") {
        auto result = Reply::stock_reply(StatusType::multiple_choices);
        CHECK(result.status == StatusType::multiple_choices);
        CHECK(result.content == "<html><head><title>Multiple Choices</title></head><body><h1>300 Multiple Choices</h1></body></html>");
    }
    SECTION("moved_permanently") {
        auto result = Reply::stock_reply(StatusType::moved_permanently);
        CHECK(result.status == StatusType::moved_permanently);
        CHECK(result.content == "<html><head><title>Moved Permanently</title></head><body><h1>301 Moved Permanently</h1></body></html>");
    }
    SECTION("moved_temporarily") {
        auto result = Reply::stock_reply(StatusType::moved_temporarily);
        CHECK(result.status == StatusType::moved_temporarily);
        CHECK(result.content == "<html><head><title>Moved Temporarily</title></head><body><h1>302 Moved Temporarily</h1></body></html>");
    }
    SECTION("not_modified") {
        auto result = Reply::stock_reply(StatusType::not_modified);
        CHECK(result.status == StatusType::not_modified);
        CHECK(result.content == "<html><head><title>Not Modified</title></head><body><h1>304 Not Modified</h1></body></html>");
    }
    SECTION("bad_request") {
        auto result = Reply::stock_reply(StatusType::bad_request);
        CHECK(result.status == StatusType::bad_request);
        CHECK(result.content == "<html><head><title>Bad Request</title></head><body><h1>400 Bad Request</h1></body></html>");
    }
    SECTION("unauthorized") {
        auto result = Reply::stock_reply(StatusType::unauthorized);
        CHECK(result.status == StatusType::unauthorized);
        CHECK(result.content == "<html><head><title>Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>");
    }
    SECTION("forbidden") {
        auto result = Reply::stock_reply(StatusType::forbidden);
        CHECK(result.status == StatusType::forbidden);
        CHECK(result.content == "<html><head><title>Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>");
    }
    SECTION("not_found") {
        auto result = Reply::stock_reply(StatusType::not_found);
        CHECK(result.status == StatusType::not_found);
        CHECK(result.content == "<html><head><title>Not Found</title></head><body><h1>404 Not Found</h1></body></html>");
    }
    SECTION("internal_server_error") {
        auto result = Reply::stock_reply(StatusType::internal_server_error);
        CHECK(result.status == StatusType::internal_server_error);
        CHECK(result.content == "<html><head><title>Internal Server Error</title></head><body><h1>500 Internal Server Error</h1></body></html>");
    }
    SECTION("not_implemented") {
        auto result = Reply::stock_reply(StatusType::not_implemented);
        CHECK(result.status == StatusType::not_implemented);
        CHECK(result.content == "<html><head><title>Not Implemented</title></head><body><h1>501 Not Implemented</h1></body></html>");
    }
    SECTION("bad_gateway") {
        auto result = Reply::stock_reply(StatusType::bad_gateway);
        CHECK(result.status == StatusType::bad_gateway);
        CHECK(result.content == "<html><head><title>Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>");
    }
    SECTION("service_unavailable") {
        auto result = Reply::stock_reply(StatusType::service_unavailable);
        CHECK(result.status == StatusType::service_unavailable);
        CHECK(result.content == "<html><head><title>Service Unavailable</title></head><body><h1>503 Service Unavailable</h1></body></html>");
    }
    SECTION("processing_continue") {
        auto result = Reply::stock_reply(StatusType::processing_continue);
        CHECK(result.status == StatusType::processing_continue);
        CHECK(result.content.empty());
    }
}

}  // namespace silkworm::rpc::http
