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

#include "stream.hpp"

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc::json {

struct JsonStreamTest : test::ContextTestBase {
};

TEST_CASE_METHOD(JsonStreamTest, "JsonStream[json]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool pool{1};
    pool.start();
    boost::asio::any_io_executor io_executor = pool.next_io_context().get_executor();

    StringWriter string_writer;
    ChunksWriter chunks_writer(string_writer);

    SECTION("write_json in string") {
        Stream stream(io_executor, string_writer);

        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"test\":\"test\"}");
    }
    SECTION("write_json in 1 chunk") {
        Stream stream(io_executor, chunks_writer);

        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "f\r\n{\"test\":\"test\"}\r\n0\r\n\r\n");
    }
    SECTION("write_json in 2 chunks") {
        Stream stream(io_executor, chunks_writer);

        nlohmann::json json = R"({
            "check": "check",
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "1f\r\n{\"check\":\"check\",\"test\":\"test\"}\r\n0\r\n\r\n");
    }
}

TEST_CASE_METHOD(JsonStreamTest, "JsonStream calls") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    ClientContextPool pool{1};
    pool.start();
    boost::asio::any_io_executor io_executor = pool.next_io_context().get_executor();

    StringWriter string_writer;
    Stream stream(io_executor, string_writer);

    SECTION("write_json json") {
        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"test\":\"test\"}");
    }
    SECTION("empty object 1") {
        stream.open_object();
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{}");
    }
    SECTION("empty object 2") {
        stream.write_json(EMPTY_OBJECT);
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{}");
    }
    SECTION("empty array 1") {
        stream.open_array();
        stream.close_array();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "[]");
    }
    SECTION("empty array 2") {
        stream.write_json(EMPTY_ARRAY);
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "[]");
    }
    SECTION("simple object 1") {
        stream.open_object();
        stream.write_json_field("null", JSON_NULL);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"null\":null}");
    }
    SECTION("simple object 2") {
        stream.open_object();
        stream.write_json_field("array", EMPTY_ARRAY);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"array\":[]}");
    }
    SECTION("simple object 3") {
        stream.open_object();
        stream.write_field("name", "value");
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name\":\"value\"}");
    }
    SECTION("simple object 4") {
        stream.open_object();
        stream.write_field("name1", "value1");
        stream.write_field("name2", "value2");
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":\"value2\"}");
    }
    SECTION("complex object 1") {
        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.open_object();
        stream.write_field("name1", "value1");
        stream.write_json_field("name2", json);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":{\"test\":\"test\"}}");
    }
    SECTION("complex object 2") {
        nlohmann::json json = R"([
            "one", "two"
        ])"_json;

        stream.open_object();
        stream.write_field("name1", "value1");
        stream.write_json_field("name2", json);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":[\"one\",\"two\"]}");
    }
    SECTION("complex object 3") {
        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.open_object();
        stream.write_field("name1", "value1");
        stream.write_field("name2");
        stream.open_array();
        stream.write_json(json);
        stream.close_array();
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":[{\"test\":\"test\"}]}");
    }
    SECTION("complex object 4") {
        nlohmann::json json_obj = R"({
            "test": "test"
        })"_json;
        nlohmann::json json_array = R"([
            "one", "two"
        ])"_json;

        stream.open_object();
        stream.write_json_field("name1", json_obj);
        stream.write_json_field("name2", json_array);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name1\":{\"test\":\"test\"},\"name2\":[\"one\",\"two\"]}");
    }
    SECTION("complex object 5") {
        nlohmann::json json_obj = R"({
            "numeric": 1,
            "boolean": true
        })"_json;
        nlohmann::json json_array = R"([
            "1.2", "3.4"
        ])"_json;

        stream.open_object();
        stream.write_json_field("name1", json_obj);
        stream.write_json_field("name2", json_array);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name1\":{\"boolean\":true,\"numeric\":1},\"name2\":[\"1.2\",\"3.4\"]}");
    }
    SECTION("complex object 6") {
        nlohmann::json json_obj = R"({
            "numeric": 1,
            "boolean": true
        })"_json;

        stream.open_object();
        stream.write_field("name1", "name1");
        stream.write_field("name2");
        stream.open_array();
        stream.write_json(json_obj);
        stream.write_json(json_obj);
        stream.close_array();
        stream.write_field("name3", "name3");
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"name1\":\"name1\",\"name2\":[{\"boolean\":true,\"numeric\":1},{\"boolean\":true,\"numeric\":1}],\"name3\":\"name3\"}");
    }
    SECTION("complex object 7") {
        stream.open_object();
        stream.write_field("numeric", 10);
        stream.write_field("double", 10.3);
        stream.write_field("boolean", true);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "{\"numeric\":10,\"double\":10.3,\"boolean\":true}");
    }
    SECTION("complex object 8") {
        stream.open_object();
        stream.write_field("result");

        stream.open_array();

        stream.open_object();
        stream.write_field("item", 1);
        stream.write_field("logs");
        stream.open_array();
        stream.open_object();
        stream.write_field("item", 1.1);
        stream.close_object();
        stream.close_array();
        stream.close_object();

        stream.open_object();
        stream.write_field("item", 2);
        stream.write_field("logs");
        stream.open_array();
        stream.open_object();
        stream.write_field("item", 2.1);
        stream.close_object();
        stream.close_array();
        stream.close_object();

        stream.close_array();
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() ==
              "{\"result\":[{\"item\":1,\"logs\":[{\"item\":1.1}]},{\"item\":2,\"logs\":[{\"item\":2.1}]}]}");
    }
    SECTION("simple array 1") {
        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.open_array();
        stream.write_json(json);
        stream.close_array();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "[{\"test\":\"test\"}]");
    }
    SECTION("simple array 2") {
        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.open_array();
        stream.write_json(json);
        stream.write_json(json);
        stream.close_array();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "[{\"test\":\"test\"},{\"test\":\"test\"}]");
    }
    SECTION("simple array 3") {
        stream.open_array();
        stream.write_json(10);
        stream.write_json(10.3);
        stream.write_json(true);
        stream.close_array();
        spawn_and_wait(stream.close());

        CHECK(string_writer.get_content() == "[10,10.3,true]");
    }
}
}  // namespace silkworm::rpc::json
