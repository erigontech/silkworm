// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stream.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>

namespace silkworm::rpc::json {

// The following constants *must* be initialized using assignment and *not* uniform initialization syntax
static const nlohmann::json kJsonNull = nlohmann::json::value_t::null;
static const nlohmann::json kJsonEmptyObject = nlohmann::json::value_t::object;
static const nlohmann::json kJsonEmptyArray = nlohmann::json::value_t::array;

struct StreamTest : test_util::ServiceContextTestBase {
};

TEST_CASE_METHOD(StreamTest, "json::Stream writing JSON", "[rpc][json]") {
    boost::asio::any_io_executor io_executor = ioc_.get_executor();

    StringWriter string_writer;

    SECTION("write_json in string") {
        Stream stream(io_executor, string_writer, /* request_id */ 0);

        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        CHECK((string_writer.get_content() == "{\"test\":\"test\"}"));
    }
    SECTION("write_json in 1 chunk") {
        Stream stream(io_executor, string_writer, /* request_id */ 0);

        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"test\":\"test\"}"));
    }
    SECTION("write_json in 2 chunks") {
        Stream stream(io_executor, string_writer, /* request_id */ 0);

        nlohmann::json json = R"({
            "check": "check",
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"check\":\"check\",\"test\":\"test\"}"));
    }
}

TEST_CASE_METHOD(StreamTest, "json::Stream API", "[rpc][json]") {
    boost::asio::any_io_executor io_executor = ioc_.get_executor();

    StringWriter string_writer;
    Stream stream(io_executor, string_writer, /* request_id */ 0);

    SECTION("write_json json") {
        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.write_json(json);
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"test\":\"test\"}"));
    }
    SECTION("empty object 1") {
        stream.open_object();
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{}"));
    }
    SECTION("empty object 2") {
        stream.write_json(kJsonEmptyObject);
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{}"));
    }
    SECTION("empty array 1") {
        stream.open_array();
        stream.close_array();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "[]"));
    }
    SECTION("empty array 2") {
        stream.write_json(kJsonEmptyArray);
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "[]"));
    }
    SECTION("simple object 1") {
        stream.open_object();
        stream.write_json_field("null", kJsonNull);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"null\":null}"));
    }
    SECTION("simple object 2") {
        stream.open_object();
        stream.write_json_field("array", kJsonEmptyArray);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"array\":[]}"));
    }
    SECTION("simple object 3") {
        stream.open_object();
        stream.write_field("name", "value");
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"name\":\"value\"}"));
    }
    SECTION("simple object 4") {
        stream.open_object();
        stream.write_field("name1", "value1");
        stream.write_field("name2", "value2");
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":\"value2\"}"));
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

        CHECK((string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":{\"test\":\"test\"}}"));
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

        CHECK((string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":[\"one\",\"two\"]}"));
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

        CHECK((string_writer.get_content() == "{\"name1\":\"value1\",\"name2\":[{\"test\":\"test\"}]}"));
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

        CHECK((string_writer.get_content() == "{\"name1\":{\"test\":\"test\"},\"name2\":[\"one\",\"two\"]}"));
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

        CHECK((string_writer.get_content() == "{\"name1\":{\"boolean\":true,\"numeric\":1},\"name2\":[\"1.2\",\"3.4\"]}"));
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

        CHECK((string_writer.get_content() == "{\"name1\":\"name1\",\"name2\":[{\"boolean\":true,\"numeric\":1},{\"boolean\":true,\"numeric\":1}],\"name3\":\"name3\"}"));
    }
    SECTION("complex object 7") {
        stream.open_object();
        stream.write_field("numeric", 10);
        stream.write_field("double", 10.3);
        stream.write_field("boolean", true);
        stream.close_object();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "{\"numeric\":10,\"double\":10.3,\"boolean\":true}"));
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

        CHECK((string_writer.get_content() ==
               "{\"result\":[{\"item\":1,\"logs\":[{\"item\":1.1}]},{\"item\":2,\"logs\":[{\"item\":2.1}]}]}"));
    }
    SECTION("simple array 1") {
        nlohmann::json json = R"({
            "test": "test"
        })"_json;

        stream.open_array();
        stream.write_json(json);
        stream.close_array();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "[{\"test\":\"test\"}]"));
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

        CHECK((string_writer.get_content() == "[{\"test\":\"test\"},{\"test\":\"test\"}]"));
    }
    SECTION("simple array 3") {
        stream.open_array();
        stream.write_json(10);
        stream.write_json(10.3);
        stream.write_json(true);
        stream.close_array();
        spawn_and_wait(stream.close());

        CHECK((string_writer.get_content() == "[10,10.3,true]"));
    }
}

TEST_CASE_METHOD(StreamTest, "json::Stream threading", "[rpc][json]") {
    boost::asio::any_io_executor io_executor = ioc_.get_executor();
    constexpr std::string_view kData{R"({"test":"test"})"};

    StringWriter string_writer;
    Stream stream(io_executor, string_writer, /* request_id */ 0, 1);  // tiny buffer capacity

    const nlohmann::json json = R"({"test":"test"})"_json;

    SECTION("using I/O context thread") {
        stream.write_json(json);
        CHECK_NOTHROW(spawn_and_wait(stream.close()));
        CHECK((string_writer.get_content() == kData));
    }

    SECTION("using worker thread") {
        WorkerPool workers;
        boost::asio::post(workers, [&]() {
            for (int i{0}; i < 1'000; ++i) {
                stream.write_json(json);
            }
        });
        workers.join();
        CHECK_NOTHROW(spawn_and_wait(stream.close()));
        CHECK(string_writer.get_content().size() == kData.size() * 1'000);
    }
}

}  // namespace silkworm::rpc::json
