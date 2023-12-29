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

#include "writer.hpp"

#include <iostream>

#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc {

struct WriterTest : test::ContextTestBase {
};

TEST_CASE_METHOD(WriterTest, "StringWriter") {
    SECTION("write") {
        StringWriter writer;
        std::string test = "test";

        spawn_and_wait(writer.write(test));

        CHECK(writer.get_content() == test);
    }
    SECTION("close") {
        StringWriter writer(5);
        std::string test = "test";

        spawn_and_wait(writer.write(test));
        spawn_and_wait(writer.close());

        CHECK(writer.get_content() == test);
    }
}

TEST_CASE_METHOD(WriterTest, "ChunksWriter") {
    SECTION("write&close under chunk size") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "4\r\n1234\r\n0\r\n\r\n");
    }
    SECTION("write over chunk size 4") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.write("5678"));

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n");
    }
    SECTION("write&close over chunk size 4") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.write("5678"));
        spawn_and_wait(writer.write("90"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n2\r\n90\r\n0\r\n\r\n");
    }
    SECTION("write over chunk size 5") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        spawn_and_wait(writer.write("12345"));
        spawn_and_wait(writer.write("67890"));

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n");
    }
    SECTION("write&close over chunk size 5") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        spawn_and_wait(writer.write("12345"));
        spawn_and_wait(writer.write("67890"));
        spawn_and_wait(writer.write("12"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n2\r\n12\r\n0\r\n\r\n");
    }
    SECTION("close") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "0\r\n\r\n");
    }
}

TEST_CASE_METHOD(WriterTest, "JsonChunksWriter") {
    SECTION("write&close under chunk size") {
        StringWriter s_writer;
        JsonChunksWriter writer(s_writer, 16);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "10\r\n1234            \r\n0\r\n\r\n");
    }
    SECTION("write&close over chunk size 4") {
        StringWriter s_writer;
        JsonChunksWriter writer(s_writer, 4);

        spawn_and_wait(writer.write("1234567890"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n4\r\n90  \r\n0\r\n\r\n");
    }
    SECTION("write&close over chunk size 5") {
        StringWriter s_writer;
        JsonChunksWriter writer(s_writer, 5);

        spawn_and_wait(writer.write("1234567890"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n0\r\n\r\n");
    }
    SECTION("write&close over chunk size 5") {
        StringWriter s_writer;
        JsonChunksWriter writer(s_writer, 5);

        spawn_and_wait(writer.write("123456789012"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n5\r\n12   \r\n0\r\n\r\n");
    }
    SECTION("close") {
        StringWriter s_writer;
        JsonChunksWriter writer(s_writer);

        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "0\r\n\r\n");
    }
    SECTION("write json") {
        StringWriter s_writer;
        JsonChunksWriter writer(s_writer, 48);

        nlohmann::json json = R"({
            "accounts": {},
            "next": "next",
            "root": "root"
        })"_json;

        const auto content = json.dump(/*indent=*/-1, /*indent_char=*/' ', /*ensure_ascii=*/false, nlohmann::json::error_handler_t::replace);

        spawn_and_wait(writer.write(content));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "30\r\n{\"accounts\":{},\"next\":\"next\",\"root\":\"root\"}     \r\n0\r\n\r\n");
    }
}

}  // namespace silkworm::rpc
