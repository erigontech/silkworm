/*
   Copyright 2022 The Silkrpc Authors

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

#include <silkworm/silkrpc/common/log.hpp>

namespace silkrpc {

TEST_CASE("StringWriter", "[silkrpc]") {
    SILKRPC_LOG_STREAMS(null_stream(), null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    SECTION("write") {
        StringWriter writer;
        std::string test = "test";

        writer.write(test);

        CHECK(writer.get_content() == test);
    }
    SECTION("close") {
        StringWriter writer(5);
        std::string test = "test";

        writer.write(test);
        writer.close();

        CHECK(writer.get_content() == test);
    }
}

TEST_CASE("ChunksWriter", "[silkrpc]") {
    SILKRPC_LOG_STREAMS(std::cout, null_stream());
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    SECTION("write&close under chunck size") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        writer.write("1234");
        writer.close();

        CHECK(s_writer.get_content() == "4\r\n1234\r\n0\r\n\r\n");
    }
    SECTION("write over chunck size 4") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer, 4);

        writer.write("1234567890");

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n");
    }
    SECTION("write&close over chunck size 4") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer, 4);

        writer.write("1234567890");
        writer.close();

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n2\r\n90\r\n0\r\n\r\n");
    }
    SECTION("write over chunck size 5") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer, 5);

        writer.write("1234567890");

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n");
    }
    SECTION("write&close over chunck size 5") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer, 5);

        writer.write("123456789012");
        writer.close();

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n2\r\n12\r\n0\r\n\r\n");
    }
    SECTION("close") {
        StringWriter s_writer;
        ChunksWriter writer(s_writer);

        writer.close();

        CHECK(s_writer.get_content() == "0\r\n\r\n");
    }
}
} // namespace silkrpc
