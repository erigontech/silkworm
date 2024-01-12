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

#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc {

struct WriterTest : test::ContextTestBase {
};

class JsonChunkWriter : public StreamWriter {
  public:
    explicit JsonChunkWriter(StreamWriter& writer, std::size_t chunk_size = kDefaultChunkSize);

    Task<std::size_t> write(std::string_view content) override;
    Task<void> close() override;

  private:
    static const std::size_t kDefaultChunkSize = 0x800;

    StreamWriter& writer_;
    bool chunk_open_ = false;
    const std::size_t chunk_size_;
    size_t room_left_in_chunk_;
    std::size_t written_{0};
    std::stringstream str_chunk_size_;
};

JsonChunkWriter::JsonChunkWriter(StreamWriter& writer, std::size_t chunk_size)
    : writer_(writer), chunk_size_(chunk_size), room_left_in_chunk_(chunk_size_) {
    str_chunk_size_ << std::hex << chunk_size_ << kChunkSep;
}

Task<std::size_t> JsonChunkWriter::write(std::string_view content) {
    auto size = content.size();

    SILK_DEBUG << "JsonChunkWriter::write written_: " << written_ << " size: " << size;

    if (!chunk_open_) {
        co_await writer_.write(str_chunk_size_.str());
        chunk_open_ = true;
    }

    size_t remaining_in_view = size;
    size_t start = 0;
    while (start < size) {
        const auto length = std::min(room_left_in_chunk_, remaining_in_view);
        std::string_view sub_view(content.data() + start, length);
        co_await writer_.write(sub_view);

        written_ += length;
        start += length;
        remaining_in_view -= length;
        room_left_in_chunk_ -= length;

        if ((room_left_in_chunk_ % chunk_size_) == 0) {
            if (chunk_open_) {
                co_await writer_.write(kChunkSep);
                room_left_in_chunk_ = chunk_size_;
                chunk_open_ = false;
            }
            if (remaining_in_view > 0) {
                co_await writer_.write(str_chunk_size_.str());
                chunk_open_ = true;
            }
        }
    }
    co_return content.size();
}

Task<void> JsonChunkWriter::close() {
    if (chunk_open_) {
        if (room_left_in_chunk_ > 0) {
            std::unique_ptr<char[]> buffer{new char[room_left_in_chunk_]};
            std::memset(buffer.get(), ' ', room_left_in_chunk_);
            co_await writer_.write(std::string_view(buffer.get(), room_left_in_chunk_));
        }
        co_await writer_.write(kChunkSep);
        chunk_open_ = false;
        room_left_in_chunk_ = chunk_size_;
    }

    co_await writer_.write(kFinalChunk);

    co_return;
}

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

TEST_CASE_METHOD(WriterTest, "ChunkWriter") {
    SECTION("write&close under chunk size") {
        StringWriter s_writer;
        ChunkWriter writer(s_writer);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "4\r\n1234\r\n0\r\n\r\n");
    }
    SECTION("write over chunk size 4") {
        StringWriter s_writer;
        ChunkWriter writer(s_writer);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.write("5678"));

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n");
    }
    SECTION("write&close over chunk size 4") {
        StringWriter s_writer;
        ChunkWriter writer(s_writer);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.write("5678"));
        spawn_and_wait(writer.write("90"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n2\r\n90\r\n0\r\n\r\n");
    }
    SECTION("write over chunk size 5") {
        StringWriter s_writer;
        ChunkWriter writer(s_writer);

        spawn_and_wait(writer.write("12345"));
        spawn_and_wait(writer.write("67890"));

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n");
    }
    SECTION("write&close over chunk size 5") {
        StringWriter s_writer;
        ChunkWriter writer(s_writer);

        spawn_and_wait(writer.write("12345"));
        spawn_and_wait(writer.write("67890"));
        spawn_and_wait(writer.write("12"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n2\r\n12\r\n0\r\n\r\n");
    }
    SECTION("close") {
        StringWriter s_writer;
        ChunkWriter writer(s_writer);

        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "0\r\n\r\n");
    }
}

TEST_CASE_METHOD(WriterTest, "JsonChunkWriter") {
    SECTION("write&close under chunk size") {
        StringWriter s_writer;
        JsonChunkWriter writer(s_writer, 16);

        spawn_and_wait(writer.write("1234"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "10\r\n1234            \r\n0\r\n\r\n");
    }
    SECTION("write&close over chunk size 4") {
        StringWriter s_writer;
        JsonChunkWriter writer(s_writer, 4);

        spawn_and_wait(writer.write("1234567890"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "4\r\n1234\r\n4\r\n5678\r\n4\r\n90  \r\n0\r\n\r\n");
    }
    SECTION("write&close over chunk size 5") {
        StringWriter s_writer;
        JsonChunkWriter writer(s_writer, 5);

        spawn_and_wait(writer.write("1234567890"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n0\r\n\r\n");
    }
    SECTION("write&close over chunk size 5") {
        StringWriter s_writer;
        JsonChunkWriter writer(s_writer, 5);

        spawn_and_wait(writer.write("123456789012"));
        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "5\r\n12345\r\n5\r\n67890\r\n5\r\n12   \r\n0\r\n\r\n");
    }
    SECTION("close") {
        StringWriter s_writer;
        JsonChunkWriter writer(s_writer);

        spawn_and_wait(writer.close());

        CHECK(s_writer.get_content() == "0\r\n\r\n");
    }
    SECTION("write json") {
        StringWriter s_writer;
        JsonChunkWriter writer(s_writer, 48);

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
