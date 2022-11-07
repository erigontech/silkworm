/*
   Copyright 2022 The Silkworm Authors

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

#include "decompressor.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/test/log.hpp>

using Catch::Matchers::Message;

namespace silkworm {

//! DecodingTable exposed for white-box testing
class DecodingTable_ForTest : public DecodingTable {
  public:
    explicit DecodingTable_ForTest(std::size_t max_depth) : DecodingTable(max_depth) {}
    [[nodiscard]] std::size_t max_depth() const { return max_depth_; }
};

TEST_CASE("DecodingTable::DecodingTable", "[silkworm][snapshot][decompressor]") {
    std::map<std::string, std::pair<std::size_t, std::size_t>> test_params{
        {"max depth is 0", {0, 0}},
        {"max depth is < kMaxTableBitLength", {DecodingTable::kMaxTableBitLength - 1, DecodingTable::kMaxTableBitLength - 1}},
        {"max depth is = kMaxTableBitLength", {DecodingTable::kMaxTableBitLength, DecodingTable::kMaxTableBitLength}},
        {"max depth is > kMaxTableBitLength", {DecodingTable::kMaxTableBitLength + 1, DecodingTable::kMaxTableBitLength}},
    };
    for (const auto& [test_name, test_pair] : test_params) {
        std::size_t max_depth = test_pair.first;
        std::size_t expected_bit_length = test_pair.second;
        DecodingTable_ForTest table{max_depth};
        CHECK(table.max_depth() == max_depth);
        CHECK(table.bit_length() == expected_bit_length);
    }
}

TEST_CASE("PatternTable::PatternTable", "[silkworm][snapshot][decompressor]") {
    PatternTable table{0};
    CHECK_NOTHROW(table.num_codewords() == 0);
}

TEST_CASE("PatternTable::operator<<", "[silkworm][snapshot][decompressor]") {
    PatternTable table{0};
    CHECK_NOTHROW(test::null_stream() << table);
}

TEST_CASE("PositionTable::PositionTable", "[silkworm][snapshot][decompressor]") {
    PositionTable table{0};
    CHECK_NOTHROW(table.num_positions() == 0);
}

TEST_CASE("PositionTable::operator<<", "[silkworm][snapshot][decompressor]") {
    PositionTable table{0};
    CHECK_NOTHROW(test::null_stream() << table);
}

//! Temporary file flushed after any data insertion
class TemporaryFile {
  public:
    explicit TemporaryFile() : path_{silkworm::TemporaryDirectory::get_unique_temporary_path()}, stream_{path_} {}
    ~TemporaryFile() { stream_.close(); }

    const std::filesystem::path& path() const noexcept { return path_; }

    void write(ByteView bv) {
        stream_.write(reinterpret_cast<const char*>(bv.data()), static_cast<std::streamsize>(bv.size()));
        stream_.flush();
    }

  private:
    std::filesystem::path path_;
    std::ofstream stream_;
};

//! Big-endian int encoder
template <typename int_t = uint64_t>
std::size_t encode_big_endian(int_t value, silkworm::Bytes& output) {
    const std::size_t old_size = output.size();
    output.resize(old_size + sizeof(int_t));
    endian::store_big_u64(output.data() + old_size, value);
    return output.size();
}

//! Varint encoder
template <typename int_t = uint64_t>
std::size_t encode_varint(int_t value, silkworm::Bytes& output) {
    std::size_t varint_size{0};
    while (value > 127) {
        output.push_back(static_cast<uint8_t>(value & 127) | 128);
        value >>= 7;
        ++varint_size;
    }
    output.push_back(static_cast<uint8_t>(value) & 127);
    return ++varint_size;
}

//! Snapshot header encoder
struct SnapshotPattern {
    uint64_t depth;
    silkworm::Bytes data;
};

struct SnapshotPosition {
    uint64_t depth;
    uint64_t value;
};

struct SnapshotHeader {
    uint64_t words_count;
    uint64_t empty_words_count;
    std::vector<SnapshotPattern> patterns;
    std::vector<SnapshotPosition> positions;

    void encode(silkworm::Bytes& output) {
        encode_big_endian<uint64_t>(words_count, output);
        encode_big_endian<uint64_t>(empty_words_count, output);
        encode_big_endian<uint64_t>(compute_patterns_size(), output);
        for (const auto& pattern : patterns) {
            encode_varint<uint64_t>(pattern.depth, output);
            encode_varint<uint64_t>(pattern.data.size(), output);
            output.append(pattern.data.cbegin(), pattern.data.cend());
        }
        encode_big_endian<uint64_t>(compute_positions_size(), output);
        for (const auto& position : positions) {
            encode_varint<uint64_t>(position.depth, output);
            encode_varint<uint64_t>(position.value, output);
        }
    }

  private:
    [[nodiscard]] uint64_t compute_patterns_size() const {
        uint64_t patterns_size{0};
        Bytes temp_buffer{};
        for (const auto& pattern : patterns) {
            patterns_size += encode_varint<uint64_t>(pattern.depth, temp_buffer);
            patterns_size += encode_varint<uint64_t>(pattern.data.size(), temp_buffer);
            patterns_size += pattern.data.size();
        }
        return patterns_size;
    }

    [[nodiscard]] uint64_t compute_positions_size() const {
        uint64_t positions_size{0};
        Bytes temp_buffer{};
        for (const auto& position : positions) {
            positions_size += encode_varint<uint64_t>(position.depth, temp_buffer);
            positions_size += encode_varint<uint64_t>(position.value, temp_buffer);
        }
        return positions_size;
    }
};

//! Temporary snapshot file
class TemporarySnapshot {
  public:
    explicit TemporarySnapshot(SnapshotHeader& header) {
        silkworm::Bytes output{};
        header.encode(output);
        file_.write(output);
    }

    const std::filesystem::path& path() const { return file_.path(); }

  private:
    TemporaryFile file_;
};

TEST_CASE("Decompressor::Decompressor", "[silkworm][snapshot][decompressor]") {
    const auto tmp_file_path{silkworm::TemporaryDirectory::get_unique_temporary_path()};
    Decompressor decoder{tmp_file_path};
    CHECK(decoder.compressed_path() == tmp_file_path);
    CHECK(decoder.pattern_table() == nullptr);
    CHECK(decoder.position_table() == nullptr);
}

TEST_CASE("Decompressor::open invalid files", "[silkworm][snapshot][decompressor]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("empty file") {
        TemporaryFile tmp_file;
        Decompressor decoder{tmp_file.path()};
        CHECK_THROWS_AS(decoder.open(), std::runtime_error);
    }
    SECTION("compressed file is too short: 1") {
        TemporaryFile tmp_file;
        tmp_file.write(*silkworm::from_hex("0"));
        Decompressor decoder{tmp_file.path()};
        CHECK_THROWS_MATCHES(decoder.open(), std::runtime_error, Message("compressed file is too short: 1"));
    }
    SECTION("compressed file is too short: 31") {
        TemporaryFile tmp_file;
        tmp_file.write(*silkworm::from_hex("0x00000000000000000000000000000000000000000000000000000000000000"));
        Decompressor decoder{tmp_file.path()};
        CHECK_THROWS_MATCHES(decoder.open(), std::runtime_error, Message("compressed file is too short: 31"));
    }
    SECTION("pattern dict is invalid: length read failed at 1") {
        TemporaryFile tmp_file;
        tmp_file.write(*silkworm::from_hex("0x0000000000000000000000000000000000000000000000010000000000000000"));
        Decompressor decoder{tmp_file.path()};
        CHECK_THROWS_MATCHES(decoder.open(), std::runtime_error, Message("pattern dict is invalid: length read failed at 1"));
    }
    SECTION("zero patterns and zero positions") {
        SnapshotHeader header{};
        TemporarySnapshot tmp_snapshot{header};
        Decompressor decoder{tmp_snapshot.path()};
        CHECK_THROWS_MATCHES(decoder.open(), std::runtime_error, Message("invalid empty pattern dict"));
    }
    SECTION("one pattern and zero positions") {
        SnapshotHeader header{
            .words_count = 0,
            .empty_words_count = 0,
            .patterns = std::vector<SnapshotPattern>{{12, {0x11, 0x22}}},
            .positions = std::vector<SnapshotPosition>{}};
        TemporarySnapshot tmp_snapshot{header};
        Decompressor decoder{tmp_snapshot.path()};
        CHECK_THROWS_MATCHES(decoder.open(), std::runtime_error, Message("invalid empty position dict"));
    }
    SECTION("zero patterns and one position") {
        SnapshotHeader header{
            .words_count = 0,
            .empty_words_count = 0,
            .patterns = std::vector<SnapshotPattern>{},
            .positions = std::vector<SnapshotPosition>{{0, 22}}};
        TemporarySnapshot tmp_snapshot{header};
        Decompressor decoder{tmp_snapshot.path()};
        CHECK_THROWS_MATCHES(decoder.open(), std::runtime_error, Message("invalid empty pattern dict"));
    }
}

TEST_CASE("Decompressor::open valid files", "[silkworm][snapshot][decompressor]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    std::map<std::string, SnapshotHeader> header_tests{
        {"one pattern and one position",
         SnapshotHeader{
             .words_count = 0,
             .empty_words_count = 0,
             .patterns = std::vector<SnapshotPattern>{{12, {}}},
             .positions = std::vector<SnapshotPosition>{{13, 22}}}},
        {"two patterns and one position",
         SnapshotHeader{
             .words_count = 0,
             .empty_words_count = 0,
             .patterns = std::vector<SnapshotPattern>{{1, {}}, {2, {}}},
             .positions = std::vector<SnapshotPosition>{{0, 22}}}}};

    for (auto& [test_name, header] : header_tests) {
        SECTION(test_name) {
            TemporarySnapshot tmp_snapshot{header};
            Decompressor decoder{tmp_snapshot.path()};
            CHECK_NOTHROW(decoder.open());
        }
    }
}

TEST_CASE("Decompressor::read_ahead", "[silkworm][snapshot][decompressor]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    SnapshotHeader header{
        .words_count = 0,
        .empty_words_count = 0,
        .patterns = std::vector<SnapshotPattern>{{0, {}}},
        .positions = std::vector<SnapshotPosition>{{0, 1}}};
    TemporarySnapshot tmp_snapshot{header};
    Decompressor decoder{tmp_snapshot.path()};
    CHECK_NOTHROW(decoder.open());

    for (const bool b : std::vector<bool>{true, false}) {
        SECTION("check returned value: " + std::to_string(b)) {
            CHECK_NOTHROW(decoder.read_ahead([=](auto) -> bool { return b; }) == b);
        }
    }

    SECTION("failure after close") {
        decoder.close();
        CHECK_THROWS_AS(decoder.read_ahead([](auto) -> bool { return false; }), std::logic_error);
    }
}

TEST_CASE("Decompressor::close", "[silkworm][snapshot][decompressor]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    SnapshotHeader header{
        .words_count = 0,
        .empty_words_count = 0,
        .patterns = std::vector<SnapshotPattern>{{0, {}}},
        .positions = std::vector<SnapshotPosition>{{0, 1}}};
    TemporarySnapshot tmp_snapshot{header};
    Decompressor decoder{tmp_snapshot.path()};
    CHECK_NOTHROW(decoder.open());

    SECTION("close after open") {
        CHECK_NOTHROW(decoder.close());
    }

    SECTION("close after close") {
        CHECK_NOTHROW(decoder.close());
        CHECK_NOTHROW(decoder.close());
    }
}

TEST_CASE("ReadIterator::ReadIterator empty data", "[silkworm][snapshot][decompressor]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    SnapshotHeader header{
        .words_count = 0,
        .empty_words_count = 0,
        .patterns = std::vector<SnapshotPattern>{{0, {}}},
        .positions = std::vector<SnapshotPosition>{{0, 1}}};
    TemporarySnapshot tmp_snapshot{header};
    Decompressor decoder{tmp_snapshot.path()};
    CHECK_NOTHROW(decoder.open());

    SECTION("has next") {
        const auto read_function = [](const auto it) -> bool {
            CHECK_FALSE(it.has_next());
            return true;
        };
        CHECK_NOTHROW(decoder.read_ahead(read_function));
    }
    SECTION("next") {
        const auto read_function = [](auto it) -> bool {
            silkworm::Bytes buffer{};
            CHECK(it.next(buffer) == 0);
            CHECK(buffer.empty());
            return true;
        };
        CHECK_NOTHROW(decoder.read_ahead(read_function));
    }
}

}  // namespace silkworm
