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
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/test/log.hpp>

using Catch::Matchers::Message;

namespace silkworm {

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
    endian::store_big_u64(output.data(), value);
    output.resize(output.size() + sizeof(int_t));
    return output.size();
}

//! Varint encoder
template <typename int_t = uint64_t>
std::size_t encode_varint(int_t value, silkworm::Bytes& output) {
    std::size_t output_size = output.size();
    while (value > 127) {
        output[output_size] = static_cast<uint8_t>(value & 127) | 128;
        value >>= 7;
        output_size++;
    }
    output[output_size++] = static_cast<uint8_t>(value) & 127;
    output.resize(output_size);
    return output_size;
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
};

void encode_header(const SnapshotHeader& header, silkworm::Bytes& output) {
    encode_big_endian<uint64_t>(header.words_count, output);
    encode_big_endian<uint64_t>(header.empty_words_count, output);
    encode_big_endian<uint64_t>(header.patterns.size(), output);
    for (const auto& pattern : header.patterns) {
        encode_varint<uint64_t>(pattern.depth, output);
        encode_varint<uint64_t>(pattern.data.size(), output);
        output.append(pattern.data.cbegin(), pattern.data.cend());
    }
    encode_big_endian<uint64_t>(header.positions.size(), output);
    for (const auto& position : header.positions) {
        encode_varint<uint64_t>(position.depth, output);
        encode_varint<uint64_t>(position.value, output);
    }
}

//! Temporary snapshot file
class TemporarySnapshot {
  public:
    explicit TemporarySnapshot(const SnapshotHeader& header) {
        silkworm::Bytes output{};
        encode_header(header, output);
        file_.write(output);
    }

    const std::filesystem::path& path() const { return file_.path(); }

  private:
    TemporaryFile file_;
};

TEST_CASE("Decompressor", "[silkworm][snapshot][decompressor]") {
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
}

TEST_CASE("Decompressor::open valid files", "[silkworm][snapshot][decompressor]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    std::map<std::string, SnapshotHeader> header_tests{
        {"zero patterns and zero positions",
         SnapshotHeader{}},
        {"one pattern and zero positions",
         SnapshotHeader{
             .words_count = 0,
             .empty_words_count = 0,
             .patterns = std::vector<SnapshotPattern>{{0, {}}},
             .positions = std::vector<SnapshotPosition>{}}},
        {"zero patterns and one position",
         SnapshotHeader{
             .words_count = 0,
             .empty_words_count = 0,
             .patterns = std::vector<SnapshotPattern>{},
             .positions = std::vector<SnapshotPosition>{{0, 22}}}},
        {"one pattern and one position",
         SnapshotHeader{
             .words_count = 0,
             .empty_words_count = 0,
             .patterns = std::vector<SnapshotPattern>{{0, {}}},
             .positions = std::vector<SnapshotPosition>{{0, 22}}}},
        {"two patterns and one position",
         SnapshotHeader{
             .words_count = 0,
             .empty_words_count = 0,
             .patterns = std::vector<SnapshotPattern>{{1, {}}, {2, {}}},
             .positions = std::vector<SnapshotPosition>{{0, 22}}}}};

    for (const auto& [test_name, header] : header_tests) {
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

    SECTION("close after close") {
        CHECK_NOTHROW(decoder.read_ahead([](const auto& it) -> bool {
            CHECK(it.has_next());
            return true;
        }) == true);
        decoder.close();
    }

    SECTION("failure after close") {
        decoder.close();
        CHECK_THROWS_AS(decoder.read_ahead([](const auto&) -> bool { return false; }), std::logic_error);
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

    SECTION("close after close") {
        CHECK_NOTHROW(decoder.close());
    }

    SECTION("close after close") {
        CHECK_NOTHROW(decoder.close());
        CHECK_NOTHROW(decoder.close());
    }
}

}  // namespace silkworm
