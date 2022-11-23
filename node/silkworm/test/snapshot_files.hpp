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

#pragma once

#include <filesystem>
#include <fstream>

#include <silkworm/common/endian.hpp>
#include <silkworm/test/files.hpp>

namespace silkworm::test {

//! Big-endian int encoder
template <typename int_t = uint64_t>
std::size_t encode_big_endian(int_t value, Bytes& output) {
    const std::size_t old_size = output.size();
    output.resize(old_size + sizeof(int_t));
    endian::store_big_u64(output.data() + old_size, value);
    return output.size();
}

//! Varint encoder
template <typename int_t = uint64_t>
std::size_t encode_varint(int_t value, Bytes& output) {
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

    void encode(silkworm::Bytes& output) const {
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

struct SnapshotBody {
    Bytes data;
    SnapshotHeader* header{nullptr};

    void encode(Bytes& output) const {
        output.append(data.cbegin(), data.cend());
    }
};

//! Temporary snapshot file
class TemporarySnapshotFile {
  public:
    explicit TemporarySnapshotFile(const SnapshotHeader& header, const SnapshotBody& body = {}) {
        silkworm::Bytes data{};
        header.encode(data);
        body.encode(data);
        file_.write(data);
    }
    TemporarySnapshotFile(const std::string& filename, const SnapshotHeader& header, const SnapshotBody& body = {})
        : file_(filename) {
        silkworm::Bytes data{};
        header.encode(data);
        body.encode(data);
        file_.write(data);
    }
    explicit TemporarySnapshotFile(const std::string& filename) : TemporarySnapshotFile(filename, {}, {}) {}

    const std::filesystem::path& path() const { return file_.path(); }

  private:
    test::TemporaryFile file_;
};

//! HelloWorld snapshot file: it contains just one word: "hello, world" w/o any patterns
class HelloWorldSnapshotFile : public TemporarySnapshotFile {
  public:
    explicit HelloWorldSnapshotFile()
        : TemporarySnapshotFile{
              test::SnapshotHeader{
                  .words_count = 1,  // number of non-empty words
                  .empty_words_count = 0,
                  .patterns = std::vector<test::SnapshotPattern>{},
                  .positions = std::vector<test::SnapshotPosition>{
                      {1, 0},  // 1: position 0: zero encoded data (no pattern)
                      {1, 13}  // 1: position 13: unencoded data length (including position encoding)
                  }},
              test::SnapshotBody{
                  *from_hex("0168656C6C6F2C20776F726C64")  // 0x01: position 0x68656C6C6F2C20776F726C64: "hello, world"
              }} {}
};
}  // namespace silkworm::test
