// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bit_stream.hpp"

#include <functional>
#include <limits>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::seg {

struct ByteWriter {
    Bytes storage;
    std::function<void(uint8_t)> func;

    ByteWriter() {
        func = [this](uint8_t b) { this->write(b); };
    }
    void write(uint8_t b) {
        storage.push_back(b);
    }
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    operator std::function<void(uint8_t)>() const {
        return func;
    }
};

TEST_CASE("BitStream.zero_bits") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(1, 0);
    }
    CHECK(writer.storage.empty());
}

TEST_CASE("BitStream.one_bit") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(1, 1);
    }
    CHECK(writer.storage == Bytes{1});
}

TEST_CASE("BitStream.few_bits") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(0b101, 3);
    }
    CHECK(writer.storage == Bytes{0b101});
}

TEST_CASE("BitStream.one_byte") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(0xFF, 8);
    }
    CHECK(writer.storage == Bytes{0xFF});
}

TEST_CASE("BitStream.some_nibbles") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(0b0011, 4);
        stream.write(0b1100, 4);
        stream.write(0b1001, 4);
    }
    CHECK(writer.storage == Bytes{0b11000011, 0b00001001});
}

TEST_CASE("BitStream.some_bits") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(0b000, 3);
        stream.write(0b1111111, 7);
        stream.write(0b00, 2);
        stream.write(0b1111, 4);
    }
    CHECK(writer.storage == Bytes{0b11111000, 0b11110011});
}

TEST_CASE("BitStream.int64") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(std::numeric_limits<uint64_t>::max(), 64);
    }
    CHECK(writer.storage == Bytes(8, 0xFF));
}

TEST_CASE("BitStream.int63") {
    ByteWriter writer;
    {
        BitStream stream{writer};
        stream.write(std::numeric_limits<uint64_t>::max(), 63);
    }
    CHECK(writer.storage == Bytes(7, 0xFF) + Bytes{0b1111111});
}

}  // namespace silkworm::snapshots::seg
