// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sequence.hpp"

#include <sstream>
#include <stdexcept>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots::encoding {

TEST_CASE("Uint64Sequence", "[silkworm][snapshots][recsplit][sequence]") {
    Uint64Sequence output_sequence{0, 11, 21, 31, 41, 51, 61};

    std::stringstream ss;
    ss << output_sequence;

    Uint64Sequence input_sequence;
    ss >> input_sequence;

    CHECK(input_sequence == output_sequence);
}

TEST_CASE("Uint64Sequence: size too big", "[silkworm][snapshots][recsplit][sequence]") {
    std::stringstream ss;
    Bytes invalid_size_buffer(sizeof(uint64_t), '\0');
    endian::store_big_u64(invalid_size_buffer.data(), 49287623586282974);
    ss.write(byte_ptr_cast(invalid_size_buffer.data()), static_cast<std::streamsize>(invalid_size_buffer.size()));

    Uint64Sequence input_sequence;
    CHECK_THROWS_AS((ss >> input_sequence), std::logic_error);
}

}  // namespace silkworm::snapshots::encoding
