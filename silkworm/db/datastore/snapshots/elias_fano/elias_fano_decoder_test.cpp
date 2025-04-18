// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "elias_fano_decoder.hpp"

#include <sstream>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>

namespace silkworm::snapshots::elias_fano {

TEST_CASE("EliasFanoDecoder") {
    EliasFanoList32Builder expected_list{3, 3};
    expected_list.add_offset(1);
    expected_list.add_offset(2);
    expected_list.add_offset(3);
    expected_list.build();
    std::stringstream expected_list_stream;
    expected_list_stream << expected_list;
    const auto expected_list_str = expected_list_stream.str();

    EliasFanoDecoder decoder;
    auto expected_list_bytes = BytesOrByteView{string_to_bytes(expected_list_str)};
    decoder.decode_word(expected_list_bytes);
    CHECK(decoder.value == expected_list.as_view());
}

}  // namespace silkworm::snapshots::elias_fano
