// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "address_codecs.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

TEST_CASE("AddressSnapshotsDecoder") {
    using evmc::literals::operator""_address;
    AddressSnapshotsDecoder decoder;
    auto word = BytesOrByteView{*from_hex("0x000000000000000000636f6e736f6c652e6c6f67")};
    decoder.decode_word(word);
    CHECK(decoder.value == 0x000000000000000000636f6e736f6c652e6c6f67_address);

    BytesOrByteView empty;
    CHECK_THROWS_AS(decoder.decode_word(empty), std::runtime_error);
}

TEST_CASE("AddressSnapshotsEncoder") {
    using evmc::literals::operator""_address;
    AddressSnapshotsEncoder encoder;
    encoder.value = 0x000000000000000000636f6e736f6c652e6c6f67_address;
    CHECK(encoder.encode_word() == *from_hex("0x000000000000000000636f6e736f6c652e6c6f67"));
}

}  // namespace silkworm::db::state
