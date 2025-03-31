// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hash_decoder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

TEST_CASE("HashSnapshotsDecoder") {
    using evmc::literals::operator""_bytes32;
    HashSnapshotsDecoder decoder;
    auto word = BytesOrByteView{*from_hex("0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55")};
    decoder.decode_word(word);
    CHECK(decoder.value == 0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55_bytes32);

    BytesOrByteView empty;
    CHECK_THROWS_AS(decoder.decode_word(empty), std::runtime_error);
}

}  // namespace silkworm::db::state
