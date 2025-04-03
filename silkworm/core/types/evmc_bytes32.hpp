// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm {

// Converts bytes to evmc::bytes32; input is cropped if necessary.
// Short inputs are left-padded with 0s.
evmc::bytes32 to_bytes32(ByteView bytes);

std::string to_hex(const evmc::bytes32& value, bool with_prefix = false);

}  // namespace silkworm

namespace silkworm::rlp {

void encode(Bytes& to, const evmc::bytes32& value);
size_t length(const evmc::bytes32& value) noexcept;

DecodingResult decode(ByteView& from, evmc::bytes32& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace silkworm::rlp

namespace evmc {
using silkworm::rlp::encode;
using silkworm::rlp::length;
}  // namespace evmc
